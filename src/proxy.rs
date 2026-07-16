use std::{convert::Infallible, net::SocketAddr, time::Instant};

use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, OriginalUri, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header},
    response::Response,
};
use futures_util::StreamExt;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::{
    AppError, AppState,
    audit::AuditEvent,
    auth::{ApiIdentity, api_identity},
    balancer::{Lease, track_response},
    crypto::encrypt,
    oauth,
};

const HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
    "cookie",
    "proxy-connection",
    "set-cookie",
];

const PROXY_ONLY_HEADERS: &[&str] = &[
    "x-lb-affinity-key",
    "x-session-id",
    "session_id",
    "session-id",
    "x-codex-session-id",
    "x-codex-conversation-id",
    "thread-id",
];

struct CallContext {
    request_id: String,
    model: Option<String>,
}

struct AuditTracker {
    permit: Option<mpsc::OwnedPermit<AuditEvent>>,
    event: Option<AuditEvent>,
    started: Instant,
}

impl AuditTracker {
    async fn begin(
        state: &AppState,
        identity: &ApiIdentity,
        request_id: &str,
        method: &Method,
        path: &str,
        client_ip: &str,
    ) -> Result<Self, AppError> {
        let permit = state
            .audit
            .reserve()
            .await
            .ok_or_else(|| AppError::unavailable("audit writer is unavailable"))?;
        Ok(Self {
            permit: Some(permit),
            event: Some(AuditEvent {
                id: Uuid::new_v4().to_string(),
                request_id: request_id.to_owned(),
                api_key_id: identity.key_id.clone(),
                user_id: identity.user_id.clone(),
                channel_id: None,
                method: method.as_str().to_owned(),
                path: path.to_owned(),
                model: None,
                status: 0,
                latency_ms: 0,
                input_tokens: 0,
                output_tokens: 0,
                cached_tokens: 0,
                error: None,
                client_ip: client_ip.to_owned(),
                created_at: chrono::Utc::now().timestamp(),
            }),
            started: Instant::now(),
        })
    }

    fn set_channel(&mut self, channel_id: &str) {
        if let Some(event) = &mut self.event {
            event.channel_id = Some(channel_id.to_owned());
        }
    }

    fn finish(
        &mut self,
        status: StatusCode,
        model: Option<&str>,
        usage: Usage,
        error: Option<&str>,
    ) {
        let Some(mut event) = self.event.take() else {
            return;
        };
        settle(
            &mut event,
            status.as_u16() as i64,
            model,
            usage,
            error,
            self.started,
        );
        self.permit
            .take()
            .expect("audit queue capacity is reserved once")
            .send(event);
    }

    fn take_stream(&mut self, status: StatusCode, model: Option<&str>) -> StreamCompletion {
        let mut event = self.event.take().expect("audit event is available once");
        event.status = status.as_u16() as i64;
        event.model = model.map(str::to_owned);
        StreamCompletion::new(
            self.permit
                .take()
                .expect("audit queue capacity is reserved once"),
            event,
            self.started,
        )
    }
}

impl Drop for AuditTracker {
    fn drop(&mut self) {
        if let Some(mut event) = self.event.take() {
            settle(
                &mut event,
                499,
                None,
                Usage::default(),
                Some("client_cancelled"),
                self.started,
            );
            self.permit
                .take()
                .expect("audit queue capacity is reserved once")
                .send(event);
        }
    }
}

fn settle(
    event: &mut AuditEvent,
    status: i64,
    model: Option<&str>,
    usage: Usage,
    error: Option<&str>,
    started: Instant,
) {
    event.status = status;
    event.model = model.map(str::to_owned);
    event.latency_ms = started.elapsed().as_millis().max(1) as i64;
    event.input_tokens = usage.input_tokens;
    event.output_tokens = usage.output_tokens;
    event.cached_tokens = usage.cached_tokens;
    event.error = error.map(str::to_owned);
}

pub async fn handle_json(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let request_id = request_id(&headers);
    let identity = api_identity(&state, &headers).await?;
    let client_ip = peer.ip().to_string();
    let mut audit = AuditTracker::begin(
        &state,
        &identity,
        &request_id,
        &method,
        uri.path(),
        &client_ip,
    )
    .await?;
    let result = dispatch(
        state,
        identity,
        request_id,
        uri.path(),
        &headers,
        &body,
        &mut audit,
    )
    .await;
    if let Err(error) = &result
        && audit.event.is_some()
    {
        audit.finish(
            error.status(),
            None,
            Usage::default(),
            Some(error.message()),
        );
    }
    result
}

pub async fn handle_audio(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, AppError> {
    let request_id = request_id(&headers);
    let identity = api_identity(&state, &headers).await?;
    let mut audit = AuditTracker::begin(
        &state,
        &identity,
        &request_id,
        &method,
        uri.path(),
        &peer.ip().to_string(),
    )
    .await?;
    let result = dispatch_audio(
        state,
        identity,
        request_id,
        uri.path(),
        &headers,
        body,
        &mut audit,
    )
    .await;
    if let Err(error) = &result
        && audit.event.is_some()
    {
        audit.finish(
            error.status(),
            None,
            Usage::default(),
            Some(error.message()),
        );
    }
    result
}

pub async fn handle_models(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let request_id = request_id(&headers);
    let identity = api_identity(&state, &headers).await?;
    let mut audit = AuditTracker::begin(
        &state,
        &identity,
        &request_id,
        &method,
        uri.path(),
        &peer.ip().to_string(),
    )
    .await?;
    models_response(&state, &mut audit).await
}

fn request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

async fn dispatch(
    state: AppState,
    identity: ApiIdentity,
    request_id: String,
    path: &str,
    headers: &HeaderMap,
    body: &Bytes,
    audit: &mut AuditTracker,
) -> Result<Response, AppError> {
    let parsed = serde_json::from_slice::<Value>(body).ok();
    let model = parsed
        .as_ref()
        .and_then(|value| value.get("model"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let affinity =
        affinity_key(headers, parsed.as_ref()).map(|key| format!("{}:{key}", identity.key_id));
    let mut payload = transform_request(path, parsed, &state)?;
    let first = select_ready_channel(&state, affinity.as_deref()).await?;
    audit.set_channel(&first.channel.id);
    let first_id = first.channel.id.clone();
    let response = send_upstream(
        &state,
        &first,
        path,
        headers,
        &request_id,
        payload.clone().into(),
    )
    .await?;
    track_response(&state, &first_id, response.status(), response.headers()).await?;
    let should_retry = retryable(response.status());
    let (lease, upstream) = if should_retry {
        let second = state
            .balancer
            .select(&state, affinity.as_deref(), Some(&first_id))
            .await;
        match second {
            Ok(mut second) => {
                if refresh_if_needed(&state, &mut second).await.is_err() {
                    return relay_response(
                        CallContext { request_id, model },
                        first,
                        response,
                        audit,
                    )
                    .await;
                }
                drop(response);
                drop(first);
                audit.set_channel(&second.channel.id);
                payload =
                    transform_request(path, serde_json::from_slice::<Value>(body).ok(), &state)?;
                let second_response =
                    send_upstream(&state, &second, path, headers, &request_id, payload.into())
                        .await?;
                track_response(
                    &state,
                    &second.channel.id,
                    second_response.status(),
                    second_response.headers(),
                )
                .await?;
                (second, second_response)
            }
            _ => (first, response),
        }
    } else {
        (first, response)
    };
    if path == "/v1/images/generations" {
        let context = CallContext { request_id, model };
        return image_response(context, lease, upstream, audit).await;
    }
    let context = CallContext { request_id, model };
    relay_response(context, lease, upstream, audit).await
}

async fn dispatch_audio(
    state: AppState,
    identity: ApiIdentity,
    request_id: String,
    path: &str,
    headers: &HeaderMap,
    body: Body,
    audit: &mut AuditTracker,
) -> Result<Response, AppError> {
    let affinity = affinity_key(headers, None).map(|key| format!("{}:{key}", identity.key_id));
    let lease = select_ready_channel(&state, affinity.as_deref()).await?;
    audit.set_channel(&lease.channel.id);
    let upstream = send_upstream(
        &state,
        &lease,
        path,
        headers,
        &request_id,
        reqwest::Body::wrap_stream(body.into_data_stream()),
    )
    .await?;
    track_response(
        &state,
        &lease.channel.id,
        upstream.status(),
        upstream.headers(),
    )
    .await?;
    relay_response(
        CallContext {
            request_id,
            model: None,
        },
        lease,
        upstream,
        audit,
    )
    .await
}

async fn select_ready_channel(state: &AppState, affinity: Option<&str>) -> Result<Lease, AppError> {
    let mut first = state.balancer.select(state, affinity, None).await?;
    if refresh_if_needed(state, &mut first).await.is_ok() {
        return Ok(first);
    }
    let failed_id = first.channel.id.clone();
    drop(first);
    let mut second = state
        .balancer
        .select(state, affinity, Some(&failed_id))
        .await?;
    refresh_if_needed(state, &mut second).await?;
    Ok(second)
}

fn transform_request(
    path: &str,
    mut parsed: Option<Value>,
    state: &AppState,
) -> Result<Bytes, AppError> {
    let value = parsed
        .as_mut()
        .ok_or_else(|| AppError::bad_request("JSON request body required"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| AppError::bad_request("JSON object required"))?;
    if path == "/v1/images/generations" {
        validate_image_request(object)?;
        let prompt = object
            .get("prompt")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::bad_request("prompt is required"))?;
        let image_model = object
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or("gpt-image-1");
        let size = object
            .get("size")
            .and_then(Value::as_str)
            .unwrap_or("1024x1024");
        let quality = object
            .get("quality")
            .and_then(Value::as_str)
            .unwrap_or("auto");
        let background = object
            .get("background")
            .and_then(Value::as_str)
            .unwrap_or("auto");
        let output_format = object
            .get("output_format")
            .and_then(Value::as_str)
            .unwrap_or("png");
        let output_compression = object
            .get("output_compression")
            .and_then(Value::as_u64)
            .unwrap_or(100);
        let moderation = object
            .get("moderation")
            .and_then(Value::as_str)
            .unwrap_or("auto");
        let translated = json!({
            "model": state.config.load().image_host_model,
            "instructions": "You are an image generator. You MUST call image_generation exactly once and return only that tool call. Mirror the user's request verbatim into the prompt argument.",
            "input": [{"type":"message","role":"user","content":[{"type":"input_text","text":prompt}]}],
            "tools": [{"type":"image_generation","model":image_model,"size":size,"quality":quality,"background":background,"output_format":output_format,"output_compression":output_compression,"moderation":moderation}],
            "tool_choice": {"type":"image_generation"}, "stream": true, "store": false
        });
        return serde_json::to_vec(&translated)
            .map(Bytes::from)
            .map_err(Into::into);
    }
    object
        .entry("instructions")
        .or_insert(Value::String(String::new()));
    if !path.ends_with("/compact") {
        object.insert("store".to_owned(), Value::Bool(false));
        object.remove("max_output_tokens");
        object.remove("temperature");
    }
    serde_json::to_vec(value)
        .map(Bytes::from)
        .map_err(Into::into)
}

fn validate_image_request(object: &serde_json::Map<String, Value>) -> Result<(), AppError> {
    if let Some(value) = object.get("n")
        && value.as_i64() != Some(1)
    {
        return Err(AppError::bad_request(
            "image generation supports integer n=1 only",
        ));
    }
    if let Some(value) = object.get("stream") {
        match value.as_bool() {
            Some(false) => {}
            Some(true) => {
                return Err(AppError::bad_request(
                    "streaming images are not supported by this endpoint",
                ));
            }
            None => return Err(AppError::bad_request("stream must be a boolean")),
        }
    }
    if let Some(value) = object.get("response_format")
        && value.as_str() != Some("b64_json")
    {
        return Err(AppError::bad_request(
            "response_format must be the string b64_json",
        ));
    }
    if let Some(value) = object.get("model")
        && value.as_str().is_none_or(str::is_empty)
    {
        return Err(AppError::bad_request("model must be a non-empty string"));
    }
    validate_enum(
        object,
        "size",
        &["auto", "1024x1024", "1536x1024", "1024x1536"],
    )?;
    validate_enum(object, "quality", &["auto", "low", "medium", "high"])?;
    validate_enum(object, "background", &["auto", "opaque", "transparent"])?;
    validate_enum(object, "output_format", &["png", "jpeg", "webp"])?;
    validate_enum(object, "moderation", &["auto", "low"])?;
    if let Some(value) = object.get("output_compression") {
        let compression = value.as_i64().ok_or_else(|| {
            AppError::bad_request("output_compression must be an integer from 0 to 100")
        })?;
        if !(0..=100).contains(&compression) {
            return Err(AppError::bad_request("output_compression must be 0-100"));
        }
    }
    Ok(())
}

fn validate_enum(
    object: &serde_json::Map<String, Value>,
    field: &str,
    allowed: &[&str],
) -> Result<(), AppError> {
    let Some(value) = object.get(field) else {
        return Ok(());
    };
    let value = value
        .as_str()
        .ok_or_else(|| AppError::bad_request(format!("{field} must be a string")))?;
    if !allowed.contains(&value) {
        return Err(AppError::bad_request(format!("unsupported {field}")));
    }
    Ok(())
}

fn affinity_key(headers: &HeaderMap, body: Option<&Value>) -> Option<String> {
    [
        "x-lb-affinity-key",
        "session_id",
        "x-session-id",
        "x-codex-session-id",
        "x-codex-conversation-id",
        "thread-id",
    ]
    .iter()
    .find_map(|name| {
        headers
            .get(*name)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    })
    .or_else(|| {
        body.and_then(|value| {
            ["session_id", "previous_response_id", "prompt_cache_key"]
                .iter()
                .find_map(|name| {
                    value
                        .get(*name)
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(str::to_owned)
                })
        })
    })
}

async fn refresh_if_needed(state: &AppState, lease: &mut Lease) -> Result<(), AppError> {
    if lease
        .channel
        .expires_at
        .is_none_or(|expires| expires > chrono::Utc::now().timestamp() + 60)
    {
        return Ok(());
    }
    let lock = state
        .refresh_locks
        .entry(lease.channel.id.clone())
        .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;
    let current: (String, String, Option<i64>, String) = sqlx::query_as(
        "SELECT access_enc,refresh_enc,expires_at,account_id FROM channels WHERE id=?",
    )
    .bind(&lease.channel.id)
    .fetch_one(&state.db)
    .await?;
    let now = chrono::Utc::now().timestamp();
    if current.2.is_some_and(|expires| expires > now + 60) {
        lease.access_token =
            crate::crypto::decrypt(&state.config.load().encryption_key, &current.0)?;
        lease.refresh_token =
            crate::crypto::decrypt(&state.config.load().encryption_key, &current.1)?;
        lease.channel.expires_at = current.2;
        lease.channel.account_id = current.3;
        return Ok(());
    }
    let refresh_token = crate::crypto::decrypt(&state.config.load().encryption_key, &current.1)?;
    let token = match oauth::refresh(state, &refresh_token).await {
        Ok(token) => token,
        Err(error) => {
            sqlx::query("UPDATE channels SET status='auth_error',last_error='credential refresh failed',updated_at=? WHERE id=? AND refresh_enc=?")
                .bind(now).bind(&lease.channel.id).bind(&current.1).execute(&state.db).await?;
            state.balancer.reload_channels(&state.db).await?;
            return Err(error);
        }
    };
    let account_id = oauth::account_id_from_jwt(&token.access_token)
        .unwrap_or_else(|_| lease.channel.account_id.clone());
    let expires_at = now + token.expires_in;
    let updated = sqlx::query("UPDATE channels SET access_enc=?,refresh_enc=?,account_id=?,expires_at=?,status='active',last_error=NULL,updated_at=? WHERE id=? AND refresh_enc=?")
        .bind(encrypt(&state.config.load().encryption_key, &token.access_token)?)
        .bind(encrypt(&state.config.load().encryption_key, &token.refresh_token)?)
        .bind(&account_id).bind(expires_at).bind(now).bind(&lease.channel.id).bind(&current.1).execute(&state.db).await?;
    if updated.rows_affected() == 0 {
        return Err(AppError::unavailable(
            "channel credential changed during refresh",
        ));
    }
    lease.access_token = token.access_token;
    lease.refresh_token = token.refresh_token;
    lease.channel.account_id = account_id;
    lease.channel.expires_at = Some(expires_at);
    state.balancer.reload_channels(&state.db).await?;
    Ok(())
}

async fn send_upstream(
    state: &AppState,
    lease: &Lease,
    path: &str,
    inbound: &HeaderMap,
    request_id: &str,
    body: reqwest::Body,
) -> Result<reqwest::Response, AppError> {
    let suffix = match path {
        "/v1/audio/transcriptions" => "/transcribe",
        "/v1/responses/compact" | "/backend-api/codex/responses/compact" => "/responses/compact",
        _ => "/responses",
    };
    let mut request = state
        .client
        .post(format!("{}{}", state.config.load().upstream_base, suffix));
    for (name, value) in inbound {
        if should_forward_request_header(path, name) {
            request = request.header(name, value);
        }
    }
    request = request
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", lease.access_token),
        )
        .header("chatgpt-account-id", &lease.channel.account_id)
        .header("x-request-id", request_id);
    if path != "/v1/audio/transcriptions" {
        request = request
            .header(header::CONTENT_TYPE, "application/json")
            .header("OpenAI-Beta", "responses=experimental")
            .header("originator", "codex_cli_rs");
    }
    Ok(request.body(body).send().await?)
}

fn should_forward_request_header(path: &str, name: &HeaderName) -> bool {
    let lower = name.as_str().to_ascii_lowercase();
    if lower == "authorization"
        || HOP_HEADERS.contains(&lower.as_str())
        || PROXY_ONLY_HEADERS.contains(&lower.as_str())
    {
        return false;
    }
    let common = matches!(lower.as_str(), "accept" | "content-type" | "user-agent")
        || lower.starts_with("x-openai-")
        || lower.starts_with("x-codex-");
    if path == "/v1/audio/transcriptions" {
        return common;
    }
    common || lower.starts_with("openai-")
}

fn retryable(status: StatusCode) -> bool {
    matches!(status.as_u16(), 401 | 403 | 429) || status.is_server_error()
}

async fn relay_response(
    context: CallContext,
    lease: Lease,
    upstream: reqwest::Response,
    audit: &mut AuditTracker,
) -> Result<Response, AppError> {
    let status = upstream.status();
    let headers = filtered_response_headers(upstream.headers());
    let is_stream = upstream
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/event-stream"));
    if !is_stream {
        let bytes = upstream.bytes().await?;
        let usage = usage_from_bytes(&bytes);
        audit.finish(
            status,
            context.model.as_deref(),
            usage,
            error_from(status, &bytes).as_deref(),
        );
        return build_response(status, headers, Body::from(bytes));
    }
    let completion = audit.take_stream(status, context.model.as_deref());
    let mut stream = upstream.bytes_stream();
    let output = async_stream::stream! {
        let mut completion = completion;
        let mut usage = Usage::default();
        let mut stream_failed = false;
        let mut pending = Vec::<u8>::new();
        while let Some(item) = stream.next().await {
            match item {
                Ok(bytes) => {
                    update_sse_usage(&mut pending, &bytes, &mut usage);
                    yield Ok::<Bytes, Infallible>(bytes);
                }
                Err(error) => {
                    tracing::warn!(request_id = context.request_id, %error, "upstream stream ended with error");
                    stream_failed = true;
                    break;
                }
            }
        }
        completion.finish(usage, stream_failed);
        drop(lease);
    };
    build_response(status, headers, Body::from_stream(output))
}

async fn image_response(
    context: CallContext,
    lease: Lease,
    upstream: reqwest::Response,
    audit: &mut AuditTracker,
) -> Result<Response, AppError> {
    let status = upstream.status();
    if !status.is_success() {
        return relay_response(context, lease, upstream, audit).await;
    }
    let bytes = upstream.bytes().await?;
    let (images, usage) = images_from_sse(&bytes)?;
    let envelope = serde_json::to_vec(
        &json!({"created": chrono::Utc::now().timestamp(), "data": images, "usage": usage}),
    )?;
    audit.finish(status, context.model.as_deref(), usage, None);
    build_response(
        StatusCode::OK,
        vec![(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        Body::from(envelope),
    )
}

fn images_from_sse(bytes: &[u8]) -> Result<(Vec<Value>, Usage), AppError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| AppError::upstream(502, "invalid image event stream"))?;
    let mut items = Vec::new();
    let mut usage = Usage::default();
    for line in text.lines().filter_map(|line| line.strip_prefix("data: ")) {
        let Ok(event) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        usage.merge(usage_from_value(&event));
        if event.get("type").and_then(Value::as_str) == Some("response.output_item.done")
            && let Some(item) = event.get("item").filter(|item| {
                item.get("type").and_then(Value::as_str) == Some("image_generation_call")
            })
        {
            items.push(item.clone());
        }
        if event.get("type").and_then(Value::as_str) == Some("response.completed")
            && items.is_empty()
            && let Some(output) = event.pointer("/response/output").and_then(Value::as_array)
        {
            items.extend(
                output
                    .iter()
                    .filter(|item| {
                        item.get("type").and_then(Value::as_str) == Some("image_generation_call")
                    })
                    .cloned(),
            );
        }
    }
    let data = items
        .into_iter()
        .filter_map(|item| {
            item.get("result").and_then(Value::as_str).map(
                |result| json!({"b64_json":result,"revised_prompt":item.get("revised_prompt")}),
            )
        })
        .collect::<Vec<_>>();
    if data.is_empty() {
        return Err(AppError::upstream(
            502,
            "upstream did not return image data",
        ));
    }
    Ok((data, usage))
}

fn filtered_response_headers(headers: &HeaderMap) -> Vec<(HeaderName, HeaderValue)> {
    headers
        .iter()
        .filter(|(name, _)| !HOP_HEADERS.contains(&name.as_str().to_ascii_lowercase().as_str()))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

struct StreamCompletion {
    permit: Option<mpsc::OwnedPermit<AuditEvent>>,
    event: Option<AuditEvent>,
    started: Instant,
}

impl StreamCompletion {
    fn new(permit: mpsc::OwnedPermit<AuditEvent>, event: AuditEvent, started: Instant) -> Self {
        Self {
            permit: Some(permit),
            event: Some(event),
            started,
        }
    }

    fn finish(&mut self, usage: Usage, failed: bool) {
        let Some(mut event) = self.event.take() else {
            return;
        };
        let status = if failed { 502 } else { event.status };
        let error = failed.then_some("upstream_stream_error");
        let model = event.model.clone();
        settle(
            &mut event,
            status,
            model.as_deref(),
            usage,
            error,
            self.started,
        );
        self.permit
            .take()
            .expect("audit queue capacity is reserved once")
            .send(event);
    }
}

impl Drop for StreamCompletion {
    fn drop(&mut self) {
        if let Some(mut event) = self.event.take() {
            let model = event.model.clone();
            settle(
                &mut event,
                499,
                model.as_deref(),
                Usage::default(),
                Some("client_cancelled"),
                self.started,
            );
            self.permit
                .take()
                .expect("audit queue capacity is reserved once")
                .send(event);
        }
    }
}

fn build_response(
    status: StatusCode,
    headers: Vec<(HeaderName, HeaderValue)>,
    body: Body,
) -> Result<Response, AppError> {
    let mut response = Response::builder().status(status);
    for (name, value) in headers {
        response = response.header(name, value);
    }
    response
        .body(body)
        .map_err(|_| AppError::internal("failed to build response"))
}

#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
struct Usage {
    input_tokens: i64,
    output_tokens: i64,
    cached_tokens: i64,
}

impl Usage {
    fn merge(&mut self, other: Self) {
        self.input_tokens = self.input_tokens.max(other.input_tokens);
        self.output_tokens = self.output_tokens.max(other.output_tokens);
        self.cached_tokens = self.cached_tokens.max(other.cached_tokens);
    }
}

fn usage_from_bytes(bytes: &[u8]) -> Usage {
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .map(|value| usage_from_value(&value))
        .unwrap_or_default()
}

fn usage_from_value(value: &Value) -> Usage {
    let usage = value
        .get("usage")
        .or_else(|| value.pointer("/response/usage"));
    Usage {
        input_tokens: usage
            .and_then(|v| v.get("input_tokens"))
            .and_then(Value::as_i64)
            .unwrap_or_default(),
        output_tokens: usage
            .and_then(|v| v.get("output_tokens"))
            .and_then(Value::as_i64)
            .unwrap_or_default(),
        cached_tokens: usage
            .and_then(|v| v.pointer("/input_tokens_details/cached_tokens"))
            .and_then(Value::as_i64)
            .unwrap_or_default(),
    }
}

fn update_sse_usage(pending: &mut Vec<u8>, bytes: &[u8], usage: &mut Usage) {
    pending.extend_from_slice(bytes);
    while let Some(index) = pending.iter().position(|byte| *byte == b'\n') {
        let line = pending.drain(..=index).collect::<Vec<_>>();
        let data = line.strip_prefix(b"data: ").unwrap_or_default();
        if let Ok(value) = serde_json::from_slice::<Value>(data) {
            usage.merge(usage_from_value(&value));
        }
    }
    if pending.len() > 2 * 1024 * 1024 {
        pending.clear();
    }
}

fn error_from(status: StatusCode, bytes: &[u8]) -> Option<String> {
    (!status.is_success()).then(|| {
        serde_json::from_slice::<Value>(bytes)
            .ok()
            .and_then(|v| {
                v.pointer("/error/message")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| format!("upstream HTTP {}", status.as_u16()))
    })
}

async fn models_response(
    _state: &AppState,
    audit: &mut AuditTracker,
) -> Result<Response, AppError> {
    let models = [
        "gpt-5.4",
        "gpt-5.3-codex",
        "gpt-5.4-mini",
        "gpt-4o-transcribe",
        "gpt-image-1",
        "gpt-image-1.5",
    ];
    audit.finish(StatusCode::OK, None, Usage::default(), None);
    let body = serde_json::to_vec(
        &json!({"object":"list","data":models.map(|id| json!({"id":id,"object":"model","owned_by":"openai"}))}),
    )?;
    build_response(
        StatusCode::OK,
        vec![(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        Body::from(body),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use axum::{
        Json, Router,
        extract::{OriginalUri, State},
        response::IntoResponse,
        routing::post,
    };
    use http_body_util::BodyExt;
    use tokio::sync::{Mutex, Notify};
    use tower::ServiceExt;

    use super::*;

    #[derive(Clone)]
    struct RecordedRequest {
        path: String,
        headers: HeaderMap,
        body: Bytes,
    }

    #[derive(Clone)]
    struct MockUpstream {
        records: Arc<Mutex<Vec<RecordedRequest>>>,
        status: StatusCode,
    }

    async fn mock_upstream(
        State(mock): State<MockUpstream>,
        OriginalUri(uri): OriginalUri,
        headers: HeaderMap,
        body: Bytes,
    ) -> Response {
        mock.records.lock().await.push(RecordedRequest {
            path: uri.path().to_owned(),
            headers,
            body: body.clone(),
        });
        if mock.status != StatusCode::OK {
            return Response::builder()
                .status(mock.status)
                .header("retry-after", "30")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"error":{"message":"limited"}}"#))
                .unwrap();
        }
        if uri.path() == "/transcribe" {
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(Body::from(body))
                .unwrap();
        }
        let image = serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|value| value.get("tools").cloned())
            .is_some();
        if image {
            let events = concat!(
                "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"image_generation_call\",\"result\":\"aW1hZ2U=\"}}\n\n",
                "data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":2,\"output_tokens\":3}}}\n\n"
            );
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(Body::from(events))
                .unwrap();
        }
        Json(json!({"id":"resp","usage":{"input_tokens":1,"output_tokens":2}})).into_response()
    }

    async fn spawn_mock(status: StatusCode) -> (String, Arc<Mutex<Vec<RecordedRequest>>>) {
        let records = Arc::new(Mutex::new(Vec::new()));
        let mock = MockUpstream {
            records: records.clone(),
            status,
        };
        let app = Router::new()
            .route("/responses", post(mock_upstream))
            .route("/responses/compact", post(mock_upstream))
            .route("/transcribe", post(mock_upstream))
            .with_state(mock);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}"), records)
    }

    async fn seed_proxy(state: &AppState, channel: bool) {
        let now = chrono::Utc::now().timestamp();
        sqlx::query("INSERT INTO users(id,role,created_at) VALUES('user-1','user',?)")
            .bind(now)
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO api_keys(id,user_id,name,prefix,secret_hash,created_at) VALUES('key-1','user-1','test','sk-test',?,?)")
            .bind(crate::crypto::api_key_hash("sk-test-secret")).bind(now).execute(&state.db).await.unwrap();
        if channel {
            sqlx::query("INSERT INTO channels(id,name,account_id,access_enc,refresh_enc,status,created_at,updated_at) VALUES('channel-1','one','account-1',?,?,'active',?,?)")
                .bind(crate::crypto::encrypt(&state.config.load().encryption_key, "access-token").unwrap())
                .bind(crate::crypto::encrypt(&state.config.load().encryption_key, "refresh-token").unwrap())
                .bind(now).bind(now).execute(&state.db).await.unwrap();
            state.balancer.reload_channels(&state.db).await.unwrap();
        }
    }

    async fn wait_for_audits(state: &AppState, expected: i64) {
        for _ in 0..100 {
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_calls")
                .fetch_one(&state.db)
                .await
                .unwrap();
            if count >= expected {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for {expected} audit events");
    }

    fn proxy_request(
        path: &str,
        content_type: &str,
        body: impl Into<Body>,
    ) -> axum::http::Request<Body> {
        axum::http::Request::builder()
            .method(if path == "/v1/models" {
                Method::GET
            } else {
                Method::POST
            })
            .uri(path)
            .header(header::AUTHORIZATION, "Bearer sk-test-secret")
            .header(header::CONTENT_TYPE, content_type)
            .header("x-lb-affinity-key", "explicit-secret")
            .header("x-session-id", "session-secret")
            .header("x-codex-session-id", "codex-session-secret")
            .header("cookie", "private=1")
            .header("x-arbitrary", "drop-me")
            .extension(ConnectInfo(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            ))
            .body(body.into())
            .unwrap()
    }

    #[test]
    fn affinity_order_is_explicit_then_session_then_body() {
        let mut headers = HeaderMap::new();
        headers.insert("x-session-id", HeaderValue::from_static("session"));
        headers.insert("x-lb-affinity-key", HeaderValue::from_static("explicit"));
        assert_eq!(
            affinity_key(&headers, Some(&json!({"previous_response_id":"body"}))).as_deref(),
            Some("explicit")
        );
    }

    #[test]
    fn reads_usage_without_retaining_prompt() {
        let usage = usage_from_value(
            &json!({"usage":{"input_tokens":10,"output_tokens":4,"input_tokens_details":{"cached_tokens":3}}}),
        );
        assert_eq!(
            (usage.input_tokens, usage.output_tokens, usage.cached_tokens),
            (10, 4, 3)
        );
    }

    #[tokio::test]
    async fn audit_persists_usage_without_request_body() {
        let state = crate::test_state("http://token.invalid").await;
        let now = chrono::Utc::now().timestamp();
        sqlx::query("INSERT INTO users(id,role,created_at) VALUES('user-1','user',?)")
            .bind(now)
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO api_keys(id,user_id,name,prefix,secret_hash,created_at) VALUES('key-1','user-1','test','sk-test','hash',?)")
            .bind(now).execute(&state.db).await.unwrap();
        let identity = ApiIdentity {
            key_id: "key-1".to_owned(),
            user_id: "user-1".to_owned(),
        };
        let mut audit = AuditTracker::begin(
            &state,
            &identity,
            "request-1",
            &Method::GET,
            "/v1/models",
            "127.0.0.1",
        )
        .await
        .unwrap();
        audit.finish(
            StatusCode::OK,
            None,
            Usage {
                input_tokens: 12,
                output_tokens: 4,
                cached_tokens: 3,
            },
            None,
        );
        wait_for_audits(&state, 1).await;
        let row: (i64, i64, i64, i64) = sqlx::query_as("SELECT input_tokens,output_tokens,cached_tokens,COUNT(*) FROM api_calls WHERE request_id='request-1'")
            .fetch_one(&state.db).await.unwrap();
        assert_eq!(row, (12, 4, 3, 1));
    }

    #[tokio::test]
    async fn audit_survives_channel_deletion_during_an_inflight_call() {
        let state = crate::test_state("http://token.invalid").await;
        seed_proxy(&state, false).await;
        let identity = ApiIdentity {
            key_id: "key-1".to_owned(),
            user_id: "user-1".to_owned(),
        };
        let mut audit = AuditTracker::begin(
            &state,
            &identity,
            "deleted-channel-request",
            &Method::POST,
            "/v1/responses",
            "127.0.0.1",
        )
        .await
        .unwrap();
        audit.set_channel("channel-1");
        sqlx::query("DELETE FROM channels WHERE id='channel-1'")
            .execute(&state.db)
            .await
            .unwrap();
        audit.finish(StatusCode::OK, Some("gpt-5.4"), Usage::default(), None);

        wait_for_audits(&state, 1).await;
        let row: (i64, Option<String>) = sqlx::query_as(
            "SELECT status,channel_id FROM api_calls WHERE request_id='deleted-channel-request'",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(row, (200, None));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_model_calls_batch_audit_without_sqlite_contention() {
        let state = crate::test_state("http://token.invalid").await;
        seed_proxy(&state, false).await;
        let app = crate::router(state.clone());
        let mut tasks = Vec::new();
        for _ in 0..200 {
            let service = app.clone();
            tasks.push(tokio::spawn(async move {
                service
                    .oneshot(proxy_request(
                        "/v1/models",
                        "application/json",
                        Body::empty(),
                    ))
                    .await
                    .unwrap()
                    .status()
            }));
        }
        for task in tasks {
            assert_eq!(task.await.unwrap(), StatusCode::OK);
        }
        wait_for_audits(&state, 200).await;
        let row: (i64, i64) =
            sqlx::query_as("SELECT COUNT(*),COUNT(DISTINCT request_id) FROM api_calls")
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(row, (200, 200));
    }

    #[tokio::test]
    async fn routes_strip_proxy_headers_and_preserve_binary_audio() {
        let (upstream, records) = spawn_mock(StatusCode::OK).await;
        let state = crate::test_state_with_upstream("http://token.invalid", &upstream).await;
        seed_proxy(&state, true).await;
        let app = crate::router(state.clone());
        let response = app
            .clone()
            .oneshot(proxy_request(
                "/v1/responses",
                "application/json",
                Body::from(r#"{"model":"gpt-5.4","input":"hello"}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = app
            .clone()
            .oneshot(proxy_request(
                "/backend-api/codex/responses/compact",
                "application/json",
                Body::from(r#"{"model":"gpt-5.4","input":"compact"}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let audio = Bytes::from_static(b"\0RIFF\xffbinary-audio");
        let response = app
            .clone()
            .oneshot(proxy_request(
                "/v1/audio/transcriptions",
                "multipart/form-data; boundary=test",
                Body::from(audio.clone()),
            ))
            .await
            .unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            audio
        );
        let response = app
            .clone()
            .oneshot(proxy_request(
                "/v1/models",
                "application/json",
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = app
            .oneshot(proxy_request(
                "/v1/images/generations",
                "application/json",
                Body::from(r#"{"model":"gpt-image-1","prompt":"diagram","n":1}"#),
            ))
            .await
            .unwrap();
        let image: Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(
            image.pointer("/data/0/b64_json").and_then(Value::as_str),
            Some("aW1hZ2U=")
        );

        let records = records.lock().await;
        assert_eq!(
            records
                .iter()
                .map(|record| record.path.as_str())
                .collect::<Vec<_>>(),
            vec![
                "/responses",
                "/responses/compact",
                "/transcribe",
                "/responses"
            ]
        );
        for record in records.iter() {
            assert!(record.headers.get("x-lb-affinity-key").is_none());
            assert!(record.headers.get("x-session-id").is_none());
            assert!(record.headers.get("x-codex-session-id").is_none());
            assert!(record.headers.get("cookie").is_none());
            assert!(record.headers.get("x-arbitrary").is_none());
            assert_eq!(
                record.headers.get(header::AUTHORIZATION).unwrap(),
                "Bearer access-token"
            );
        }
        let response_body: Value = serde_json::from_slice(&records[0].body).unwrap();
        assert_eq!(response_body.get("store"), Some(&Value::Bool(false)));
        assert!(response_body.get("instructions").is_some());
        let compact_body: Value = serde_json::from_slice(&records[1].body).unwrap();
        assert!(compact_body.get("store").is_none());
        assert_eq!(records[2].body, audio);
        drop(records);
        wait_for_audits(&state, 4).await;
        let method: String =
            sqlx::query_scalar("SELECT method FROM api_calls WHERE path='/v1/models'")
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(method, "GET");
    }

    #[tokio::test]
    async fn single_channel_error_is_forwarded_and_failed_calls_are_audited() {
        for expected in [
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::BAD_GATEWAY,
        ] {
            let (upstream, _) = spawn_mock(expected).await;
            let state = crate::test_state_with_upstream("http://token.invalid", &upstream).await;
            seed_proxy(&state, true).await;
            let response = crate::router(state.clone())
                .oneshot(proxy_request(
                    "/v1/responses",
                    "application/json",
                    Body::from(r#"{"model":"gpt-5.4","input":"hello"}"#),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert!(std::str::from_utf8(&body).unwrap().contains("limited"));
            wait_for_audits(&state, 1).await;
            let status: i64 = sqlx::query_scalar("SELECT status FROM api_calls")
                .fetch_one(&state.db)
                .await
                .unwrap();
            assert_eq!(status, expected.as_u16() as i64);
        }

        let state = crate::test_state("http://token.invalid").await;
        seed_proxy(&state, false).await;
        let response = crate::router(state.clone())
            .oneshot(proxy_request(
                "/v1/responses",
                "application/json",
                Body::from(r#"{"model":"gpt-5.4","input":"hello"}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        wait_for_audits(&state, 1).await;
        let status: i64 = sqlx::query_scalar("SELECT status FROM api_calls")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(status, 503);
    }

    #[tokio::test]
    async fn image_parameters_and_header_policy_fail_closed() {
        let state = crate::test_state("http://token.invalid").await;
        for payload in [
            json!({"prompt":"x","n":2}),
            json!({"prompt":"x","n":"1"}),
            json!({"prompt":"x","n":-1}),
            json!({"prompt":"x","stream":"false"}),
            json!({"prompt":"x","response_format":1}),
            json!({"prompt":"x","output_compression":"90"}),
            json!({"prompt":"x","output_compression":-1}),
            json!({"prompt":"x","model":4}),
        ] {
            assert!(transform_request("/v1/images/generations", Some(payload), &state,).is_err());
        }
        let mut headers = HeaderMap::new();
        headers.insert("x-lb-affinity-key", HeaderValue::from_static("secret"));
        assert!(!should_forward_request_header(
            "/v1/responses",
            headers.keys().next().unwrap()
        ));
    }

    #[tokio::test]
    async fn concurrent_refresh_is_singleflight() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let token_app = Router::new().route("/token", post(move || {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Json(json!({"access_token":"access-new","refresh_token":"refresh-new","expires_in":3600}))
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, token_app).await.unwrap();
        });
        let state = crate::test_state(&format!("http://{address}/token")).await;
        let now = chrono::Utc::now().timestamp();
        sqlx::query("INSERT INTO channels(id,name,account_id,access_enc,refresh_enc,expires_at,status,created_at,updated_at) VALUES('channel-1','one','account-1',?,?,?,'active',?,?)")
            .bind(crate::crypto::encrypt(&state.config.load().encryption_key, "access-old").unwrap())
            .bind(crate::crypto::encrypt(&state.config.load().encryption_key, "refresh-old").unwrap())
            .bind(now - 1).bind(now).bind(now).execute(&state.db).await.unwrap();
        state.balancer.reload_channels(&state.db).await.unwrap();
        let first = state.balancer.select(&state, None, None).await.unwrap();
        let second = state.balancer.select(&state, None, None).await.unwrap();
        let state_one = state.clone();
        let state_two = state.clone();
        let one = tokio::spawn(async move {
            let mut lease = first;
            refresh_if_needed(&state_one, &mut lease).await
        });
        let two = tokio::spawn(async move {
            let mut lease = second;
            refresh_if_needed(&state_two, &mut lease).await
        });
        assert!(one.await.unwrap().is_ok());
        assert!(two.await.unwrap().is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancelled_stream_finalizes_pending_audit() {
        let state = crate::test_state("http://token.invalid").await;
        seed_proxy(&state, false).await;
        let identity = ApiIdentity {
            key_id: "key-1".to_owned(),
            user_id: "user-1".to_owned(),
        };
        let mut audit = AuditTracker::begin(
            &state,
            &identity,
            "stream-request",
            &Method::POST,
            "/v1/responses",
            "127.0.0.1",
        )
        .await
        .unwrap();
        drop(audit.take_stream(StatusCode::OK, Some("gpt-5.4")));
        wait_for_audits(&state, 1).await;
        let status: i64 =
            sqlx::query_scalar("SELECT status FROM api_calls WHERE request_id='stream-request'")
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(status, 499);
    }

    #[tokio::test]
    async fn abort_before_upstream_headers_finalizes_pending_audit() {
        let started = Arc::new(Notify::new());
        let signal = started.clone();
        let upstream_app = Router::new().route(
            "/responses",
            post(move || {
                let signal = signal.clone();
                async move {
                    signal.notify_one();
                    std::future::pending::<Response>().await
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, upstream_app).await.unwrap();
        });
        let state =
            crate::test_state_with_upstream("http://token.invalid", &format!("http://{address}"))
                .await;
        seed_proxy(&state, true).await;
        let app = crate::router(state.clone());
        let request_task = tokio::spawn(async move {
            app.oneshot(proxy_request(
                "/v1/responses",
                "application/json",
                Body::from(r#"{"model":"gpt-5.4","input":"wait"}"#),
            ))
            .await
        });
        started.notified().await;
        request_task.abort();
        assert!(request_task.await.unwrap_err().is_cancelled());
        wait_for_audits(&state, 1).await;
        let status: i64 = sqlx::query_scalar("SELECT status FROM api_calls")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(status, 499);
        let pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_calls WHERE status=0")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(pending, 0);
    }
}
