use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Instant,
};

use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, OriginalUri, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header},
    response::Response,
};
use futures_util::StreamExt;
use serde_json::{Value, json};
use tokio::sync::OwnedSemaphorePermit;
use uuid::Uuid;

use crate::{
    AppError, AppState,
    audit::{ARCHIVE_BODY_LIMIT, AuditEvent, AuditReservation},
    auth::{ApiIdentity, api_identity},
    balancer::{Lease, affinity_hash, track_response},
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
    stream: bool,
}

struct AuditTracker {
    permit: Option<AuditReservation>,
    archive_budget: Option<OwnedSemaphorePermit>,
    event: Option<AuditEvent>,
    started: Instant,
}

impl AuditTracker {
    fn begin(
        state: &AppState,
        identity: &ApiIdentity,
        request_id: &str,
        thread_id: Option<&str>,
        method: &Method,
        path: &str,
        client_ip: &str,
    ) -> Self {
        let permit = state.audit.try_reserve();
        let archive_budget = if permit.is_some() && identity.request_archive {
            state.audit.try_reserve_archive()
        } else {
            None
        };
        let event = permit.as_ref().map(|_| AuditEvent {
            id: Uuid::new_v4().to_string(),
            request_id: request_id.to_owned(),
            thread_id: thread_id.map(str::to_owned),
            consumer_id: identity.consumer_id.clone(),
            user_id: identity.user_id.clone(),
            request_archive: archive_budget.is_some(),
            provider_id: None,
            affinity_hash: None,
            affinity_source: None,
            method: method.as_str().to_owned(),
            path: path.to_owned(),
            model: None,
            reasoning_effort: None,
            status: 0,
            first_byte_latency_ms: None,
            request_bytes: 0,
            response_bytes: 0,
            latency_ms: 0,
            input_tokens: 0,
            output_tokens: 0,
            cached_tokens: 0,
            error: None,
            client_ip: client_ip.to_owned(),
            created_at: chrono::Utc::now().timestamp(),
            request_headers_json: "[]".to_owned(),
            request_body: Vec::new(),
            request_body_truncated: false,
            response_headers_json: None,
            response_body: None,
            response_body_truncated: false,
        });
        Self {
            permit,
            archive_budget,
            event,
            started: Instant::now(),
        }
    }

    fn set_provider(&mut self, provider_id: &str) {
        if let Some(event) = &mut self.event {
            event.provider_id = Some(provider_id.to_owned());
        }
    }

    fn set_affinity(&mut self, key: Option<&str>, source: Option<&str>) {
        if let Some(event) = &mut self.event {
            event.affinity_hash = key.map(affinity_hash);
            event.affinity_source = source.map(str::to_owned);
        }
    }

    fn set_reasoning_effort(&mut self, effort: Option<&str>) {
        if let Some(event) = &mut self.event {
            event.reasoning_effort = effort.map(str::to_owned);
        }
    }

    fn set_request(&mut self, headers: &HeaderMap, body: &[u8], truncated: bool) {
        if let Some(event) = &mut self.event {
            if !event.request_archive {
                return;
            }
            event.request_headers_json = archive_headers(headers);
            let (body, limit_truncated) = body_preview(body);
            event.request_body = body;
            event.request_body_truncated = truncated || limit_truncated;
        }
    }

    fn set_response_headers(&mut self, headers: &HeaderMap) {
        if let Some(event) = &mut self.event {
            if !event.request_archive {
                return;
            }
            event.response_headers_json = Some(archive_headers(headers));
        }
    }

    fn mark_first_byte(&mut self) {
        let elapsed = self.started.elapsed().as_millis().max(1) as i64;
        if let Some(event) = &mut self.event {
            event.first_byte_latency_ms.get_or_insert(elapsed);
        }
    }

    fn set_request_size(&mut self, bytes: i64) {
        if let Some(event) = &mut self.event {
            event.request_bytes = bytes;
        }
    }

    fn set_response_size(&mut self, bytes: i64) {
        if let Some(event) = &mut self.event {
            event.response_bytes = bytes;
        }
    }

    fn set_response_body(&mut self, body: &[u8], truncated: bool) {
        if let Some(event) = &mut self.event {
            if !event.request_archive {
                return;
            }
            let (body, limit_truncated) = body_preview(body);
            event.response_body = Some(body);
            event.response_body_truncated = truncated || limit_truncated;
        }
    }

    fn set_error_response(&mut self, error: &AppError) {
        let body = serde_json::to_vec(&json!({"error":{
            "message":error.message(),
            "type":"proxy_error",
            "code":error.status().as_u16()
        }}))
        .expect("proxy error response is serializable");
        self.set_response_size(body.len() as i64);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        self.set_response_headers(&headers);
        self.set_response_body(&body, false);
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
            .send(event, self.archive_budget.take());
    }

    fn take_stream(&mut self, status: StatusCode, model: Option<&str>) -> StreamCompletion {
        if let Some(event) = &mut self.event {
            event.status = status.as_u16() as i64;
            event.model = model.map(str::to_owned);
        }
        StreamCompletion::new(
            self.permit.take(),
            self.archive_budget.take(),
            self.event.take(),
            self.started,
        )
    }
}

impl Drop for AuditTracker {
    fn drop(&mut self) {
        if let Some(mut event) = self.event.take() {
            event.response_body_truncated = true;
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
                .send(event, self.archive_budget.take());
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
    let thread_id = thread_id(&headers);
    let identity = api_identity(&state, &headers).await?;
    let client_ip = peer.ip().to_string();
    let mut audit = AuditTracker::begin(
        &state,
        &identity,
        &request_id,
        thread_id.as_deref(),
        &method,
        uri.path(),
        &client_ip,
    );
    audit.set_request(&headers, &body, false);
    audit.set_request_size(body.len() as i64);
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
        audit.set_error_response(error);
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
    let thread_id = thread_id(&headers);
    let identity = api_identity(&state, &headers).await?;
    let mut audit = AuditTracker::begin(
        &state,
        &identity,
        &request_id,
        thread_id.as_deref(),
        &method,
        uri.path(),
        &peer.ip().to_string(),
    );
    audit.set_request(&headers, &[], true);
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
        audit.set_error_response(error);
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
    headers: HeaderMap,
) -> Result<Response, AppError> {
    api_identity(&state, &headers).await?;
    models_response()
}

fn body_preview(body: &[u8]) -> (Vec<u8>, bool) {
    let end = body.len().min(ARCHIVE_BODY_LIMIT);
    (body[..end].to_vec(), body.len() > end)
}

fn archive_headers(headers: &HeaderMap) -> String {
    let values = headers
        .iter()
        .filter(|(name, _)| archive_header_allowed(name))
        .map(|(name, value)| {
            (
                name.as_str(),
                value.to_str().unwrap_or("<non-UTF-8 header value>"),
            )
        })
        .collect::<Vec<_>>();
    serde_json::to_string(&values).expect("HTTP headers are serializable")
}

fn archive_header_allowed(name: &HeaderName) -> bool {
    let name = name.as_str();
    matches!(
        name,
        "accept"
            | "accept-encoding"
            | "content-encoding"
            | "content-length"
            | "content-type"
            | "date"
            | "retry-after"
            | "server"
            | "user-agent"
            | "x-request-id"
    ) || name.starts_with("x-ratelimit-")
}

#[derive(Default)]
struct StreamingPreview {
    body: Vec<u8>,
    truncated: bool,
    bytes: i64,
}

impl StreamingPreview {
    fn capture(&mut self, bytes: &[u8]) {
        self.bytes += bytes.len() as i64;
        let remaining = ARCHIVE_BODY_LIMIT.saturating_sub(self.body.len());
        let copied = remaining.min(bytes.len());
        self.body.extend_from_slice(&bytes[..copied]);
        self.truncated |= copied < bytes.len();
    }
}

fn request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

fn thread_id(headers: &HeaderMap) -> Option<String> {
    ["x-codex-conversation-id", "thread-id"]
        .iter()
        .find_map(|name| {
            headers
                .get(*name)
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        })
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
    audit.set_reasoning_effort(parsed.as_ref().and_then(reasoning_effort).as_deref());
    let stream = parsed
        .as_ref()
        .and_then(|value| value.get("stream"))
        .and_then(Value::as_bool)
        .unwrap_or_default();
    let affinity_key = affinity_key(headers, parsed.as_ref());
    let affinity = affinity_key
        .as_ref()
        .map(|key| format!("{}:{}", identity.consumer_id, key.value));
    audit.set_affinity(
        affinity.as_deref(),
        affinity_key.as_ref().map(|key| key.source),
    );
    let mut payload = transform_request(path, parsed, &state)?;
    let first = select_ready_provider(&state, &identity, affinity.as_deref()).await?;
    audit.set_provider(&first.provider.id);
    let first_id = first.provider.id.clone();
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
            .select(
                &state,
                &identity.user_id,
                identity.all_providers,
                affinity.as_deref(),
                Some(&first_id),
            )
            .await;
        match second {
            Ok(mut second) => {
                if refresh_if_needed(&state, &mut second).await.is_err() {
                    return relay_response(
                        CallContext {
                            request_id,
                            model,
                            stream,
                        },
                        first,
                        response,
                        audit,
                    )
                    .await;
                }
                drop(response);
                drop(first);
                audit.set_provider(&second.provider.id);
                payload =
                    transform_request(path, serde_json::from_slice::<Value>(body).ok(), &state)?;
                let second_response =
                    send_upstream(&state, &second, path, headers, &request_id, payload.into())
                        .await?;
                track_response(
                    &state,
                    &second.provider.id,
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
        let context = CallContext {
            request_id,
            model,
            stream,
        };
        return image_response(context, lease, upstream, audit).await;
    }
    let context = CallContext {
        request_id,
        model,
        stream,
    };
    relay_response(context, lease, upstream, audit).await
}

fn reasoning_effort(request: &Value) -> Option<String> {
    request
        .pointer("/reasoning/effort")
        .and_then(Value::as_str)
        .or_else(|| request.get("reasoning_effort").and_then(Value::as_str))
        .map(str::to_owned)
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
    let affinity_key = affinity_key(headers, None);
    let affinity = affinity_key
        .as_ref()
        .map(|key| format!("{}:{}", identity.consumer_id, key.value));
    audit.set_affinity(
        affinity.as_deref(),
        affinity_key.as_ref().map(|key| key.source),
    );
    let lease = select_ready_provider(&state, &identity, affinity.as_deref()).await?;
    audit.set_provider(&lease.provider.id);
    let preview = Arc::new(Mutex::new(StreamingPreview::default()));
    let capture = preview.clone();
    let stream = body.into_data_stream().map(move |item| {
        if let Ok(bytes) = &item {
            capture
                .lock()
                .expect("audio preview mutex is not poisoned")
                .capture(bytes);
        }
        item
    });
    let upstream = send_upstream(
        &state,
        &lease,
        path,
        headers,
        &request_id,
        reqwest::Body::wrap_stream(stream),
    )
    .await;
    let (body, truncated, bytes) = {
        let preview = preview.lock().expect("audio preview mutex is not poisoned");
        (preview.body.clone(), preview.truncated, preview.bytes)
    };
    audit.set_request(headers, &body, truncated);
    audit.set_request_size(bytes);
    let upstream = upstream?;
    track_response(
        &state,
        &lease.provider.id,
        upstream.status(),
        upstream.headers(),
    )
    .await?;
    relay_response(
        CallContext {
            request_id,
            model: None,
            stream: false,
        },
        lease,
        upstream,
        audit,
    )
    .await
}

async fn select_ready_provider(
    state: &AppState,
    identity: &ApiIdentity,
    affinity: Option<&str>,
) -> Result<Lease, AppError> {
    let mut first = state
        .balancer
        .select(
            state,
            &identity.user_id,
            identity.all_providers,
            affinity,
            None,
        )
        .await?;
    if refresh_if_needed(state, &mut first).await.is_ok() {
        return Ok(first);
    }
    let failed_id = first.provider.id.clone();
    drop(first);
    let mut second = state
        .balancer
        .select(
            state,
            &identity.user_id,
            identity.all_providers,
            affinity,
            Some(&failed_id),
        )
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

struct AffinityKey {
    source: &'static str,
    value: String,
}

fn affinity_key(headers: &HeaderMap, body: Option<&Value>) -> Option<AffinityKey> {
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
            .map(|value| AffinityKey {
                source: name,
                value: value.to_owned(),
            })
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
                        .map(|value| AffinityKey {
                            source: name,
                            value: value.to_owned(),
                        })
                })
        })
    })
}

async fn refresh_if_needed(state: &AppState, lease: &mut Lease) -> Result<(), AppError> {
    if lease
        .provider
        .expires_at
        .is_none_or(|expires| expires > chrono::Utc::now().timestamp() + 60)
    {
        return Ok(());
    }
    let lock = state
        .refresh_locks
        .entry(lease.provider.id.clone())
        .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;
    let current: (String, String, Option<i64>, String) = sqlx::query_as(
        "SELECT access_token,refresh_token,expires_at,account_id FROM providers WHERE id=?",
    )
    .bind(&lease.provider.id)
    .fetch_one(&state.db)
    .await?;
    let now = chrono::Utc::now().timestamp();
    if current.2.is_some_and(|expires| expires > now + 60) {
        lease.access_token = current.0;
        lease.refresh_token = current.1;
        lease.provider.expires_at = current.2;
        lease.provider.account_id = current.3;
        return Ok(());
    }
    let refresh_token = current.1.clone();
    let token = match oauth::refresh(state, &refresh_token).await {
        Ok(token) => token,
        Err(error) => {
            sqlx::query("UPDATE providers SET status='auth_error',last_error='credential refresh failed',updated_at=? WHERE id=? AND refresh_token=?")
                .bind(now).bind(&lease.provider.id).bind(&current.1).execute(&state.db).await?;
            state.balancer.reload_providers(&state.db).await?;
            return Err(error);
        }
    };
    let account_id = oauth::account_id_from_jwt(&token.access_token)
        .unwrap_or_else(|_| lease.provider.account_id.clone());
    let expires_at = now + token.expires_in;
    let updated = sqlx::query("UPDATE providers SET access_token=?,refresh_token=?,account_id=?,expires_at=?,status='active',last_error=NULL,updated_at=? WHERE id=? AND refresh_token=?")
        .bind(&token.access_token)
        .bind(&token.refresh_token)
        .bind(&account_id).bind(expires_at).bind(now).bind(&lease.provider.id).bind(&current.1).execute(&state.db).await?;
    if updated.rows_affected() == 0 {
        return Err(AppError::unavailable(
            "provider credential changed during refresh",
        ));
    }
    lease.access_token = token.access_token;
    lease.refresh_token = token.refresh_token;
    lease.provider.account_id = account_id;
    lease.provider.expires_at = Some(expires_at);
    state.balancer.reload_providers(&state.db).await?;
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
        .header("chatgpt-account-id", &lease.provider.account_id)
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
    let common = matches!(lower.as_str(), "accept" | "user-agent")
        || lower.starts_with("x-openai-")
        || lower.starts_with("x-codex-");
    if path == "/v1/audio/transcriptions" {
        return common || lower == "content-type";
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
    audit.mark_first_byte();
    let status = upstream.status();
    audit.set_response_headers(upstream.headers());
    let headers = filtered_response_headers(upstream.headers());
    let is_stream = context.stream && status.is_success();
    if !is_stream {
        let bytes = upstream.bytes().await?;
        audit.set_response_size(bytes.len() as i64);
        audit.set_response_body(&bytes, false);
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
        let mut stream_failed = false;
        let mut pending = Vec::<u8>::new();
        while let Some(item) = stream.next().await {
            match item {
                Ok(bytes) => {
                    completion.capture_sse(&mut pending, &bytes);
                    yield Ok::<Bytes, Infallible>(bytes);
                }
                Err(error) => {
                    tracing::warn!(request_id = context.request_id, %error, "upstream stream ended with error");
                    stream_failed = true;
                    break;
                }
            }
        }
        completion.finish(stream_failed);
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
    audit.mark_first_byte();
    let status = upstream.status();
    if !status.is_success() {
        return relay_response(context, lease, upstream, audit).await;
    }
    let bytes = upstream.bytes().await?;
    let (images, usage) = images_from_sse(&bytes)?;
    let envelope = serde_json::to_vec(
        &json!({"created": chrono::Utc::now().timestamp(), "data": images, "usage": usage}),
    )?;
    audit.set_response_size(envelope.len() as i64);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    audit.set_response_headers(&headers);
    audit.set_response_body(&envelope, false);
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
    permit: Option<AuditReservation>,
    archive_budget: Option<OwnedSemaphorePermit>,
    event: Option<AuditEvent>,
    started: Instant,
    usage: Usage,
    response_preview: StreamingPreview,
    response_bytes: i64,
}

impl StreamCompletion {
    fn new(
        permit: Option<AuditReservation>,
        archive_budget: Option<OwnedSemaphorePermit>,
        event: Option<AuditEvent>,
        started: Instant,
    ) -> Self {
        Self {
            permit,
            archive_budget,
            event,
            started,
            usage: Usage::default(),
            response_preview: StreamingPreview::default(),
            response_bytes: 0,
        }
    }

    fn capture_sse(&mut self, pending: &mut Vec<u8>, bytes: &[u8]) {
        let Some(request_archive) = self.event.as_ref().map(|event| event.request_archive) else {
            return;
        };
        self.response_bytes += bytes.len() as i64;
        update_sse_usage(pending, bytes, &mut self.usage);
        if request_archive {
            self.response_preview.capture(bytes);
        }
    }

    fn finish(&mut self, failed: bool) {
        let Some(mut event) = self.event.take() else {
            return;
        };
        let status = if failed { 502 } else { event.status };
        let error = failed.then_some("upstream_stream_error");
        let model = event.model.clone();
        event.response_body = Some(std::mem::take(&mut self.response_preview.body));
        event.response_body_truncated = self.response_preview.truncated || failed;
        event.response_bytes = self.response_bytes;
        settle(
            &mut event,
            status,
            model.as_deref(),
            self.usage,
            error,
            self.started,
        );
        self.permit
            .take()
            .expect("audit queue capacity is reserved once")
            .send(event, self.archive_budget.take());
    }
}

impl Drop for StreamCompletion {
    fn drop(&mut self) {
        if let Some(mut event) = self.event.take() {
            let model = event.model.clone();
            event.response_body = Some(std::mem::take(&mut self.response_preview.body));
            event.response_body_truncated = true;
            event.response_bytes = self.response_bytes;
            settle(
                &mut event,
                499,
                model.as_deref(),
                self.usage,
                Some("client_cancelled"),
                self.started,
            );
            self.permit
                .take()
                .expect("audit queue capacity is reserved once")
                .send(event, self.archive_budget.take());
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

fn models_response() -> Result<Response, AppError> {
    let models = [
        "gpt-5.4",
        "gpt-5.3-codex",
        "gpt-5.4-mini",
        "gpt-4o-transcribe",
        "gpt-image-1",
        "gpt-image-1.5",
    ];
    let body = serde_json::to_vec(
        &json!({"object":"list","data":models.map(|id| json!({"id":id,"object":"model","owned_by":"openai"}))}),
    )?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
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
        let stream = serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|value| value.get("stream").and_then(Value::as_bool))
            .unwrap_or_default();
        if stream {
            let events = concat!(
                "event: response.created\n",
                "data: {\"type\":\"response.created\",\"response\":{\"usage\":null},\"sequence_number\":1}\n\n",
                "event: response.completed\n",
                "data: {\"type\":\"response.completed\",\"response\":{\"model\":\"gpt-5.5\",\"usage\":{",
                "\"input_tokens\":19,\"input_tokens_details\":{\"cache_write_tokens\":0,\"cached_tokens\":0},",
                "\"output_tokens\":6,\"output_tokens_details\":{\"reasoning_tokens\":0},\"total_tokens\":25}},",
                "\"sequence_number\":9}\n\n",
            );
            return Response::builder()
                .status(StatusCode::OK)
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

    async fn spawn_stream_mock(fail_after_first_chunk: bool) -> (String, Arc<Notify>) {
        let interrupt = Arc::new(Notify::new());
        let wait_for_interrupt = interrupt.clone();
        let app = Router::new().route(
            "/responses",
            post(move || {
                let wait_for_interrupt = wait_for_interrupt.clone();
                async move {
                    let output = async_stream::stream! {
                        yield Ok::<Bytes, std::io::Error>(Bytes::from_static(
                            b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n\n",
                        ));
                        if fail_after_first_chunk {
                            wait_for_interrupt.notified().await;
                            yield Err(std::io::Error::other("test stream failure"));
                        } else {
                            yield Ok(Bytes::from_static(
                                b"data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":1,\"output_tokens\":2}}}\n\n",
                            ));
                        }
                    };
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "text/event-stream")
                        .body(Body::from_stream(output))
                        .unwrap()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}"), interrupt)
    }

    async fn seed_proxy(state: &AppState, provider: bool) {
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO users(id,role,provider_access,created_at) VALUES('user-1','user',1,?)",
        )
        .bind(now)
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query("INSERT INTO consumers(id,user_id,name,prefix,secret_hash,request_archive,created_at) VALUES('key-1','user-1','test','sk-test',?,1,?)")
            .bind(crate::crypto::consumer_secret_hash("sk-test-secret")).bind(now).execute(&state.db).await.unwrap();
        if provider {
            sqlx::query("INSERT INTO providers(id,name,account_id,access_token,refresh_token,status,created_at,updated_at) VALUES('provider-1','one','account-1',?,?,'active',?,?)")
                .bind("access-token")
                .bind("refresh-token")
                .bind(now).bind(now).execute(&state.db).await.unwrap();
            state.balancer.reload_providers(&state.db).await.unwrap();
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
            affinity_key(&headers, Some(&json!({"previous_response_id":"body"})))
                .map(|key| key.value)
                .as_deref(),
            Some("explicit")
        );
    }

    #[test]
    fn thread_id_extracts_existing_downstream_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("thread-id", HeaderValue::from_static("app-thread"));
        assert_eq!(thread_id(&headers).as_deref(), Some("app-thread"));

        headers.insert(
            "x-codex-conversation-id",
            HeaderValue::from_static("codex-thread"),
        );
        assert_eq!(thread_id(&headers).as_deref(), Some("codex-thread"));

        headers.clear();
        assert_eq!(thread_id(&headers), None);
    }

    #[tokio::test]
    async fn models_calls_are_not_audited() {
        let state = crate::test_state("http://token.invalid").await;
        seed_proxy(&state, false).await;
        let app = crate::router(state.clone());
        let mut request = proxy_request("/v1/models", "application/json", Body::empty());
        request.headers_mut().insert(
            "x-codex-conversation-id",
            HeaderValue::from_static("codex-thread"),
        );
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let calls: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_calls")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(calls, 0);
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

    #[test]
    fn diagnostic_preview_uses_a_safe_header_allowlist() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer secret"),
        );
        headers.insert("x-api-key", HeaderValue::from_static("secret"));
        headers.insert("x-openai-api-key", HeaderValue::from_static("secret"));
        headers.insert("x-auth", HeaderValue::from_static("secret"));
        headers.insert("x-credential", HeaderValue::from_static("secret"));
        headers.insert("access-key", HeaderValue::from_static("secret"));
        headers.insert("x-session-id", HeaderValue::from_static("session-secret"));
        headers.insert("x-arbitrary", HeaderValue::from_static("private"));
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        let archived = archive_headers(&headers);
        assert_eq!(archived, r#"[["content-type","application/json"]]"#);

        let (preview, truncated) = body_preview(&vec![7; ARCHIVE_BODY_LIMIT + 1]);
        assert_eq!(preview.len(), ARCHIVE_BODY_LIMIT);
        assert!(truncated);
    }

    #[test]
    fn reads_usage_from_response_completed_sse_across_chunks() {
        let event = concat!(
            "data: {\"type\":\"response.completed\",\"response\":{\"usage\":{",
            "\"input_tokens\":11,\"output_tokens\":5,",
            "\"input_tokens_details\":{\"cached_tokens\":7}}}}\n\n",
        );
        let mut pending = Vec::new();
        let mut usage = Usage::default();

        for chunk in event.as_bytes().chunks(17) {
            update_sse_usage(&mut pending, chunk, &mut usage);
        }

        assert_eq!(
            (usage.input_tokens, usage.cached_tokens, usage.output_tokens),
            (11, 7, 5)
        );
    }

    #[test]
    fn reads_reasoning_effort_from_supported_request_shapes() {
        assert_eq!(
            reasoning_effort(&json!({"reasoning":{"effort":"high"}})),
            Some("high".to_owned())
        );
        assert_eq!(
            reasoning_effort(&json!({"reasoning_effort":"medium"})),
            Some("medium".to_owned())
        );
        assert_eq!(reasoning_effort(&json!({"reasoning":{}})), None);
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
        sqlx::query("INSERT INTO consumers(id,user_id,name,prefix,secret_hash,created_at) VALUES('key-1','user-1','test','sk-test','hash',?)")
            .bind(now).execute(&state.db).await.unwrap();
        let identity = ApiIdentity {
            consumer_id: "key-1".to_owned(),
            user_id: "user-1".to_owned(),
            request_archive: false,
            all_providers: false,
        };
        let mut audit = AuditTracker::begin(
            &state,
            &identity,
            "request-1",
            Some("thread-1"),
            &Method::GET,
            "/v1/models",
            "127.0.0.1",
        );
        audit.set_affinity(
            Some("key-1:previous-response"),
            Some("previous_response_id"),
        );
        audit.set_reasoning_effort(Some("high"));
        audit.mark_first_byte();
        audit.set_request_size(42);
        audit.set_response_size(64);
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
        let row: (i64, i64, i64, Option<i64>, i64, i64, i64, String, String) = sqlx::query_as("SELECT input_tokens,output_tokens,cached_tokens,first_byte_latency_ms,request_bytes,response_bytes,COUNT(*),affinity_hash,affinity_source FROM api_calls WHERE request_id='request-1'")
            .fetch_one(&state.db).await.unwrap();
        assert_eq!(
            row,
            (
                12,
                4,
                3,
                Some(1),
                42,
                64,
                1,
                affinity_hash("key-1:previous-response"),
                "previous_response_id".to_owned(),
            )
        );
        let effort: Option<String> = sqlx::query_scalar(
            "SELECT reasoning_effort FROM api_calls WHERE request_id='request-1'",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(effort.as_deref(), Some("high"));
        let archives: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM request_archives")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(archives, 0);
    }

    #[tokio::test]
    async fn stream_cancellation_preserves_captured_usage() {
        let state = crate::test_state("http://token.invalid").await;
        seed_proxy(&state, false).await;
        let identity = ApiIdentity {
            consumer_id: "key-1".to_owned(),
            user_id: "user-1".to_owned(),
            request_archive: true,
            all_providers: false,
        };
        let mut audit = AuditTracker::begin(
            &state,
            &identity,
            "cancelled-stream",
            Some("cancelled-thread"),
            &Method::POST,
            "/v1/responses",
            "127.0.0.1",
        );
        let mut completion = audit.take_stream(StatusCode::OK, Some("gpt-5.5"));
        let mut pending = Vec::new();
        completion.capture_sse(
            &mut pending,
            concat!(
                "data: {\"type\":\"response.completed\",\"response\":{\"usage\":{",
                "\"input_tokens\":11,\"output_tokens\":5,",
                "\"input_tokens_details\":{\"cached_tokens\":7}}}}\n\n",
            )
            .as_bytes(),
        );

        drop(completion);
        wait_for_audits(&state, 1).await;

        let row: (i64, i64, i64, i64, String, bool) = sqlx::query_as(
            "SELECT c.input_tokens,c.cached_tokens,c.output_tokens,c.status,c.error,a.response_body_truncated FROM api_calls c JOIN request_archives a ON a.api_call_id=c.id WHERE c.request_id='cancelled-stream'",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(row, (11, 7, 5, 499, "client_cancelled".to_owned(), true));
    }

    #[tokio::test]
    async fn requested_stream_audits_real_sse_without_content_type() {
        let (upstream, _) = spawn_mock(StatusCode::OK).await;
        let state = crate::test_state_with_upstream("http://token.invalid", &upstream).await;
        seed_proxy(&state, true).await;
        let response = crate::router(state.clone())
            .oneshot(proxy_request(
                "/v1/responses",
                "application/json",
                Body::from(r#"{"model":"gpt-5.5","input":"audit","stream":true}"#),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(body.ends_with(b"\n\n"));
        wait_for_audits(&state, 1).await;

        let row: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT input_tokens,cached_tokens,output_tokens,response_bytes FROM api_calls",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(row, (19, 0, 6, body.len() as i64));
    }

    #[tokio::test]
    async fn audit_survives_provider_deletion_during_an_inflight_call() {
        let state = crate::test_state("http://token.invalid").await;
        seed_proxy(&state, false).await;
        let identity = ApiIdentity {
            consumer_id: "key-1".to_owned(),
            user_id: "user-1".to_owned(),
            request_archive: true,
            all_providers: false,
        };
        let mut audit = AuditTracker::begin(
            &state,
            &identity,
            "deleted-provider-request",
            Some("deleted-provider-thread"),
            &Method::POST,
            "/v1/responses",
            "127.0.0.1",
        );
        audit.set_provider("provider-1");
        sqlx::query("DELETE FROM providers WHERE id='provider-1'")
            .execute(&state.db)
            .await
            .unwrap();
        audit.finish(StatusCode::OK, Some("gpt-5.4"), Usage::default(), None);

        wait_for_audits(&state, 1).await;
        let row: (i64, Option<String>) = sqlx::query_as(
            "SELECT status,provider_id FROM api_calls WHERE request_id='deleted-provider-request'",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(row, (200, None));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_proxy_calls_batch_audit_without_sqlite_contention() {
        let (upstream, _) = spawn_mock(StatusCode::OK).await;
        let state = crate::test_state_with_upstream("http://token.invalid", &upstream).await;
        seed_proxy(&state, true).await;
        let app = crate::router(state.clone());
        let mut tasks = Vec::new();
        for _ in 0..200 {
            let service = app.clone();
            tasks.push(tokio::spawn(async move {
                service
                    .oneshot(proxy_request(
                        "/v1/responses",
                        "application/json",
                        Body::from(r#"{"model":"gpt-5.4","input":"audit"}"#),
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
                "application/vnd.client+json",
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
        for record in [&records[0], &records[1], &records[3]] {
            assert_eq!(
                record.headers.get_all(header::CONTENT_TYPE).iter().count(),
                1
            );
            assert_eq!(
                record.headers.get(header::CONTENT_TYPE).unwrap(),
                "application/json"
            );
        }
        assert_eq!(
            records[2].headers.get(header::CONTENT_TYPE).unwrap(),
            "multipart/form-data; boundary=test"
        );
        assert_eq!(records[2].body, audio);
        drop(records);
        wait_for_audits(&state, 4).await;
        let model_calls: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM api_calls WHERE path='/v1/models'")
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(model_calls, 0);
        let archive: (String, Vec<u8>, Vec<u8>, bool, bool) = sqlx::query_as(
            "SELECT a.request_headers_json,a.request_body,a.response_body,a.request_body_truncated,a.response_body_truncated FROM request_archives a JOIN api_calls c ON c.id=a.api_call_id WHERE c.path='/v1/responses'",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert!(!archive.0.contains("authorization"));
        assert!(!archive.0.contains("sk-test-secret"));
        assert!(!archive.0.contains("session-secret"));
        assert!(std::str::from_utf8(&archive.1).unwrap().contains("hello"));
        assert!(std::str::from_utf8(&archive.2).unwrap().contains("resp"));
        assert!(!archive.3);
        assert!(!archive.4);

        let archived_audio: Vec<u8> = sqlx::query_scalar(
            "SELECT a.request_body FROM request_archives a JOIN api_calls c ON c.id=a.api_call_id WHERE c.path='/v1/audio/transcriptions'",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(archived_audio, audio);
        let audio_sizes: (i64, i64) = sqlx::query_as(
            "SELECT request_bytes,response_bytes FROM api_calls WHERE path='/v1/audio/transcriptions'",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(audio_sizes, (audio.len() as i64, audio.len() as i64));
    }

    #[tokio::test]
    async fn network_failure_is_returned_and_archived() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (connection, _) = listener.accept().await.unwrap();
            drop(connection);
        });
        let state =
            crate::test_state_with_upstream("http://token.invalid", &format!("http://{address}"))
                .await;
        seed_proxy(&state, true).await;

        let response = crate::router(state.clone())
            .oneshot(proxy_request(
                "/v1/responses",
                "application/json",
                Body::from(r#"{"model":"gpt-5.4","input":"network"}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        wait_for_audits(&state, 1).await;

        let archived: (i64, String, Vec<u8>, Vec<u8>) = sqlx::query_as(
            "SELECT c.status,c.error,a.request_body,a.response_body FROM api_calls c JOIN request_archives a ON a.api_call_id=c.id",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(archived.0, 500);
        assert_eq!(archived.1, "internal server error");
        assert!(
            std::str::from_utf8(&archived.2)
                .unwrap()
                .contains("network")
        );
        assert!(
            std::str::from_utf8(&archived.3)
                .unwrap()
                .contains("internal server error")
        );
    }

    #[tokio::test]
    async fn streaming_response_body_is_archived_and_interruption_is_marked_truncated() {
        for failed in [false, true] {
            let (upstream, interrupt) = spawn_stream_mock(failed).await;
            let state = crate::test_state_with_upstream("http://token.invalid", &upstream).await;
            seed_proxy(&state, true).await;
            let response = crate::router(state.clone())
                .oneshot(proxy_request(
                    "/v1/responses",
                    "application/json",
                    Body::from(r#"{"model":"gpt-5.4","input":"stream","stream":true}"#),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            if failed {
                interrupt.notify_one();
            }
            let client_body = response.into_body().collect().await.unwrap().to_bytes();
            assert!(std::str::from_utf8(&client_body).unwrap().contains("hello"));
            wait_for_audits(&state, 1).await;

            let archived: (i64, Option<String>, Vec<u8>, bool) = sqlx::query_as(
                "SELECT c.status,c.error,a.response_body,a.response_body_truncated FROM api_calls c JOIN request_archives a ON a.api_call_id=c.id",
            )
            .fetch_one(&state.db)
            .await
            .unwrap();
            assert!(std::str::from_utf8(&archived.2).unwrap().contains("hello"));
            if failed {
                assert_eq!(archived.0, 502);
                assert_eq!(archived.1.as_deref(), Some("upstream_stream_error"));
                assert!(archived.3);
            } else {
                assert_eq!(archived.0, 200);
                assert_eq!(archived.1, None);
                assert!(!archived.3);
                assert!(
                    std::str::from_utf8(&archived.2)
                        .unwrap()
                        .contains("response.completed")
                );
            }
        }
    }

    #[tokio::test]
    async fn temporary_archive_write_failure_does_not_change_response_and_retries() {
        let (upstream, _) = spawn_mock(StatusCode::OK).await;
        let state = crate::test_state_with_upstream("http://token.invalid", &upstream).await;
        seed_proxy(&state, true).await;
        sqlx::query("DROP TABLE request_archives")
            .execute(&state.db)
            .await
            .unwrap();
        let retries_before = crate::audit::write_retries();

        let response = crate::router(state.clone())
            .oneshot(proxy_request(
                "/v1/responses",
                "application/json",
                Body::from(r#"{"model":"gpt-5.4","input":"archive"}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(std::str::from_utf8(&body).unwrap().contains("resp"));

        for _ in 0..100 {
            if crate::audit::write_retries() > retries_before {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(crate::audit::write_retries() > retries_before);
        sqlx::query(
            "CREATE TABLE request_archives (api_call_id TEXT PRIMARY KEY REFERENCES api_calls(id) ON DELETE CASCADE,request_headers_json TEXT NOT NULL,request_body BLOB NOT NULL,request_body_truncated INTEGER NOT NULL CHECK(request_body_truncated IN (0,1)),response_headers_json TEXT,response_body BLOB,response_body_truncated INTEGER NOT NULL CHECK(response_body_truncated IN (0,1)),created_at INTEGER NOT NULL)",
        )
        .execute(&state.db)
        .await
        .unwrap();

        wait_for_audits(&state, 1).await;
        let archives: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM request_archives")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(archives, 1);
    }

    #[tokio::test]
    async fn full_audit_queue_does_not_delay_proxy_or_capture_diagnostics() {
        let (upstream, _) = spawn_mock(StatusCode::OK).await;
        let state = crate::test_state_with_upstream("http://token.invalid", &upstream).await;
        seed_proxy(&state, true).await;
        let mut reservations = Vec::new();
        while let Some(reservation) = state.audit.try_reserve() {
            reservations.push(reservation);
        }
        assert!(!reservations.is_empty());

        let dropped_before = crate::audit::dropped_events();
        let identity = ApiIdentity {
            consumer_id: "key-1".to_owned(),
            user_id: "user-1".to_owned(),
            request_archive: true,
            all_providers: false,
        };
        let mut audit = AuditTracker::begin(
            &state,
            &identity,
            "dropped-diagnostic",
            None,
            &Method::POST,
            "/v1/responses",
            "127.0.0.1",
        );
        audit.set_request(&HeaderMap::new(), &vec![0; ARCHIVE_BODY_LIMIT], false);
        assert!(audit.event.is_none());
        drop(audit);

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            crate::router(state.clone()).oneshot(proxy_request(
                "/v1/responses",
                "application/json",
                Body::from(r#"{"model":"gpt-5.4","input":"full queue"}"#),
            )),
        )
        .await
        .expect("full audit queue must not block the proxy")
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(crate::audit::dropped_events() >= dropped_before + 2);
        let calls: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_calls")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(calls, 0);

        drop(reservations);
    }

    #[tokio::test]
    async fn full_archive_budget_preserves_base_audit_without_diagnostics() {
        let (upstream, _) = spawn_mock(StatusCode::OK).await;
        let state = crate::test_state_with_upstream("http://token.invalid", &upstream).await;
        seed_proxy(&state, true).await;
        let mut archive_budgets = Vec::new();
        while let Some(budget) = state.audit.try_reserve_archive() {
            archive_budgets.push(budget);
        }
        assert!(!archive_budgets.is_empty());

        let response = crate::router(state.clone())
            .oneshot(proxy_request(
                "/v1/responses",
                "application/json",
                Body::from(r#"{"model":"gpt-5.4","input":"archive budget"}"#),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        wait_for_audits(&state, 1).await;
        let stored: (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*),COUNT(a.api_call_id) FROM api_calls c LEFT JOIN request_archives a ON a.api_call_id=c.id",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(stored, (1, 0));

        drop(archive_budgets);
    }

    #[tokio::test]
    async fn single_provider_error_is_forwarded_and_failed_calls_are_audited() {
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
            let archived_response: Vec<u8> =
                sqlx::query_scalar("SELECT response_body FROM request_archives")
                    .fetch_one(&state.db)
                    .await
                    .unwrap();
            assert!(
                std::str::from_utf8(&archived_response)
                    .unwrap()
                    .contains("limited")
            );
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
        let archived_response: Vec<u8> =
            sqlx::query_scalar("SELECT response_body FROM request_archives")
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert!(
            std::str::from_utf8(&archived_response)
                .unwrap()
                .contains("no available CodeX provider")
        );
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
        sqlx::query("INSERT INTO providers(id,name,account_id,access_token,refresh_token,expires_at,status,created_at,updated_at) VALUES('provider-1','one','account-1',?,?,?,'active',?,?)")
            .bind("access-old")
            .bind("refresh-old")
            .bind(now - 1).bind(now).bind(now).execute(&state.db).await.unwrap();
        state.balancer.reload_providers(&state.db).await.unwrap();
        let first = state
            .balancer
            .select(&state, "test-user", true, None, None)
            .await
            .unwrap();
        let second = state
            .balancer
            .select(&state, "test-user", true, None, None)
            .await
            .unwrap();
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
            consumer_id: "key-1".to_owned(),
            user_id: "user-1".to_owned(),
            request_archive: true,
            all_providers: false,
        };
        let mut audit = AuditTracker::begin(
            &state,
            &identity,
            "stream-request",
            Some("stream-thread"),
            &Method::POST,
            "/v1/responses",
            "127.0.0.1",
        );
        drop(audit.take_stream(StatusCode::OK, Some("gpt-5.4")));
        wait_for_audits(&state, 1).await;
        let row: (i64, bool) = sqlx::query_as(
            "SELECT c.status,a.response_body_truncated FROM api_calls c JOIN request_archives a ON a.api_call_id=c.id WHERE c.request_id='stream-request'",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(row, (499, true));
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
        let row: (i64, bool) = sqlx::query_as(
            "SELECT c.status,a.response_body_truncated FROM api_calls c JOIN request_archives a ON a.api_call_id=c.id",
        )
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(row, (499, true));
        let pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_calls WHERE status=0")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(pending, 0);
    }
}
