use std::net::SocketAddr;

use axum::{
    Json,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, HeaderValue, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;

use crate::{
    AppError, AppState,
    auth::{bearer, browser_identity, is_admin, require_admin, require_root},
    balancer::Provider,
    crypto::consumer_secret_hash,
    oauth,
};

pub async fn public_config(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let setup_required = setup_required(&state).await?;
    let config = state.config.load();
    Ok(Json(json!({
        "setup_required": setup_required,
        "auth_issuer": (!setup_required).then(|| config.auth_issuer.clone()).flatten()
    })))
}

pub async fn health() -> Json<Value> {
    Json(json!({"status":"ok"}))
}

pub async fn setup_status(State(state): State<AppState>) -> Result<Json<Value>, AppError> {
    let required = setup_required(&state).await?;
    let config = state.config.load();
    Ok(Json(json!({
        "setup_required": required,
        "auth_issuer": (!required).then(|| config.auth_issuer.clone()).flatten()
    })))
}

#[derive(Deserialize)]
pub struct SetupInput {
    auth_issuer: String,
    #[serde(default)]
    auth_audience: Option<String>,
}

pub async fn setup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<SetupInput>,
) -> Result<Json<Value>, AppError> {
    if !setup_required(&state).await? {
        return Err(AppError::not_found("setup is already complete"));
    }
    let issuer = validate_issuer(&input.auth_issuer)?;
    let audience = input.auth_audience.filter(|value| !value.trim().is_empty());
    let identity = state
        .auth
        .verify_candidate(issuer.clone(), audience.clone(), bearer(&headers)?)
        .await?;
    let now = chrono::Utc::now().timestamp();
    let mut transaction = state.db.begin_with("BEGIN IMMEDIATE").await?;
    let complete: String =
        sqlx::query_scalar("SELECT value FROM app_meta WHERE key='setup_complete'")
            .fetch_one(&mut *transaction)
            .await?;
    if complete == "true" {
        return Err(AppError::not_found("setup is already complete"));
    }
    sqlx::query("INSERT INTO users(id,email,display_name,role,created_at) VALUES(?,?,?,'root',?) ON CONFLICT(id) DO UPDATE SET email=excluded.email,display_name=excluded.display_name,role='root'")
        .bind(&identity.id)
        .bind(&identity.email)
        .bind(&identity.name)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
    for (key, value) in [
        ("auth_issuer", issuer.as_str()),
        ("auth_audience", audience.as_deref().unwrap_or("")),
        ("setup_complete", "true"),
    ] {
        sqlx::query("UPDATE app_meta SET value=?,updated_at=? WHERE key=?")
            .bind(value)
            .bind(now)
            .bind(key)
            .execute(&mut *transaction)
            .await?;
    }
    transaction.commit().await?;
    state.auth.configure(issuer.clone(), audience.clone()).await;
    let mut config = (**state.config.load()).clone();
    config.setup_complete = true;
    config.auth_issuer = Some(issuer);
    config.auth_audience = audience;
    state.config.store(std::sync::Arc::new(config));
    Ok(Json(json!({"ok":true,"root_user_id":identity.id})))
}

async fn setup_required(state: &AppState) -> Result<bool, AppError> {
    let value: String = sqlx::query_scalar("SELECT value FROM app_meta WHERE key='setup_complete'")
        .fetch_one(&state.db)
        .await?;
    Ok(value != "true")
}

fn validate_issuer(value: &str) -> Result<String, AppError> {
    let issuer = value.trim().trim_end_matches('/');
    let parsed = url::Url::parse(issuer)
        .map_err(|_| AppError::bad_request("Auth Mini issuer must be an absolute URL"))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(AppError::bad_request("Auth Mini issuer URL is not valid"));
    }
    if parsed.scheme() == "http"
        && !matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "::1"))
    {
        return Err(AppError::bad_request(
            "Auth Mini issuer must use HTTPS outside localhost",
        ));
    }
    Ok(issuer.to_owned())
}

pub async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    Ok(Json(serde_json::to_value(
        browser_identity(&state, &headers).await?,
    )?))
}

#[derive(Deserialize)]
pub struct CreateConsumer {
    name: String,
}

pub async fn list_consumers(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let user = browser_identity(&state, &headers).await?;
    let rows = sqlx::query("SELECT id,name,prefix,created_at,last_used_at,revoked_at FROM consumers WHERE user_id=? ORDER BY created_at DESC")
        .bind(&user.id).fetch_all(&state.db).await?;
    Ok(Json(Value::Array(rows.into_iter().map(|row| json!({
        "id": row.get::<String,_>(0), "name": row.get::<String,_>(1), "prefix": row.get::<String,_>(2),
        "created_at": row.get::<i64,_>(3), "last_used_at": row.get::<Option<i64>,_>(4), "revoked_at": row.get::<Option<i64>,_>(5)
    })).collect())))
}

pub async fn create_consumer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateConsumer>,
) -> Result<Json<Value>, AppError> {
    let user = browser_identity(&state, &headers).await?;
    let name = input.name.trim();
    if name.is_empty() || name.len() > 80 {
        return Err(AppError::bad_request("key name must be 1-80 characters"));
    }
    let mut random = [0_u8; 32];
    rand::rng().fill_bytes(&mut random);
    let secret = format!("sk-{}", URL_SAFE_NO_PAD.encode(random));
    let prefix = secret.chars().take(11).collect::<String>();
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO consumers(id,user_id,name,prefix,secret_hash,created_at) VALUES(?,?,?,?,?,?)",
    )
    .bind(&id)
    .bind(&user.id)
    .bind(name)
    .bind(&prefix)
    .bind(consumer_secret_hash(&secret))
    .bind(chrono::Utc::now().timestamp())
    .execute(&state.db)
    .await?;
    Ok(Json(
        json!({"id":id,"name":name,"prefix":prefix,"secret":secret}),
    ))
}

pub async fn revoke_consumer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let user = browser_identity(&state, &headers).await?;
    let result = sqlx::query(
        "UPDATE consumers SET revoked_at=? WHERE id=? AND user_id=? AND revoked_at IS NULL",
    )
    .bind(chrono::Utc::now().timestamp())
    .bind(id)
    .bind(user.id)
    .execute(&state.db)
    .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::not_found("consumer not found"));
    }
    Ok(Json(json!({"ok":true})))
}

#[derive(Deserialize)]
pub struct CreateProvider {
    name: String,
    access_key: String,
    refresh_key: String,
}

pub async fn list_providers(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let user = browser_identity(&state, &headers).await?;
    require_admin(&user)?;
    let providers =
        sqlx::query_as::<_, Provider>("SELECT * FROM providers ORDER BY created_at DESC")
            .fetch_all(&state.db)
            .await?;
    Ok(Json(Value::Array(
        providers
            .into_iter()
            .map(|provider| {
                let inflight = state.balancer.inflight(&provider.id);
                let mut value = serde_json::to_value(provider).expect("provider serializes");
                value["inflight"] = json!(inflight);
                value
            })
            .collect(),
    )))
}

pub async fn create_provider(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<CreateProvider>,
) -> Result<Json<Value>, AppError> {
    let user = browser_identity(&state, &headers).await?;
    require_admin(&user)?;
    let result = insert_provider(
        &state,
        &input.name,
        &input.access_key,
        &input.refresh_key,
        None,
    )
    .await;
    let action = if result.is_ok() {
        "provider.create"
    } else {
        "provider.create.failed"
    };
    write_admin_audit(
        &state,
        &user.id,
        action,
        result
            .as_ref()
            .ok()
            .and_then(|value| value.0.get("id"))
            .and_then(Value::as_str),
        &peer.ip().to_string(),
    )
    .await?;
    result
}

async fn insert_provider(
    state: &AppState,
    name: &str,
    access: &str,
    refresh: &str,
    expires_at: Option<i64>,
) -> Result<Json<Value>, AppError> {
    if name.trim().is_empty() || access.trim().is_empty() || refresh.trim().is_empty() {
        return Err(AppError::bad_request(
            "name, access_key and refresh_key are required",
        ));
    }
    let account_id = oauth::account_id_from_jwt(access)?;
    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().timestamp();
    let expires_at = expires_at.or_else(|| oauth::expires_at_from_jwt(access));
    sqlx::query("INSERT INTO providers(id,name,account_id,access_token,refresh_token,expires_at,status,created_at,updated_at) VALUES(?,?,?,?,?,?,'active',?,?)")
        .bind(&id).bind(name.trim()).bind(&account_id).bind(access.trim())
        .bind(refresh.trim()).bind(expires_at).bind(now).bind(now).execute(&state.db).await?;
    state.balancer.reload_providers(&state.db).await?;
    Ok(Json(
        json!({"id":id,"name":name.trim(),"account_id":account_id,"status":"active"}),
    ))
}

#[derive(Deserialize)]
pub struct ProviderUpdate {
    name: Option<String>,
    enabled: Option<bool>,
    refresh: Option<bool>,
}

pub async fn update_provider(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<ProviderUpdate>,
) -> Result<Json<Value>, AppError> {
    let user = browser_identity(&state, &headers).await?;
    require_admin(&user)?;
    let operation: Result<Json<Value>, AppError> = async {
        if let Some(name) = input.name.filter(|name| !name.trim().is_empty()) {
            sqlx::query("UPDATE providers SET name=?,updated_at=? WHERE id=?")
                .bind(name.trim())
                .bind(chrono::Utc::now().timestamp())
                .bind(&id)
                .execute(&state.db)
                .await?;
        }
        if let Some(enabled) = input.enabled {
            let (disabled, status) = if enabled { (0, "active") } else { (1, "disabled") };
            sqlx::query("UPDATE providers SET manual_disabled=?,status=?,cooldown_until=NULL,updated_at=? WHERE id=?")
                .bind(disabled).bind(status).bind(chrono::Utc::now().timestamp()).bind(&id).execute(&state.db).await?;
        }
        if input.refresh.unwrap_or(false) {
            refresh_provider(&state, &id).await?;
        }
        state.balancer.reload_providers(&state.db).await?;
        Ok(Json(json!({"ok":true})))
    }.await;
    let action = if operation.is_ok() {
        "provider.update"
    } else {
        "provider.update.failed"
    };
    write_admin_audit(&state, &user.id, action, Some(&id), &peer.ip().to_string()).await?;
    operation
}

async fn refresh_provider(state: &AppState, id: &str) -> Result<(), AppError> {
    let lock = state
        .refresh_locks
        .entry(id.to_owned())
        .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;
    let row = sqlx::query("SELECT refresh_token,account_id FROM providers WHERE id=?")
        .bind(id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::not_found("provider not found"))?;
    let refresh: String = row.get(0);
    let token = oauth::refresh(state, &refresh).await?;
    let account_id =
        oauth::account_id_from_jwt(&token.access_token).unwrap_or_else(|_| row.get::<String, _>(1));
    let now = chrono::Utc::now().timestamp();
    let updated = sqlx::query("UPDATE providers SET access_token=?,refresh_token=?,account_id=?,expires_at=?,status=CASE WHEN manual_disabled=1 THEN 'disabled' ELSE 'active' END,cooldown_until=NULL,last_error=NULL,updated_at=? WHERE id=? AND refresh_token=?")
        .bind(&token.access_token)
        .bind(&token.refresh_token)
        .bind(account_id).bind(now + token.expires_in).bind(now).bind(id).bind(refresh).execute(&state.db).await?;
    if updated.rows_affected() == 0 {
        return Err(AppError::unavailable(
            "provider credential changed during refresh",
        ));
    }
    state.balancer.reload_providers(&state.db).await?;
    Ok(())
}

pub async fn read_provider_tokens(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<(HeaderMap, Json<Value>), AppError> {
    let user = browser_identity(&state, &headers).await?;
    require_admin(&user)?;
    let result: Result<(HeaderMap, Json<Value>), AppError> = async {
        let row: (String, String) =
            sqlx::query_as("SELECT access_token,refresh_token FROM providers WHERE id=?")
                .bind(&id)
                .fetch_optional(&state.db)
                .await?
                .ok_or_else(|| AppError::not_found("provider not found"))?;
        let mut response_headers = HeaderMap::new();
        response_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        Ok((
            response_headers,
            Json(json!({"access_key":row.0,"refresh_key":row.1})),
        ))
    }
    .await;
    let action = if result.is_ok() {
        "provider.tokens.read"
    } else {
        "provider.tokens.read.failed"
    };
    write_admin_audit(&state, &user.id, action, Some(&id), &peer.ip().to_string()).await?;
    result
}

#[derive(Deserialize)]
pub struct ReplaceProviderTokens {
    name: String,
    access_key: String,
    refresh_key: String,
}

pub async fn replace_provider_tokens(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<ReplaceProviderTokens>,
) -> Result<Json<Value>, AppError> {
    let user = browser_identity(&state, &headers).await?;
    require_admin(&user)?;
    let result = replace_provider_token_values(
        &state,
        &id,
        input.name.trim(),
        input.access_key.trim(),
        input.refresh_key.trim(),
    )
    .await;
    let action = if result.is_ok() {
        "provider.tokens.update"
    } else {
        "provider.tokens.update.failed"
    };
    write_admin_audit(&state, &user.id, action, Some(&id), &peer.ip().to_string()).await?;
    result
}

async fn replace_provider_token_values(
    state: &AppState,
    id: &str,
    name: &str,
    access_token: &str,
    refresh_token: &str,
) -> Result<Json<Value>, AppError> {
    if name.is_empty() || access_token.is_empty() || refresh_token.is_empty() {
        return Err(AppError::bad_request(
            "name, access_key and refresh_key are required",
        ));
    }
    let account_id = oauth::account_id_from_jwt(access_token)?;
    let expires_at = oauth::expires_at_from_jwt(access_token);
    let updated = sqlx::query("UPDATE providers SET name=?,access_token=?,refresh_token=?,account_id=?,expires_at=?,status=CASE WHEN manual_disabled=1 THEN 'disabled' ELSE 'active' END,cooldown_until=NULL,last_error=NULL,updated_at=? WHERE id=?")
        .bind(name).bind(access_token).bind(refresh_token).bind(&account_id).bind(expires_at)
        .bind(chrono::Utc::now().timestamp()).bind(id).execute(&state.db).await?;
    if updated.rows_affected() == 0 {
        return Err(AppError::not_found("provider not found"));
    }
    state.balancer.reload_providers(&state.db).await?;
    Ok(Json(json!({"ok":true,"name":name,"account_id":account_id})))
}

pub async fn list_provider_usage(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let user = browser_identity(&state, &headers).await?;
    require_admin(&user)?;
    let ids = sqlx::query_scalar::<_, String>("SELECT id FROM providers ORDER BY created_at DESC")
        .fetch_all(&state.db)
        .await?;
    let mut providers = serde_json::Map::new();
    for id in ids {
        let value = match provider_usage_value(&state, &id).await {
            Ok(usage) => json!({"usage": usage}),
            Err(error) => json!({"error": error.message()}),
        };
        providers.insert(id, value);
    }
    Ok(Json(json!({"providers": providers})))
}

pub async fn test_provider(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let user = browser_identity(&state, &headers).await?;
    require_admin(&user)?;
    let result = provider_usage(&state, &id).await;
    let action = if result.is_ok() {
        "provider.test"
    } else {
        "provider.test.failed"
    };
    write_admin_audit(&state, &user.id, action, Some(&id), &peer.ip().to_string()).await?;
    result
}

async fn provider_usage(state: &AppState, id: &str) -> Result<Json<Value>, AppError> {
    Ok(Json(
        json!({"ok":true,"usage":provider_usage_value(state, id).await?}),
    ))
}

async fn provider_usage_value(state: &AppState, id: &str) -> Result<Value, AppError> {
    let row: (String, String) =
        sqlx::query_as("SELECT access_token,account_id FROM providers WHERE id=?")
            .bind(id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| AppError::not_found("provider not found"))?;
    let mut usage_url = url::Url::parse(&state.config.load().upstream_base)?;
    usage_url.set_path("/backend-api/wham/usage");
    usage_url.set_query(None);
    let response = state
        .client
        .get(usage_url)
        .bearer_auth(row.0)
        .header("chatgpt-account-id", row.1)
        .send()
        .await
        .map_err(|_| AppError::upstream(502, "provider Usage API request failed"))?;
    if !response.status().is_success() {
        return Err(AppError::upstream(
            502,
            format!("provider Usage API returned {}", response.status()),
        ));
    }
    let usage = response
        .json::<Value>()
        .await
        .map_err(|_| AppError::upstream(502, "provider Usage API returned invalid JSON"))?;
    Ok(usage)
}

pub async fn delete_provider(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let user = browser_identity(&state, &headers).await?;
    require_admin(&user)?;
    let result: Result<Json<Value>, AppError> = async {
        let deleted = sqlx::query("DELETE FROM providers WHERE id=?")
            .bind(&id)
            .execute(&state.db)
            .await?;
        if deleted.rows_affected() == 0 {
            return Err(AppError::not_found("provider not found"));
        }
        state.balancer.forget_provider(&id);
        state.balancer.reload_providers(&state.db).await?;
        Ok(Json(json!({"ok":true})))
    }
    .await;
    let action = if result.is_ok() {
        "provider.delete"
    } else {
        "provider.delete.failed"
    };
    write_admin_audit(&state, &user.id, action, Some(&id), &peer.ip().to_string()).await?;
    result
}

pub async fn oauth_start(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let user = browser_identity(&state, &headers).await?;
    require_admin(&user)?;
    let result: Result<Json<Value>, AppError> = async {
        Ok(Json(serde_json::to_value(
            oauth::start(&state, &user.id).await?,
        )?))
    }
    .await;
    let action = if result.is_ok() {
        "oauth.start"
    } else {
        "oauth.start.failed"
    };
    write_admin_audit(&state, &user.id, action, None, &peer.ip().to_string()).await?;
    result
}

#[derive(Deserialize)]
pub struct OAuthComplete {
    state: String,
    code: String,
    name: String,
}

pub async fn oauth_complete(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<OAuthComplete>,
) -> Result<Json<Value>, AppError> {
    let user = browser_identity(&state, &headers).await?;
    require_admin(&user)?;
    let result: Result<Json<Value>, AppError> = async {
        let token = oauth::exchange(&state, &input.state, &input.code, &user.id).await?;
        insert_provider(
            &state,
            &input.name,
            &token.access_token,
            &token.refresh_token,
            Some(chrono::Utc::now().timestamp() + token.expires_in),
        )
        .await
    }
    .await;
    let action = if result.is_ok() {
        "oauth.complete"
    } else {
        "oauth.complete.failed"
    };
    write_admin_audit(
        &state,
        &user.id,
        action,
        result
            .as_ref()
            .ok()
            .and_then(|value| value.0.get("id"))
            .and_then(Value::as_str),
        &peer.ip().to_string(),
    )
    .await?;
    result
}

#[derive(Deserialize)]
pub struct Page {
    limit: Option<i64>,
    offset: Option<i64>,
}

pub async fn usage(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let user = browser_identity(&state, &headers).await?;
    let rows = sqlx::query("SELECT k.id,k.name,k.prefix,COUNT(c.id),COALESCE(SUM(c.input_tokens),0),COALESCE(SUM(c.output_tokens),0),COALESCE(SUM(c.cached_tokens),0),COALESCE(SUM(CASE WHEN c.status>=400 THEN 1 ELSE 0 END),0),COALESCE(AVG(c.latency_ms),0) FROM consumers k LEFT JOIN api_calls c ON c.consumer_id=k.id WHERE k.user_id=? GROUP BY k.id ORDER BY k.created_at DESC")
        .bind(&user.id).fetch_all(&state.db).await?;
    Ok(Json(Value::Array(rows.into_iter().map(|row| json!({
        "consumer_id":row.get::<String,_>(0),"name":row.get::<String,_>(1),"prefix":row.get::<String,_>(2),"requests":row.get::<i64,_>(3),
        "input_tokens":row.get::<i64,_>(4),"output_tokens":row.get::<i64,_>(5),"cached_tokens":row.get::<i64,_>(6),"errors":row.get::<i64,_>(7),"avg_latency_ms":row.get::<f64,_>(8)
    })).collect())))
}

pub async fn audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(page): Query<Page>,
) -> Result<Json<Value>, AppError> {
    let user = browser_identity(&state, &headers).await?;
    let limit = page.limit.unwrap_or(100).clamp(1, 500);
    let offset = page.offset.unwrap_or(0).max(0);
    let (sql, scope) = if is_admin(&user) {
        (
            "SELECT c.id,c.request_id,c.user_id,k.prefix,c.provider_id,ch.name,c.path,c.method,c.model,c.status,c.latency_ms,c.input_tokens,c.output_tokens,c.cached_tokens,c.error,c.client_ip,c.created_at FROM api_calls c JOIN consumers k ON k.id=c.consumer_id LEFT JOIN providers ch ON ch.id=c.provider_id ORDER BY c.created_at DESC LIMIT ? OFFSET ?",
            None,
        )
    } else {
        (
            "SELECT c.id,c.request_id,c.user_id,k.prefix,c.provider_id,ch.name,c.path,c.method,c.model,c.status,c.latency_ms,c.input_tokens,c.output_tokens,c.cached_tokens,c.error,c.client_ip,c.created_at FROM api_calls c JOIN consumers k ON k.id=c.consumer_id LEFT JOIN providers ch ON ch.id=c.provider_id WHERE c.user_id=? ORDER BY c.created_at DESC LIMIT ? OFFSET ?",
            Some(user.id),
        )
    };
    let mut query = sqlx::query(sql);
    if let Some(scope) = scope {
        query = query.bind(scope);
    }
    let rows = query.bind(limit).bind(offset).fetch_all(&state.db).await?;
    Ok(Json(Value::Array(rows.into_iter().map(|row| json!({
        "id":row.get::<String,_>(0),"request_id":row.get::<String,_>(1),"user_id":row.get::<String,_>(2),"consumer_prefix":row.get::<String,_>(3),"provider_id":row.get::<Option<String>,_>(4),"provider_name":row.get::<Option<String>,_>(5),
        "path":row.get::<String,_>(6),"method":row.get::<String,_>(7),"model":row.get::<Option<String>,_>(8),"status":row.get::<i64,_>(9),"latency_ms":row.get::<i64,_>(10),
        "input_tokens":row.get::<i64,_>(11),"output_tokens":row.get::<i64,_>(12),"cached_tokens":row.get::<i64,_>(13),"error":row.get::<Option<String>,_>(14),"client_ip":row.get::<Option<String>,_>(15),"created_at":row.get::<i64,_>(16)
    })).collect())))
}

pub async fn audit_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let user = browser_identity(&state, &headers).await?;
    let (sql, scope) = if is_admin(&user) {
        (
            "SELECT c.id,c.request_id,c.user_id,k.prefix,c.provider_id,ch.name,c.method,c.path,c.model,c.status,c.latency_ms,c.input_tokens,c.output_tokens,c.cached_tokens,c.error,c.client_ip,c.affinity_hash,c.affinity_source,c.created_at,a.api_call_id,a.request_headers_json,a.request_body,a.request_body_truncated,a.response_headers_json,a.response_body,a.response_body_truncated FROM api_calls c JOIN consumers k ON k.id=c.consumer_id LEFT JOIN providers ch ON ch.id=c.provider_id LEFT JOIN request_archives a ON a.api_call_id=c.id WHERE c.id=?",
            None,
        )
    } else {
        (
            "SELECT c.id,c.request_id,c.user_id,k.prefix,c.provider_id,ch.name,c.method,c.path,c.model,c.status,c.latency_ms,c.input_tokens,c.output_tokens,c.cached_tokens,c.error,c.client_ip,c.affinity_hash,c.affinity_source,c.created_at,a.api_call_id,a.request_headers_json,a.request_body,a.request_body_truncated,a.response_headers_json,a.response_body,a.response_body_truncated FROM api_calls c JOIN consumers k ON k.id=c.consumer_id LEFT JOIN providers ch ON ch.id=c.provider_id LEFT JOIN request_archives a ON a.api_call_id=c.id WHERE c.id=? AND c.user_id=?",
            Some(user.id.clone()),
        )
    };
    let mut query = sqlx::query(sql).bind(&id);
    if let Some(scope) = scope {
        query = query.bind(scope);
    }
    let row = query
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::not_found("audit event not found"))?;
    let affinity_hash = row.get::<Option<String>, _>(16);
    let navigation_rows = if let Some(affinity_hash) = &affinity_hash {
        let (sql, scope) = if is_admin(&user) {
            (
                "SELECT id,request_id,created_at FROM api_calls WHERE affinity_hash=? ORDER BY created_at,id",
                None,
            )
        } else {
            (
                "SELECT id,request_id,created_at FROM api_calls WHERE affinity_hash=? AND user_id=? ORDER BY created_at,id",
                Some(user.id.clone()),
            )
        };
        let mut query = sqlx::query(sql).bind(affinity_hash);
        if let Some(scope) = scope {
            query = query.bind(scope);
        }
        query.fetch_all(&state.db).await?
    } else {
        Vec::new()
    };
    let position = navigation_rows
        .iter()
        .position(|item| item.get::<String, _>(0) == id);
    let navigation = |item: Option<&sqlx::sqlite::SqliteRow>| {
        item.map(|item| {
            json!({
                "id":item.get::<String,_>(0),
                "request_id":item.get::<String,_>(1),
                "created_at":item.get::<i64,_>(2)
            })
        })
    };
    let previous = position
        .and_then(|index| index.checked_sub(1))
        .and_then(|index| navigation_rows.get(index));
    let next = position.and_then(|index| navigation_rows.get(index + 1));
    Ok(Json(json!({
        "id":row.get::<String,_>(0),"request_id":row.get::<String,_>(1),"user_id":row.get::<String,_>(2),"consumer_prefix":row.get::<String,_>(3),
        "provider_id":row.get::<Option<String>,_>(4),"provider_name":row.get::<Option<String>,_>(5),"method":row.get::<String,_>(6),"path":row.get::<String,_>(7),
        "model":row.get::<Option<String>,_>(8),"status":row.get::<i64,_>(9),"latency_ms":row.get::<i64,_>(10),"input_tokens":row.get::<i64,_>(11),
        "output_tokens":row.get::<i64,_>(12),"cached_tokens":row.get::<i64,_>(13),"error":row.get::<Option<String>,_>(14),"client_ip":row.get::<Option<String>,_>(15),
        "affinity_hash":affinity_hash,"affinity_source":row.get::<Option<String>,_>(17),"created_at":row.get::<i64,_>(18),
        "archive_available":row.get::<Option<String>,_>(19).is_some(),"request_headers":row.get::<Option<String>,_>(20),
        "request_body":row.get::<Option<Vec<u8>>,_>(21).map(|body| String::from_utf8_lossy(&body).into_owned()),"request_body_truncated":row.get::<Option<i64>,_>(22).unwrap_or_default() != 0,
        "response_headers":row.get::<Option<String>,_>(23),"response_body":row.get::<Option<Vec<u8>>,_>(24).map(|body| String::from_utf8_lossy(&body).into_owned()),
        "response_body_truncated":row.get::<Option<i64>,_>(25).unwrap_or_default() != 0,
        "previous":navigation(previous),"next":navigation(next)
    })))
}

pub async fn list_admin_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(page): Query<Page>,
) -> Result<Json<Value>, AppError> {
    let user = browser_identity(&state, &headers).await?;
    require_admin(&user)?;
    let rows = sqlx::query("SELECT a.id,a.admin_user_id,u.email,a.action,a.target_id,a.client_ip,a.created_at FROM admin_audit a JOIN users u ON u.id=a.admin_user_id ORDER BY a.created_at DESC LIMIT ? OFFSET ?")
        .bind(page.limit.unwrap_or(100).clamp(1, 500))
        .bind(page.offset.unwrap_or(0).max(0))
        .fetch_all(&state.db).await?;
    Ok(Json(Value::Array(
        rows.into_iter()
            .map(|row| {
                json!({
                    "id":row.get::<String,_>(0),
                    "admin_user_id":row.get::<String,_>(1),
                    "admin_email":row.get::<Option<String>,_>(2),
                    "action":row.get::<String,_>(3),
                    "target_id":row.get::<Option<String>,_>(4),
                    "client_ip":row.get::<Option<String>,_>(5),
                    "created_at":row.get::<i64,_>(6)
                })
            })
            .collect(),
    )))
}

pub async fn dashboard(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let user = browser_identity(&state, &headers).await?;
    let consumers: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM consumers WHERE user_id=? AND revoked_at IS NULL")
            .bind(&user.id)
            .fetch_one(&state.db)
            .await?;
    let calls: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM api_calls WHERE user_id=? AND created_at>?")
            .bind(&user.id)
            .bind(chrono::Utc::now().timestamp() - 86400)
            .fetch_one(&state.db)
            .await?;
    let errors: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM api_calls WHERE user_id=? AND status>=400 AND created_at>?",
    )
    .bind(&user.id)
    .bind(chrono::Utc::now().timestamp() - 86400)
    .fetch_one(&state.db)
    .await?;
    let providers: i64 = if is_admin(&user) {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM providers WHERE manual_disabled=0 AND status='active'",
        )
        .fetch_one(&state.db)
        .await?
    } else {
        0
    };
    Ok(Json(
        json!({"active_consumers":consumers,"calls_24h":calls,"errors_24h":errors,"available_providers":providers}),
    ))
}

pub async fn settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let user = browser_identity(&state, &headers).await?;
    let config = state.config.load();
    Ok(Json(json!({
        "role":user.role,
        "auth_issuer":config.auth_issuer,
        "upstream_base":config.upstream_base,
        "image_host_model":config.image_host_model,
        "oauth_authorize_url":config.oauth_authorize_url,
        "oauth_token_url":config.oauth_token_url,
        "oauth_redirect_uri":config.oauth_redirect_uri,
        "oauth_client_id":config.oauth_client_id,
        "response_body_limit":config.response_body_limit,
        "image_body_limit":config.image_body_limit,
        "audio_body_limit":config.audio_body_limit,
        "affinity_ttl_seconds":config.affinity_ttl_seconds,
        "request_archive_retention_days":config.request_archive_retention_days
    })))
}

#[derive(Deserialize)]
pub struct UpdateSettings {
    upstream_base: String,
    image_host_model: String,
    oauth_authorize_url: String,
    oauth_token_url: String,
    oauth_redirect_uri: String,
    oauth_client_id: String,
    response_body_limit: usize,
    image_body_limit: usize,
    audio_body_limit: usize,
    affinity_ttl_seconds: i64,
    request_archive_retention_days: i64,
}

pub async fn update_settings(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<UpdateSettings>,
) -> Result<Json<Value>, AppError> {
    let root = browser_identity(&state, &headers).await?;
    require_root(&root)?;
    let upstream_base = validate_http_url("upstream base", &input.upstream_base)?;
    let oauth_authorize_url = validate_http_url("OAuth authorize URL", &input.oauth_authorize_url)?;
    let oauth_token_url = validate_http_url("OAuth token URL", &input.oauth_token_url)?;
    let oauth_redirect_uri = validate_http_url("OAuth redirect URI", &input.oauth_redirect_uri)?;
    let image_host_model = required_setting("image host model", &input.image_host_model)?;
    let oauth_client_id = required_setting("OAuth client ID", &input.oauth_client_id)?;
    if !(1_024..=16 * 1_024 * 1_024).contains(&input.response_body_limit)
        || !(1_024..=16 * 1_024 * 1_024).contains(&input.image_body_limit)
        || !(1_024 * 1_024..=2_000_000_000).contains(&input.audio_body_limit)
        || !(60..=2_592_000).contains(&input.affinity_ttl_seconds)
        || !(1..=365).contains(&input.request_archive_retention_days)
    {
        return Err(AppError::bad_request(
            "one or more numeric settings are outside the allowed range",
        ));
    }
    let values = [
        ("upstream_base", upstream_base.clone()),
        ("image_host_model", image_host_model.clone()),
        ("oauth_authorize_url", oauth_authorize_url.clone()),
        ("oauth_token_url", oauth_token_url.clone()),
        ("oauth_redirect_uri", oauth_redirect_uri.clone()),
        ("oauth_client_id", oauth_client_id.clone()),
        ("response_body_limit", input.response_body_limit.to_string()),
        ("image_body_limit", input.image_body_limit.to_string()),
        ("audio_body_limit", input.audio_body_limit.to_string()),
        (
            "affinity_ttl_seconds",
            input.affinity_ttl_seconds.to_string(),
        ),
        (
            "request_archive_retention_days",
            input.request_archive_retention_days.to_string(),
        ),
    ];
    let now = chrono::Utc::now().timestamp();
    let mut transaction = state.db.begin().await?;
    for (key, value) in values {
        sqlx::query("UPDATE app_meta SET value=?,updated_at=? WHERE key=?")
            .bind(value)
            .bind(now)
            .bind(key)
            .execute(&mut *transaction)
            .await?;
    }
    transaction.commit().await?;
    let mut config = (**state.config.load()).clone();
    config.upstream_base = upstream_base;
    config.image_host_model = image_host_model;
    config.oauth_authorize_url = oauth_authorize_url;
    config.oauth_token_url = oauth_token_url;
    config.oauth_redirect_uri = oauth_redirect_uri;
    config.oauth_client_id = oauth_client_id;
    config.response_body_limit = input.response_body_limit;
    config.image_body_limit = input.image_body_limit;
    config.audio_body_limit = input.audio_body_limit;
    config.affinity_ttl_seconds = input.affinity_ttl_seconds;
    config.request_archive_retention_days = input.request_archive_retention_days;
    state.config.store(std::sync::Arc::new(config));
    write_admin_audit(
        &state,
        &root.id,
        "settings.update",
        None,
        &peer.ip().to_string(),
    )
    .await?;
    Ok(Json(json!({"ok":true})))
}

fn validate_http_url(name: &str, value: &str) -> Result<String, AppError> {
    let normalized = value.trim().trim_end_matches('/');
    let parsed = url::Url::parse(normalized)
        .map_err(|_| AppError::bad_request(format!("{name} must be an absolute URL")))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(AppError::bad_request(format!(
            "{name} must use HTTP or HTTPS"
        )));
    }
    Ok(normalized.to_owned())
}

fn required_setting(name: &str, value: &str) -> Result<String, AppError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 200 {
        return Err(AppError::bad_request(format!(
            "{name} must be 1-200 characters"
        )));
    }
    Ok(value.to_owned())
}

pub async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let root = browser_identity(&state, &headers).await?;
    require_admin(&root)?;
    let rows = sqlx::query(
        "SELECT id,email,display_name,role,provider_access,created_at FROM users ORDER BY created_at,id",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(Value::Array(
        rows.into_iter()
            .map(|row| {
                json!({
                    "id":row.get::<String,_>(0),
                    "email":row.get::<Option<String>,_>(1),
                    "display_name":row.get::<Option<String>,_>(2),
                    "role":row.get::<String,_>(3),
                    "provider_access":row.get::<i64,_>(4) != 0,
                    "created_at":row.get::<i64,_>(5)
                })
            })
            .collect(),
    )))
}

#[derive(Deserialize)]
pub struct UpdateUser {
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    provider_access: Option<bool>,
}

pub async fn update_user(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<UpdateUser>,
) -> Result<Json<Value>, AppError> {
    let admin = browser_identity(&state, &headers).await?;
    require_admin(&admin)?;
    if input.role.is_none() && input.provider_access.is_none() {
        return Err(AppError::bad_request("role or provider_access is required"));
    }
    if let Some(role) = input.role {
        require_root(&admin)?;
        if !matches!(role.as_str(), "admin" | "user") {
            return Err(AppError::bad_request("role must be admin or user"));
        }
        let result = sqlx::query("UPDATE users SET role=? WHERE id=? AND role<>'root'")
            .bind(role)
            .bind(&id)
            .execute(&state.db)
            .await?;
        if result.rows_affected() == 0 {
            return Err(AppError::not_found(
                "user not found or root role is immutable",
            ));
        }
        write_admin_audit(
            &state,
            &admin.id,
            "user.role.update",
            Some(&id),
            &peer.ip().to_string(),
        )
        .await?;
    }
    if let Some(provider_access) = input.provider_access {
        let result = sqlx::query("UPDATE users SET provider_access=? WHERE id=? AND role='user'")
            .bind(provider_access)
            .bind(&id)
            .execute(&state.db)
            .await?;
        if result.rows_affected() == 0 {
            return Err(AppError::bad_request(
                "provider access only applies to tenant users",
            ));
        }
        write_admin_audit(
            &state,
            &admin.id,
            "user.provider_access.update",
            Some(&id),
            &peer.ip().to_string(),
        )
        .await?;
    }
    Ok(Json(json!({"ok":true})))
}

async fn write_admin_audit(
    state: &AppState,
    admin_user_id: &str,
    action: &str,
    target_id: Option<&str>,
    client_ip: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO admin_audit(id,admin_user_id,action,target_id,client_ip,created_at) VALUES(?,?,?,?,?,?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(admin_user_id)
    .bind(action)
    .bind(target_id)
    .bind(client_ip)
    .bind(chrono::Utc::now().timestamp())
    .execute(&state.db)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::{
        Router,
        body::Body,
        http::{Method, Request, StatusCode},
        response::{IntoResponse, Response},
        routing::get,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;

    fn setup_token(signing: &SigningKey, issuer: &str, user_id: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","kid":"setup","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "sub":user_id,
                "iss":issuer,
                "typ":"access",
                "exp":chrono::Utc::now().timestamp() + 300,
                "email":"root@example.com"
            }))
            .unwrap(),
        );
        let input = format!("{header}.{payload}");
        format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(signing.sign(input.as_bytes()).to_bytes())
        )
    }

    fn provider_access_token(account_id: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "https://api.openai.com/auth": {"chatgpt_account_id":account_id},
                "exp":chrono::Utc::now().timestamp() + 3600
            }))
            .unwrap(),
        );
        format!("{header}.{payload}.signature")
    }

    async fn provider_request(
        state: &AppState,
        method: Method,
        path: &str,
        token: &str,
        body: Option<Value>,
    ) -> Response {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .extension(ConnectInfo("127.0.0.1:9000".parse::<SocketAddr>().unwrap()));
        let body = match body {
            Some(value) => {
                builder = builder.header(header::CONTENT_TYPE, "application/json");
                Body::from(value.to_string())
            }
            None => Body::empty(),
        };
        crate::router(state.clone())
            .oneshot(builder.body(body).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn setup_atomically_binds_root_and_closes() {
        let signing = SigningKey::from_bytes(&[23_u8; 32]);
        let x = URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes());
        let jwks = Router::new().route("/jwks", get(move || {
            let x = x.clone();
            async move { Json(json!({"keys":[{"kid":"setup","kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","x":x}]})) }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, jwks).await.unwrap() });
        let issuer = format!("http://{address}");
        let token = setup_token(&signing, &issuer, "root-user");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        let state = crate::test_state("http://token.invalid").await;
        let response = setup(
            State(state.clone()),
            headers.clone(),
            Json(SetupInput {
                auth_issuer: issuer.clone(),
                auth_audience: None,
            }),
        )
        .await
        .unwrap();
        assert_eq!(response.0["root_user_id"], "root-user");
        let role: String = sqlx::query_scalar("SELECT role FROM users WHERE id='root-user'")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(role, "root");
        assert!(state.config.load().setup_complete);
        let second = setup(
            State(state),
            headers,
            Json(SetupInput {
                auth_issuer: issuer,
                auth_audience: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(second.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn tenant_audit_scope_cannot_read_another_user() {
        let state = crate::test_state("http://token.invalid").await;
        let now = chrono::Utc::now().timestamp();
        for user in ["tenant-a", "tenant-b"] {
            sqlx::query("INSERT INTO users(id,role,created_at) VALUES(?,'user',?)")
                .bind(user)
                .bind(now)
                .execute(&state.db)
                .await
                .unwrap();
            sqlx::query("INSERT INTO consumers(id,user_id,name,prefix,secret_hash,created_at) VALUES(?,?,?,? ,?,?)")
                .bind(format!("key-{user}")).bind(user).bind(user).bind(user)
                .bind(format!("hash-{user}")).bind(now).execute(&state.db).await.unwrap();
            sqlx::query("INSERT INTO api_calls(id,request_id,consumer_id,user_id,method,path,status,latency_ms,created_at) VALUES(?,?,?,?, 'POST','/v1/responses',200,1,?)")
                .bind(format!("call-{user}")).bind("shared-client-request-id").bind(format!("key-{user}"))
                .bind(user).bind(now).execute(&state.db).await.unwrap();
        }
        let visible: Vec<String> = sqlx::query_scalar("SELECT id FROM api_calls WHERE user_id=?")
            .bind("tenant-a")
            .fetch_all(&state.db)
            .await
            .unwrap();
        assert_eq!(visible, vec!["call-tenant-a"]);
        let duplicated_request_ids: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM api_calls WHERE request_id='shared-client-request-id'",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(duplicated_request_ids, 2);
    }

    #[tokio::test]
    async fn sensitive_admin_action_is_audited() {
        let state = crate::test_state("http://token.invalid").await;
        sqlx::query("INSERT INTO users(id,role,created_at) VALUES('admin','admin',?)")
            .bind(chrono::Utc::now().timestamp())
            .execute(&state.db)
            .await
            .unwrap();
        write_admin_audit(
            &state,
            "admin",
            "provider.create",
            Some("provider-1"),
            "127.0.0.1",
        )
        .await
        .unwrap();
        let row: (String, String) = sqlx::query_as("SELECT action,client_ip FROM admin_audit")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(row, ("provider.create".to_owned(), "127.0.0.1".to_owned()));
    }

    #[tokio::test]
    async fn provider_tokens_are_stored_and_replaced_as_plaintext() {
        let state = crate::test_state("http://token.invalid").await;
        let access = provider_access_token("account-old");
        let _ = insert_provider(&state, "provider", &access, "refresh-old", None)
            .await
            .unwrap();
        let id: String = sqlx::query_scalar("SELECT id FROM providers")
            .fetch_one(&state.db)
            .await
            .unwrap();
        let stored: (String, String) =
            sqlx::query_as("SELECT access_token,refresh_token FROM providers WHERE id=?")
                .bind(&id)
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(stored, (access, "refresh-old".to_owned()));

        let replacement = provider_access_token("account-new");
        let _ = replace_provider_token_values(
            &state,
            &id,
            "provider renamed",
            &replacement,
            "refresh-new",
        )
        .await
        .unwrap();
        let updated: (String, String, String, String) = sqlx::query_as(
            "SELECT name,access_token,refresh_token,account_id FROM providers WHERE id=?",
        )
        .bind(&id)
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(
            updated,
            (
                "provider renamed".to_owned(),
                replacement,
                "refresh-new".to_owned(),
                "account-new".to_owned()
            )
        );
    }

    #[tokio::test]
    async fn provider_test_calls_usage_with_server_side_credentials() {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let usage = Router::new().route(
            "/backend-api/wham/usage",
            get(move |headers: HeaderMap| {
                let sender = sender.clone();
                async move {
                    sender.send(headers).await.unwrap();
                    Json(json!({
                        "plan_type":"team",
                        "rate_limit":{"primary_window":{"used_percent":25.0}}
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, usage).await.unwrap() });
        let state = crate::test_state_with_upstream(
            "http://token.invalid",
            &format!("http://{address}/backend-api/codex"),
        )
        .await;
        let now = chrono::Utc::now().timestamp();
        sqlx::query("INSERT INTO providers(id,name,account_id,access_token,refresh_token,created_at,updated_at) VALUES('provider','Provider','account','access','refresh',?,?)")
            .bind(now).bind(now).execute(&state.db).await.unwrap();

        let result = provider_usage(&state, "provider").await.unwrap();
        assert_eq!(result.0["usage"]["plan_type"], "team");
        assert_eq!(
            result.0["usage"]["rate_limit"]["primary_window"]["used_percent"],
            25.0
        );
        let headers = receiver.recv().await.unwrap();
        assert_eq!(headers[axum::http::header::AUTHORIZATION], "Bearer access");
        assert_eq!(headers["chatgpt-account-id"], "account");
    }

    #[tokio::test]
    async fn provider_routes_enforce_roles_audit_actions_and_preserve_call_history() {
        let signing = SigningKey::from_bytes(&[31_u8; 32]);
        let x = URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes());
        let external = Router::new()
            .route(
                "/jwks",
                get(move || {
                    let x = x.clone();
                    async move { Json(json!({"keys":[{"kid":"setup","kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","x":x}]})) }
                }),
            )
            .route(
                "/backend-api/wham/usage",
                get(|headers: HeaderMap| async move {
                    if headers[header::AUTHORIZATION] == "Bearer denied" {
                        return (StatusCode::UNAUTHORIZED, "denied").into_response();
                    }
                    Json(json!({"email":"ops@example.com","plan_type":"team","rate_limit":{"primary_window":{"used_percent":10,"reset_after_seconds":1800}}})).into_response()
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, external).await.unwrap() });
        let issuer = format!("http://{address}");
        let state = crate::test_state_with_upstream(
            "http://token.invalid",
            &format!("{issuer}/backend-api/codex"),
        )
        .await;
        state.auth.configure(issuer.clone(), None).await;
        let now = chrono::Utc::now().timestamp();
        for (id, role) in [
            ("root-user", "root"),
            ("admin-user", "admin"),
            ("tenant-user", "user"),
        ] {
            sqlx::query("INSERT INTO users(id,role,created_at) VALUES(?,?,?)")
                .bind(id)
                .bind(role)
                .bind(now)
                .execute(&state.db)
                .await
                .unwrap();
        }
        sqlx::query("INSERT INTO consumers(id,user_id,name,prefix,secret_hash,created_at) VALUES('history-key','root-user','history','sk-history','hash-history',?)")
            .bind(now).execute(&state.db).await.unwrap();

        let admin_browser_token = setup_token(&signing, &issuer, "admin-user");
        let users = provider_request(
            &state,
            Method::GET,
            "/api/users",
            &admin_browser_token,
            None,
        )
        .await;
        assert_eq!(users.status(), StatusCode::OK);
        let users: Value =
            serde_json::from_slice(&users.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(
            users
                .as_array()
                .unwrap()
                .iter()
                .find(|user| user["id"] == "tenant-user")
                .and_then(|user| user["provider_access"].as_bool()),
            Some(false)
        );
        let grant = provider_request(
            &state,
            Method::PATCH,
            "/api/users/tenant-user",
            &admin_browser_token,
            Some(json!({"provider_access":true})),
        )
        .await;
        assert_eq!(grant.status(), StatusCode::OK);
        let granted: i64 =
            sqlx::query_scalar("SELECT provider_access FROM users WHERE id='tenant-user'")
                .fetch_one(&state.db)
                .await
                .unwrap();
        assert_eq!(granted, 1);

        for user_id in ["root-user", "admin-user"] {
            let provider_id = format!("provider-{user_id}");
            let call_id = format!("call-{user_id}");
            let access = provider_access_token(&format!("account-{user_id}"));
            sqlx::query("INSERT INTO providers(id,name,account_id,access_token,refresh_token,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
                .bind(&provider_id).bind(user_id).bind(format!("account-{user_id}"))
                .bind(access).bind("refresh").bind(now).bind(now).execute(&state.db).await.unwrap();
            sqlx::query("INSERT INTO api_calls(id,request_id,consumer_id,user_id,provider_id,method,path,status,latency_ms,created_at) VALUES(?,?,'history-key','root-user',?,'POST','/v1/responses',200,1,?)")
                .bind(&call_id).bind(&call_id).bind(&provider_id).bind(now).execute(&state.db).await.unwrap();
            let browser_token = setup_token(&signing, &issuer, user_id);

            let read = provider_request(
                &state,
                Method::GET,
                &format!("/api/providers/{provider_id}"),
                &browser_token,
                None,
            )
            .await;
            assert_eq!(read.status(), StatusCode::OK);
            assert_eq!(read.headers()[header::CACHE_CONTROL], "no-store");
            let read_body = read.into_body().collect().await.unwrap().to_bytes();
            assert!(std::str::from_utf8(&read_body).unwrap().contains("refresh"));

            let replacement = provider_access_token(&format!("replacement-{user_id}"));
            let update = provider_request(
                &state,
                Method::PUT,
                &format!("/api/providers/{provider_id}"),
                &browser_token,
                Some(
                    json!({"name":"renamed","access_key":replacement,"refresh_key":"refresh-new"}),
                ),
            )
            .await;
            assert_eq!(update.status(), StatusCode::OK);
            sqlx::query("INSERT INTO request_archives(api_call_id,request_headers_json,request_body,request_body_truncated,response_headers_json,response_body,response_body_truncated,created_at) VALUES(?,?,?,?,?,?,?,?)")
                .bind(&call_id)
                .bind(r#"[["content-type","application/json"]]"#)
                .bind(br#"{"input":"audit detail"}"#.as_slice())
                .bind(0)
                .bind(r#"[["content-type","application/json"]]"#)
                .bind(br#"{"output":"diagnostic"}"#.as_slice())
                .bind(0)
                .bind(now)
                .execute(&state.db)
                .await
                .unwrap();
            let affinity_hash =
                crate::balancer::affinity_hash(&format!("history-key:response-{user_id}"));
            sqlx::query("UPDATE api_calls SET affinity_hash=?,affinity_source='previous_response_id' WHERE id=?")
                .bind(&affinity_hash)
                .bind(&call_id)
                .execute(&state.db)
                .await
                .unwrap();
            let previous_id = format!("previous-{user_id}");
            sqlx::query("INSERT INTO api_calls(id,request_id,consumer_id,user_id,affinity_hash,affinity_source,method,path,status,latency_ms,created_at) VALUES(?,?, 'history-key','root-user',?,'previous_response_id','POST','/v1/responses',200,1,?)")
                .bind(&previous_id)
                .bind(format!("previous-request-{user_id}"))
                .bind(&affinity_hash)
                .bind(now - 1)
                .execute(&state.db)
                .await
                .unwrap();
            let audit =
                provider_request(&state, Method::GET, "/api/audit", &browser_token, None).await;
            assert_eq!(audit.status(), StatusCode::OK);
            let audits: Value =
                serde_json::from_slice(&audit.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            assert_eq!(
                audits
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|audit| audit["id"] == call_id)
                    .and_then(|audit| audit["provider_name"].as_str()),
                Some("renamed")
            );
            let detail = provider_request(
                &state,
                Method::GET,
                &format!("/api/audit/{call_id}"),
                &browser_token,
                None,
            )
            .await;
            assert_eq!(detail.status(), StatusCode::OK);
            let detail: Value =
                serde_json::from_slice(&detail.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            assert_eq!(detail["archive_available"], true);
            assert_eq!(detail["request_body"], json!(r#"{"input":"audit detail"}"#));
            assert_eq!(detail["response_body"], json!(r#"{"output":"diagnostic"}"#));
            assert_eq!(detail["previous"]["id"], previous_id);
            let test = provider_request(
                &state,
                Method::POST,
                &format!("/api/providers/{provider_id}/test"),
                &browser_token,
                None,
            )
            .await;
            assert_eq!(test.status(), StatusCode::OK);
            let usage_list = provider_request(
                &state,
                Method::GET,
                "/api/providers/usage",
                &browser_token,
                None,
            )
            .await;
            assert_eq!(usage_list.status(), StatusCode::OK);
            let usage_body = usage_list.into_body().collect().await.unwrap().to_bytes();
            let usage_value: Value = serde_json::from_slice(&usage_body).unwrap();
            assert_eq!(
                usage_value.pointer(&format!("/providers/{provider_id}/usage/plan_type")),
                Some(&json!("team"))
            );
            assert_eq!(
                usage_value.pointer(&format!("/providers/{provider_id}/usage/email")),
                Some(&json!("ops@example.com"))
            );
            let delete = provider_request(
                &state,
                Method::DELETE,
                &format!("/api/providers/{provider_id}"),
                &browser_token,
                None,
            )
            .await;
            assert_eq!(delete.status(), StatusCode::OK);
            let historical_provider: Option<String> =
                sqlx::query_scalar("SELECT provider_id FROM api_calls WHERE id=?")
                    .bind(call_id)
                    .fetch_one(&state.db)
                    .await
                    .unwrap();
            assert_eq!(historical_provider, None);
        }

        sqlx::query("INSERT INTO providers(id,name,account_id,access_token,refresh_token,created_at,updated_at) VALUES('tenant-provider','tenant','tenant','access','refresh',?,?)")
            .bind(now).bind(now).execute(&state.db).await.unwrap();
        let tenant_token = setup_token(&signing, &issuer, "tenant-user");
        sqlx::query("INSERT INTO consumers(id,user_id,name,prefix,secret_hash,created_at) VALUES('tenant-audit-key','tenant-user','tenant audit','sk-tenant-audit','tenant-audit-hash',?)")
            .bind(now).execute(&state.db).await.unwrap();
        sqlx::query("INSERT INTO api_calls(id,request_id,consumer_id,user_id,method,path,status,latency_ms,created_at) VALUES('tenant-audit-call','tenant-audit-request','tenant-audit-key','tenant-user','POST','/v1/responses',200,1,?)")
            .bind(now).execute(&state.db).await.unwrap();
        let tenant_detail = provider_request(
            &state,
            Method::GET,
            "/api/audit/tenant-audit-call",
            &tenant_token,
            None,
        )
        .await;
        assert_eq!(tenant_detail.status(), StatusCode::OK);
        let foreign_detail = provider_request(
            &state,
            Method::GET,
            "/api/audit/call-root-user",
            &tenant_token,
            None,
        )
        .await;
        assert_eq!(foreign_detail.status(), StatusCode::NOT_FOUND);
        for (method, path, body) in [
            (Method::GET, "/api/providers/usage", None),
            (Method::GET, "/api/providers/tenant-provider", None),
            (
                Method::PUT,
                "/api/providers/tenant-provider",
                Some(
                    json!({"name":"tenant","access_key":provider_access_token("tenant"),"refresh_key":"refresh"}),
                ),
            ),
            (Method::POST, "/api/providers/tenant-provider/test", None),
            (Method::DELETE, "/api/providers/tenant-provider", None),
        ] {
            let response = provider_request(&state, method, path, &tenant_token, body).await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }

        sqlx::query("INSERT INTO providers(id,name,account_id,access_token,refresh_token,created_at,updated_at) VALUES('denied-provider','denied','denied','denied','refresh',?,?)")
            .bind(now).bind(now).execute(&state.db).await.unwrap();
        let admin_token = setup_token(&signing, &issuer, "admin-user");
        let denied = provider_request(
            &state,
            Method::POST,
            "/api/providers/denied-provider/test",
            &admin_token,
            None,
        )
        .await;
        assert_eq!(denied.status(), StatusCode::BAD_GATEWAY);

        for (action, expected) in [
            ("provider.tokens.read", 2_i64),
            ("provider.tokens.update", 2),
            ("provider.test", 2),
            ("provider.delete", 2),
            ("provider.test.failed", 1),
        ] {
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM admin_audit WHERE action=?")
                .bind(action)
                .fetch_one(&state.db)
                .await
                .unwrap();
            assert_eq!(count, expected, "unexpected audit count for {action}");
        }
    }

    #[tokio::test]
    async fn provider_usage_maps_invalid_json_to_bad_gateway() {
        let invalid = Router::new().route(
            "/backend-api/wham/usage",
            get(|| async { (StatusCode::OK, "not-json") }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, invalid).await.unwrap() });
        let state = crate::test_state_with_upstream(
            "http://token.invalid",
            &format!("http://{address}/backend-api/codex"),
        )
        .await;
        let now = chrono::Utc::now().timestamp();
        sqlx::query("INSERT INTO providers(id,name,account_id,access_token,refresh_token,created_at,updated_at) VALUES('invalid','invalid','account','access','refresh',?,?)")
            .bind(now).bind(now).execute(&state.db).await.unwrap();
        let error = provider_usage(&state, "invalid").await.unwrap_err();
        assert_eq!(error.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(error.message(), "provider Usage API returned invalid JSON");
    }

    #[tokio::test]
    async fn provider_usage_maps_network_failure_to_bad_gateway() {
        let unavailable = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = unavailable.local_addr().unwrap();
        drop(unavailable);
        let state = crate::test_state_with_upstream(
            "http://token.invalid",
            &format!("http://{address}/backend-api/codex"),
        )
        .await;
        let now = chrono::Utc::now().timestamp();
        sqlx::query("INSERT INTO providers(id,name,account_id,access_token,refresh_token,created_at,updated_at) VALUES('offline','offline','account','access','refresh',?,?)")
            .bind(now).bind(now).execute(&state.db).await.unwrap();
        let error = provider_usage(&state, "offline").await.unwrap_err();
        assert_eq!(error.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(error.message(), "provider Usage API request failed");
    }
}
