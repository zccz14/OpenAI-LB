use std::net::SocketAddr;

use axum::{
    Json,
    extract::{ConnectInfo, Path, Query, State},
    http::HeaderMap,
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
    balancer::Channel,
    crypto::{api_key_hash, encrypt},
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
pub struct CreateKey {
    name: String,
}

pub async fn list_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let user = browser_identity(&state, &headers).await?;
    let rows = sqlx::query("SELECT id,name,prefix,created_at,last_used_at,revoked_at FROM api_keys WHERE user_id=? ORDER BY created_at DESC")
        .bind(&user.id).fetch_all(&state.db).await?;
    Ok(Json(Value::Array(rows.into_iter().map(|row| json!({
        "id": row.get::<String,_>(0), "name": row.get::<String,_>(1), "prefix": row.get::<String,_>(2),
        "created_at": row.get::<i64,_>(3), "last_used_at": row.get::<Option<i64>,_>(4), "revoked_at": row.get::<Option<i64>,_>(5)
    })).collect())))
}

pub async fn create_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateKey>,
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
        "INSERT INTO api_keys(id,user_id,name,prefix,secret_hash,created_at) VALUES(?,?,?,?,?,?)",
    )
    .bind(&id)
    .bind(&user.id)
    .bind(name)
    .bind(&prefix)
    .bind(api_key_hash(&secret))
    .bind(chrono::Utc::now().timestamp())
    .execute(&state.db)
    .await?;
    Ok(Json(
        json!({"id":id,"name":name,"prefix":prefix,"secret":secret}),
    ))
}

pub async fn revoke_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let user = browser_identity(&state, &headers).await?;
    let result = sqlx::query(
        "UPDATE api_keys SET revoked_at=? WHERE id=? AND user_id=? AND revoked_at IS NULL",
    )
    .bind(chrono::Utc::now().timestamp())
    .bind(id)
    .bind(user.id)
    .execute(&state.db)
    .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::not_found("API key not found"));
    }
    Ok(Json(json!({"ok":true})))
}

#[derive(Deserialize)]
pub struct CreateChannel {
    name: String,
    access_key: String,
    refresh_key: String,
}

pub async fn list_channels(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let user = browser_identity(&state, &headers).await?;
    require_admin(&user)?;
    let channels = sqlx::query_as::<_, Channel>("SELECT * FROM channels ORDER BY created_at DESC")
        .fetch_all(&state.db)
        .await?;
    Ok(Json(Value::Array(
        channels
            .into_iter()
            .map(|channel| {
                let inflight = state.balancer.inflight(&channel.id);
                let mut value = serde_json::to_value(channel).expect("channel serializes");
                value["inflight"] = json!(inflight);
                value
            })
            .collect(),
    )))
}

pub async fn create_channel(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(input): Json<CreateChannel>,
) -> Result<Json<Value>, AppError> {
    let user = browser_identity(&state, &headers).await?;
    require_admin(&user)?;
    let result = insert_channel(
        &state,
        &input.name,
        &input.access_key,
        &input.refresh_key,
        None,
    )
    .await;
    let action = if result.is_ok() {
        "channel.create"
    } else {
        "channel.create.failed"
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

async fn insert_channel(
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
    sqlx::query("INSERT INTO channels(id,name,account_id,access_enc,refresh_enc,expires_at,status,created_at,updated_at) VALUES(?,?,?,?,?,?,'active',?,?)")
        .bind(&id).bind(name.trim()).bind(&account_id).bind(encrypt(&state.config.load().encryption_key, access)?)
        .bind(encrypt(&state.config.load().encryption_key, refresh)?).bind(expires_at).bind(now).bind(now).execute(&state.db).await?;
    state.balancer.reload_channels(&state.db).await?;
    Ok(Json(
        json!({"id":id,"name":name.trim(),"account_id":account_id,"status":"active"}),
    ))
}

#[derive(Deserialize)]
pub struct ChannelUpdate {
    name: Option<String>,
    enabled: Option<bool>,
    refresh: Option<bool>,
}

pub async fn update_channel(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<ChannelUpdate>,
) -> Result<Json<Value>, AppError> {
    let user = browser_identity(&state, &headers).await?;
    require_admin(&user)?;
    let operation: Result<Json<Value>, AppError> = async {
        if let Some(name) = input.name.filter(|name| !name.trim().is_empty()) {
            sqlx::query("UPDATE channels SET name=?,updated_at=? WHERE id=?")
                .bind(name.trim())
                .bind(chrono::Utc::now().timestamp())
                .bind(&id)
                .execute(&state.db)
                .await?;
        }
        if let Some(enabled) = input.enabled {
            let (disabled, status) = if enabled { (0, "active") } else { (1, "disabled") };
            sqlx::query("UPDATE channels SET manual_disabled=?,status=?,cooldown_until=NULL,updated_at=? WHERE id=?")
                .bind(disabled).bind(status).bind(chrono::Utc::now().timestamp()).bind(&id).execute(&state.db).await?;
        }
        if input.refresh.unwrap_or(false) {
            refresh_channel(&state, &id).await?;
        }
        state.balancer.reload_channels(&state.db).await?;
        Ok(Json(json!({"ok":true})))
    }.await;
    let action = if operation.is_ok() {
        "channel.update"
    } else {
        "channel.update.failed"
    };
    write_admin_audit(&state, &user.id, action, Some(&id), &peer.ip().to_string()).await?;
    operation
}

async fn refresh_channel(state: &AppState, id: &str) -> Result<(), AppError> {
    let lock = state
        .refresh_locks
        .entry(id.to_owned())
        .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;
    let row = sqlx::query("SELECT refresh_enc,account_id FROM channels WHERE id=?")
        .bind(id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::not_found("channel not found"))?;
    let refresh =
        crate::crypto::decrypt(&state.config.load().encryption_key, row.get::<&str, _>(0))?;
    let token = oauth::refresh(state, &refresh).await?;
    let account_id =
        oauth::account_id_from_jwt(&token.access_token).unwrap_or_else(|_| row.get::<String, _>(1));
    let now = chrono::Utc::now().timestamp();
    let refresh_enc: String = row.get(0);
    let updated = sqlx::query("UPDATE channels SET access_enc=?,refresh_enc=?,account_id=?,expires_at=?,status=CASE WHEN manual_disabled=1 THEN 'disabled' ELSE 'active' END,cooldown_until=NULL,last_error=NULL,updated_at=? WHERE id=? AND refresh_enc=?")
        .bind(encrypt(&state.config.load().encryption_key, &token.access_token)?)
        .bind(encrypt(&state.config.load().encryption_key, &token.refresh_token)?)
        .bind(account_id).bind(now + token.expires_in).bind(now).bind(id).bind(refresh_enc).execute(&state.db).await?;
    if updated.rows_affected() == 0 {
        return Err(AppError::unavailable(
            "channel credential changed during refresh",
        ));
    }
    state.balancer.reload_channels(&state.db).await?;
    Ok(())
}

pub async fn delete_channel(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let user = browser_identity(&state, &headers).await?;
    require_admin(&user)?;
    let result: Result<Json<Value>, AppError> = async {
        let deleted = sqlx::query("DELETE FROM channels WHERE id=?")
            .bind(&id)
            .execute(&state.db)
            .await?;
        if deleted.rows_affected() == 0 {
            return Err(AppError::not_found("channel not found"));
        }
        state.balancer.reload_channels(&state.db).await?;
        Ok(Json(json!({"ok":true})))
    }
    .await;
    let action = if result.is_ok() {
        "channel.delete"
    } else {
        "channel.delete.failed"
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
        insert_channel(
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
    let rows = sqlx::query("SELECT k.id,k.name,k.prefix,COUNT(c.id),COALESCE(SUM(c.input_tokens),0),COALESCE(SUM(c.output_tokens),0),COALESCE(SUM(c.cached_tokens),0),COALESCE(SUM(CASE WHEN c.status>=400 THEN 1 ELSE 0 END),0),COALESCE(AVG(c.latency_ms),0) FROM api_keys k LEFT JOIN api_calls c ON c.api_key_id=k.id WHERE k.user_id=? GROUP BY k.id ORDER BY k.created_at DESC")
        .bind(&user.id).fetch_all(&state.db).await?;
    Ok(Json(Value::Array(rows.into_iter().map(|row| json!({
        "key_id":row.get::<String,_>(0),"name":row.get::<String,_>(1),"prefix":row.get::<String,_>(2),"requests":row.get::<i64,_>(3),
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
            "SELECT c.id,c.request_id,c.user_id,k.prefix,c.channel_id,c.path,c.method,c.model,c.status,c.latency_ms,c.input_tokens,c.output_tokens,c.cached_tokens,c.error,c.client_ip,c.created_at FROM api_calls c JOIN api_keys k ON k.id=c.api_key_id ORDER BY c.created_at DESC LIMIT ? OFFSET ?",
            None,
        )
    } else {
        (
            "SELECT c.id,c.request_id,c.user_id,k.prefix,c.channel_id,c.path,c.method,c.model,c.status,c.latency_ms,c.input_tokens,c.output_tokens,c.cached_tokens,c.error,c.client_ip,c.created_at FROM api_calls c JOIN api_keys k ON k.id=c.api_key_id WHERE c.user_id=? ORDER BY c.created_at DESC LIMIT ? OFFSET ?",
            Some(user.id),
        )
    };
    let mut query = sqlx::query(sql);
    if let Some(scope) = scope {
        query = query.bind(scope);
    }
    let rows = query.bind(limit).bind(offset).fetch_all(&state.db).await?;
    Ok(Json(Value::Array(rows.into_iter().map(|row| json!({
        "id":row.get::<String,_>(0),"request_id":row.get::<String,_>(1),"user_id":row.get::<String,_>(2),"key_prefix":row.get::<String,_>(3),"channel_id":row.get::<Option<String>,_>(4),
        "path":row.get::<String,_>(5),"method":row.get::<String,_>(6),"model":row.get::<Option<String>,_>(7),"status":row.get::<i64,_>(8),"latency_ms":row.get::<i64,_>(9),
        "input_tokens":row.get::<i64,_>(10),"output_tokens":row.get::<i64,_>(11),"cached_tokens":row.get::<i64,_>(12),"error":row.get::<Option<String>,_>(13),"client_ip":row.get::<Option<String>,_>(14),"created_at":row.get::<i64,_>(15)
    })).collect())))
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
    let keys: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM api_keys WHERE user_id=? AND revoked_at IS NULL")
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
    let channels: i64 = if is_admin(&user) {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM channels WHERE manual_disabled=0 AND status='active'",
        )
        .fetch_one(&state.db)
        .await?
    } else {
        0
    };
    Ok(Json(
        json!({"active_keys":keys,"calls_24h":calls,"errors_24h":errors,"available_channels":channels}),
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
    require_root(&root)?;
    let rows = sqlx::query(
        "SELECT id,email,display_name,role,created_at FROM users ORDER BY created_at,id",
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
                    "created_at":row.get::<i64,_>(4)
                })
            })
            .collect(),
    )))
}

#[derive(Deserialize)]
pub struct UpdateUserRole {
    role: String,
}

pub async fn update_user_role(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<UpdateUserRole>,
) -> Result<Json<Value>, AppError> {
    let root = browser_identity(&state, &headers).await?;
    require_root(&root)?;
    if !matches!(input.role.as_str(), "admin" | "user") {
        return Err(AppError::bad_request("role must be admin or user"));
    }
    let result = sqlx::query("UPDATE users SET role=? WHERE id=? AND role<>'root'")
        .bind(&input.role)
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
        &root.id,
        "user.role.update",
        Some(&id),
        &peer.ip().to_string(),
    )
    .await?;
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
    use axum::{Router, routing::get};
    use ed25519_dalek::{Signer, SigningKey};

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
            sqlx::query("INSERT INTO api_keys(id,user_id,name,prefix,secret_hash,created_at) VALUES(?,?,?,? ,?,?)")
                .bind(format!("key-{user}")).bind(user).bind(user).bind(user)
                .bind(format!("hash-{user}")).bind(now).execute(&state.db).await.unwrap();
            sqlx::query("INSERT INTO api_calls(id,request_id,api_key_id,user_id,method,path,status,latency_ms,created_at) VALUES(?,?,?,?, 'POST','/v1/responses',200,1,?)")
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
            "channel.create",
            Some("channel-1"),
            "127.0.0.1",
        )
        .await
        .unwrap();
        let row: (String, String) = sqlx::query_as("SELECT action,client_ip FROM admin_audit")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(row, ("channel.create".to_owned(), "127.0.0.1".to_owned()));
    }
}
