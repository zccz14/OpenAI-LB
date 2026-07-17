pub mod api;
pub mod audit;
pub mod auth;
pub mod balancer;
pub mod config;
pub mod crypto;
pub mod db;
pub mod oauth;
pub mod proxy;

use std::{sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use axum::{
    Router,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, patch, post},
};
use dashmap::DashMap;
use rust_embed::RustEmbed;
use serde_json::json;
use sqlx::SqlitePool;
use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};

use crate::audit::AuditWriter;
use crate::{auth::AuthManager, balancer::Balancer, config::Config};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<ArcSwap<Config>>,
    pub db: SqlitePool,
    pub client: reqwest::Client,
    pub auth: AuthManager,
    pub audit: AuditWriter,
    pub balancer: Balancer,
    pub refresh_locks: Arc<DashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    pub(crate) oauth_flows: Arc<DashMap<String, OAuthFlow>>,
}

pub(crate) struct OAuthFlow {
    pub verifier: String,
    pub created_by: String,
    pub expires_at: i64,
}

impl AppState {
    pub async fn new(config: Config, db: SqlitePool) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(600))
            .build()?;
        let auth = AuthManager::new(
            config.auth_issuer.clone(),
            config.auth_audience.clone(),
            client.clone(),
        );
        let config = Arc::new(ArcSwap::from_pointee(config));
        let audit = AuditWriter::new(db.clone(), config.clone());
        let balancer = Balancer::default();
        balancer.hydrate(&db).await?;
        balancer.start_maintenance(db.clone());
        Ok(Self {
            config,
            db,
            client,
            auth,
            audit,
            balancer,
            refresh_locks: Arc::new(DashMap::new()),
            oauth_flows: Arc::new(DashMap::new()),
        })
    }
}

pub fn router(state: AppState) -> Router {
    let config = state.config.load();
    let response_limit = config.response_body_limit;
    let image_limit = config.image_body_limit;
    let audio_limit = config.audio_body_limit;
    drop(config);
    Router::new()
        .route("/api/health", get(api::health))
        .route("/api/config", get(api::public_config))
        .route("/api/setup", get(api::setup_status).post(api::setup))
        .route("/api/me", get(api::me))
        .route(
            "/api/consumers",
            get(api::list_consumers).post(api::create_consumer),
        )
        .route(
            "/api/consumers/{id}",
            patch(api::update_consumer).delete(api::revoke_consumer),
        )
        .route(
            "/api/providers",
            get(api::list_providers).post(api::create_provider),
        )
        .route("/api/providers/usage", get(api::list_provider_usage))
        .route(
            "/api/providers/{id}",
            get(api::read_provider_tokens)
                .put(api::replace_provider_tokens)
                .patch(api::update_provider)
                .delete(api::delete_provider),
        )
        .route("/api/providers/{id}/test", post(api::test_provider))
        .route("/api/oauth/start", post(api::oauth_start))
        .route("/api/oauth/complete", post(api::oauth_complete))
        .route("/api/usage", get(api::usage))
        .route("/api/audit", get(api::audit))
        .route("/api/audit/{id}", get(api::audit_detail))
        .route("/api/admin-audit", get(api::list_admin_audit))
        .route("/api/dashboard", get(api::dashboard))
        .route(
            "/api/settings",
            get(api::settings).patch(api::update_settings),
        )
        .route("/api/users", get(api::list_users))
        .route("/api/users/{id}", patch(api::update_user))
        .route(
            "/v1/responses",
            post(proxy::handle_json).layer(RequestBodyLimitLayer::new(response_limit)),
        )
        .route(
            "/v1/responses/compact",
            post(proxy::handle_json).layer(RequestBodyLimitLayer::new(response_limit)),
        )
        .route(
            "/backend-api/codex/responses",
            post(proxy::handle_json).layer(RequestBodyLimitLayer::new(response_limit)),
        )
        .route(
            "/backend-api/codex/responses/compact",
            post(proxy::handle_json).layer(RequestBodyLimitLayer::new(response_limit)),
        )
        .route(
            "/v1/audio/transcriptions",
            post(proxy::handle_audio).layer(RequestBodyLimitLayer::new(audio_limit)),
        )
        .route(
            "/v1/images/generations",
            post(proxy::handle_json).layer(RequestBodyLimitLayer::new(image_limit)),
        )
        .route("/v1/models", get(proxy::handle_models))
        .fallback(static_asset)
        .layer(axum::extract::DefaultBodyLimit::disable())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[derive(RustEmbed)]
#[folder = "web/dist/"]
struct Assets;

async fn static_asset(uri: axum::http::Uri) -> Response {
    if ["/api", "/v1", "/backend-api"]
        .iter()
        .any(|prefix| uri.path() == *prefix || uri.path().starts_with(&format!("{prefix}/")))
    {
        return (
            StatusCode::NOT_FOUND,
            axum::Json(
                json!({"error":{"message":"API route not found","type":"not_found","code":404}}),
            ),
        )
            .into_response();
    }
    let requested = uri.path().trim_start_matches('/');
    let path = if requested.is_empty() {
        "index.html"
    } else {
        requested
    };
    let requested_asset = Assets::get(path);
    let is_fallback = requested_asset.is_none();
    match requested_asset.or_else(|| Assets::get("index.html")) {
        Some(asset) => {
            let mime = if is_fallback {
                "text/html; charset=utf-8"
            } else {
                match path.rsplit('.').next() {
                    Some("js") => "text/javascript",
                    Some("css") => "text/css",
                    Some("svg") => "image/svg+xml",
                    Some("woff2") => "font/woff2",
                    _ => "text/html; charset=utf-8",
                }
            };
            ([(axum::http::header::CONTENT_TYPE, mime)], asset.data).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct AppError {
    status: StatusCode,
    message: String,
}

impl AppError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }
    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: message.into(),
        }
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
    pub fn upstream(status: u16, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
            message: message.into(),
        }
    }
    pub(crate) fn status(&self) -> StatusCode {
        self.status
    }
    pub(crate) fn message(&self) -> &str {
        &self.message
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.status, axum::Json(json!({"error":{"message":self.message,"type":"proxy_error","code":self.status.as_u16()}}))).into_response()
    }
}

impl From<anyhow::Error> for AppError {
    fn from(error: anyhow::Error) -> Self {
        tracing::error!(%error, "request failed");
        Self::internal("internal server error")
    }
}

macro_rules! internal_from {
    ($($kind:ty),+ $(,)?) => {$(
        impl From<$kind> for AppError {
            fn from(error: $kind) -> Self {
                tracing::error!(%error, "request failed");
                Self::internal("internal server error")
            }
        }
    )+};
}

internal_from!(
    sqlx::Error,
    reqwest::Error,
    serde_json::Error,
    url::ParseError
);

#[cfg(test)]
pub(crate) async fn test_state(oauth_token_url: &str) -> AppState {
    test_state_with_upstream(oauth_token_url, "http://upstream.invalid").await
}

#[cfg(test)]
pub(crate) async fn test_state_with_upstream(
    oauth_token_url: &str,
    upstream_base: &str,
) -> AppState {
    let pool = db::connect_memory().await.unwrap();
    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: std::env::temp_dir(),
        database_path: std::path::PathBuf::from(":memory:"),
        setup_complete: true,
        auth_issuer: Some("http://auth.invalid".to_owned()),
        auth_audience: None,
        upstream_base: upstream_base.to_owned(),
        image_host_model: "gpt-5.4".to_owned(),
        oauth_authorize_url: "http://auth.invalid/oauth/authorize".to_owned(),
        oauth_token_url: oauth_token_url.to_owned(),
        oauth_redirect_uri: "http://localhost:1455/auth/callback".to_owned(),
        oauth_client_id: "test-client".to_owned(),
        response_body_limit: 1024 * 1024,
        image_body_limit: 1024 * 1024,
        audio_body_limit: 1024 * 1024,
        affinity_ttl_seconds: 3600,
        request_archive_retention_days: 1,
    };
    AppState::new(config, pool).await.unwrap()
}

#[cfg(test)]
mod routing_tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[tokio::test]
    async fn unknown_api_namespace_returns_json_not_spa() {
        let state = crate::test_state("http://token.invalid").await;
        for path in ["/api/missing", "/v1/missing", "/backend-api/missing"] {
            let response = crate::router(state.clone())
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert_eq!(
                response.headers().get("content-type").unwrap(),
                "application/json"
            );
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert!(
                std::str::from_utf8(&body)
                    .unwrap()
                    .contains("API route not found")
            );
        }
    }
}
