use std::{net::SocketAddr, str::FromStr};

use anyhow::{Context, Result};

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub database_url: String,
    pub encryption_key: [u8; 32],
    pub auth_issuer: String,
    pub auth_audience: Option<String>,
    pub admin_user_id: Option<String>,
    pub upstream_base: String,
    pub image_host_model: String,
    pub oauth_authorize_url: String,
    pub oauth_token_url: String,
    pub oauth_redirect_uri: String,
    pub oauth_client_id: String,
    pub allowed_origins: Vec<String>,
    pub max_body_bytes: usize,
    pub affinity_ttl_seconds: i64,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let key = std::env::var("ENCRYPTION_KEY").context("ENCRYPTION_KEY is required")?;
        let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, key)
            .context("ENCRYPTION_KEY must be base64")?;
        let encryption_key: [u8; 32] = decoded
            .try_into()
            .map_err(|_| anyhow::anyhow!("ENCRYPTION_KEY must decode to 32 bytes"))?;
        Ok(Self {
            listen: SocketAddr::from_str(&env("LISTEN_ADDR", "0.0.0.0:8080"))?,
            database_url: env("DATABASE_URL", "sqlite://openai-lb.sqlite?mode=rwc"),
            encryption_key,
            auth_issuer: trim_slash(
                &std::env::var("AUTH_MINI_ISSUER").context("AUTH_MINI_ISSUER is required")?,
            ),
            auth_audience: std::env::var("AUTH_MINI_AUDIENCE")
                .ok()
                .filter(|v| !v.is_empty()),
            admin_user_id: std::env::var("ADMIN_USER_ID")
                .ok()
                .filter(|v| !v.is_empty()),
            upstream_base: trim_slash(&env(
                "CODEX_UPSTREAM_BASE",
                "https://chatgpt.com/backend-api/codex",
            )),
            image_host_model: env("IMAGE_HOST_MODEL", "gpt-5.4"),
            oauth_authorize_url: env(
                "CODEX_OAUTH_AUTHORIZE_URL",
                "https://auth.openai.com/oauth/authorize",
            ),
            oauth_token_url: env(
                "CODEX_OAUTH_TOKEN_URL",
                "https://auth.openai.com/oauth/token",
            ),
            oauth_redirect_uri: env(
                "CODEX_OAUTH_REDIRECT_URI",
                "http://localhost:1455/auth/callback",
            ),
            oauth_client_id: env("CODEX_OAUTH_CLIENT_ID", "app_EMoamEEZ73f0CkXaXp7hrann"),
            allowed_origins: env("CORS_ALLOWED_ORIGINS", "http://localhost:5173")
                .split(',')
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
                .collect(),
            max_body_bytes: env("MAX_BODY_BYTES", "67108864").parse()?,
            affinity_ttl_seconds: env("AFFINITY_TTL_SECONDS", "86400").parse()?,
        })
    }
}

fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
}

fn trim_slash(value: &str) -> String {
    value.trim_end_matches('/').to_owned()
}
