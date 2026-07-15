use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use axum::http::HeaderMap;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use tokio::sync::RwLock;

use crate::{AppError, AppState, crypto::api_key_hash};

#[derive(Clone, Debug, Serialize)]
pub struct UserIdentity {
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub role: String,
}

#[derive(Clone, Debug)]
pub struct ApiIdentity {
    pub key_id: String,
    pub user_id: String,
}

#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    exp: usize,
    #[serde(default)]
    email: Option<String>,
    #[serde(default, alias = "display_name")]
    name: Option<String>,
    typ: String,
}

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<EdJwk>,
}

#[derive(Clone, Debug, Deserialize)]
struct EdJwk {
    kid: String,
    x: String,
}

#[derive(Default)]
struct JwksCache {
    fetched_at: Option<Instant>,
    keys: Vec<EdJwk>,
}

#[derive(Clone)]
pub struct AuthVerifier {
    issuer: String,
    audience: Option<String>,
    client: reqwest::Client,
    cache: Arc<RwLock<JwksCache>>,
}

impl AuthVerifier {
    pub fn new(issuer: String, audience: Option<String>, client: reqwest::Client) -> Self {
        Self {
            issuer,
            audience,
            client,
            cache: Arc::new(RwLock::new(JwksCache::default())),
        }
    }

    async fn verify(&self, token: &str) -> Result<Claims, AppError> {
        let header =
            decode_header(token).map_err(|_| AppError::unauthorized("invalid bearer token"))?;
        if header.alg != Algorithm::EdDSA {
            return Err(AppError::unauthorized("unsupported token algorithm"));
        }
        let kid = header
            .kid
            .ok_or_else(|| AppError::unauthorized("token is missing kid"))?;
        let mut key = self.cached_key(&kid).await;
        if key.is_none() {
            self.refresh().await?;
            key = self.cached_key(&kid).await;
        }
        let key = key.ok_or_else(|| AppError::unauthorized("unknown signing key"))?;
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.leeway = 0;
        validation.set_issuer(&[&self.issuer]);
        if let Some(audience) = &self.audience {
            validation.set_audience(&[audience]);
        } else {
            validation.validate_aud = false;
        }
        let decoding_key = DecodingKey::from_ed_components(&key.x)
            .map_err(|_| AppError::unauthorized("invalid signing key"))?;
        let claims = decode::<Claims>(token, &decoding_key, &validation)
            .map_err(|_| AppError::unauthorized("invalid or expired bearer token"))?
            .claims;
        if claims.iss != self.issuer
            || claims.typ != "access"
            || claims.sub.trim().is_empty()
            || claims.exp == 0
        {
            return Err(AppError::unauthorized("invalid access token claims"));
        }
        Ok(claims)
    }

    async fn cached_key(&self, kid: &str) -> Option<EdJwk> {
        let cache = self.cache.read().await;
        let fresh = cache
            .fetched_at
            .is_some_and(|at| at.elapsed() < Duration::from_secs(300));
        fresh
            .then(|| cache.keys.iter().find(|key| key.kid == kid).cloned())
            .flatten()
    }

    async fn refresh(&self) -> Result<(), AppError> {
        let jwks = self
            .client
            .get(format!("{}/jwks", self.issuer))
            .send()
            .await
            .context("failed to fetch Auth Mini JWKS")?
            .error_for_status()
            .context("Auth Mini JWKS returned an error")?
            .json::<Jwks>()
            .await
            .context("invalid Auth Mini JWKS")?;
        *self.cache.write().await = JwksCache {
            fetched_at: Some(Instant::now()),
            keys: jwks.keys,
        };
        Ok(())
    }
}

pub async fn browser_identity(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<UserIdentity, AppError> {
    let token = bearer(headers)?;
    let claims = state.auth.verify(token).await?;
    upsert_user(&state.db, &claims, state.config.admin_user_id.as_deref()).await
}

async fn upsert_user(
    pool: &SqlitePool,
    claims: &Claims,
    configured_admin: Option<&str>,
) -> Result<UserIdentity, AppError> {
    let mut connection = pool.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *connection)
        .await?;
    if let Some(admin_id) = configured_admin {
        sqlx::query("UPDATE users SET role=CASE WHEN id=? THEN 'admin' ELSE 'user' END")
            .bind(admin_id)
            .execute(&mut *connection)
            .await?;
    }
    let existing = sqlx::query("SELECT email, display_name, role FROM users WHERE id=?")
        .bind(&claims.sub)
        .fetch_optional(&mut *connection)
        .await?;
    if let Some(row) = existing {
        let role: String = if configured_admin == Some(claims.sub.as_str()) {
            sqlx::query("UPDATE users SET role='admin' WHERE id=?")
                .bind(&claims.sub)
                .execute(&mut *connection)
                .await?;
            "admin".to_owned()
        } else {
            row.get(2)
        };
        sqlx::query("COMMIT").execute(&mut *connection).await?;
        return Ok(UserIdentity {
            id: claims.sub.clone(),
            email: row.get(0),
            name: row.get(1),
            role,
        });
    }
    let role = match configured_admin {
        Some(admin_id) if admin_id == claims.sub => "admin",
        Some(_) => "user",
        None => {
            let admins: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role='admin'")
                .fetch_one(&mut *connection)
                .await?;
            if admins == 0 { "admin" } else { "user" }
        }
    };
    let now = chrono::Utc::now().timestamp();
    sqlx::query("INSERT INTO users(id,email,display_name,role,created_at) VALUES(?,?,?,?,?)")
        .bind(&claims.sub)
        .bind(&claims.email)
        .bind(&claims.name)
        .bind(role)
        .bind(now)
        .execute(&mut *connection)
        .await?;
    sqlx::query("COMMIT").execute(&mut *connection).await?;
    Ok(UserIdentity {
        id: claims.sub.clone(),
        email: claims.email.clone(),
        name: claims.name.clone(),
        role: role.to_owned(),
    })
}

pub async fn api_identity(state: &AppState, headers: &HeaderMap) -> Result<ApiIdentity, AppError> {
    let secret = bearer(headers)?;
    if !secret.starts_with("sk-") {
        return Err(AppError::unauthorized("invalid API key"));
    }
    let row =
        sqlx::query("SELECT id,user_id FROM api_keys WHERE secret_hash=? AND revoked_at IS NULL")
            .bind(api_key_hash(secret))
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| AppError::unauthorized("invalid API key"))?;
    let identity = ApiIdentity {
        key_id: row.get(0),
        user_id: row.get(1),
    };
    sqlx::query("UPDATE api_keys SET last_used_at=? WHERE id=?")
        .bind(chrono::Utc::now().timestamp())
        .bind(&identity.key_id)
        .execute(&state.db)
        .await?;
    Ok(identity)
}

pub fn require_admin(identity: &UserIdentity) -> Result<(), AppError> {
    (identity.role == "admin")
        .then_some(())
        .ok_or_else(|| AppError::forbidden("administrator access required"))
}

fn bearer(headers: &HeaderMap) -> Result<&str, AppError> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::unauthorized("missing bearer token"))
}

#[cfg(test)]
mod tests {
    use axum::{
        Json, Router,
        http::{HeaderMap, HeaderValue},
        routing::get,
    };
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    #[tokio::test]
    async fn api_key_auth_accepts_active_hash_and_rejects_revoked_key() {
        let state = crate::test_state("http://token.invalid").await;
        let now = chrono::Utc::now().timestamp();
        sqlx::query("INSERT INTO users(id,role,created_at) VALUES('user-1','user',?)")
            .bind(now)
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO api_keys(id,user_id,name,prefix,secret_hash,created_at) VALUES('key-1','user-1','test','sk-test',?,?)")
            .bind(api_key_hash("sk-test-secret")).bind(now).execute(&state.db).await.unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer sk-test-secret"),
        );
        let identity = api_identity(&state, &headers).await.unwrap();
        assert_eq!(
            (identity.key_id.as_str(), identity.user_id.as_str()),
            ("key-1", "user-1")
        );
        sqlx::query("UPDATE api_keys SET revoked_at=? WHERE id='key-1'")
            .bind(now)
            .execute(&state.db)
            .await
            .unwrap();
        assert!(api_identity(&state, &headers).await.is_err());
    }

    fn claims(sub: &str) -> Claims {
        Claims {
            sub: sub.to_owned(),
            iss: "http://issuer".to_owned(),
            exp: (chrono::Utc::now().timestamp() + 300) as usize,
            email: None,
            name: None,
            typ: "access".to_owned(),
        }
    }

    #[tokio::test]
    async fn first_admin_bootstrap_is_atomic() {
        let path =
            std::env::temp_dir().join(format!("openai-lb-admin-{}.sqlite", uuid::Uuid::new_v4()));
        let pool = crate::db::connect(&format!("sqlite://{}?mode=rwc", path.display()))
            .await
            .unwrap();
        let first_pool = pool.clone();
        let second_pool = pool.clone();
        let first = tokio::spawn(async move {
            upsert_user(&first_pool, &claims("first"), None)
                .await
                .unwrap()
        });
        let second = tokio::spawn(async move {
            upsert_user(&second_pool, &claims("second"), None)
                .await
                .unwrap()
        });
        let (first, second) = tokio::join!(first, second);
        let roles = [first.unwrap().role, second.unwrap().role];
        assert_eq!(
            roles.iter().filter(|role| role.as_str() == "admin").count(),
            1
        );
        pool.close().await;
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    #[tokio::test]
    async fn configured_admin_disables_first_user_bootstrap() {
        let state = crate::test_state("http://token.invalid").await;
        let ordinary = upsert_user(&state.db, &claims("ordinary"), Some("configured"))
            .await
            .unwrap();
        let configured = upsert_user(&state.db, &claims("configured"), Some("configured"))
            .await
            .unwrap();
        assert_eq!(ordinary.role, "user");
        assert_eq!(configured.role, "admin");
    }

    fn sign_token(key: &SigningKey, issuer: &str, typ: &str, exp: i64) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","kid":"test","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "sub":"user-1", "iss":issuer, "typ":typ, "exp":exp
            }))
            .unwrap(),
        );
        let input = format!("{header}.{payload}");
        let signature = key.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    #[tokio::test]
    async fn ed25519_jwks_verification_fails_closed_on_claims() {
        let signing = SigningKey::from_bytes(&[7_u8; 32]);
        let x = URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes());
        let app = Router::new().route("/jwks", get(move || {
            let x = x.clone();
            async move { Json(serde_json::json!({"keys":[{"kid":"test","kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","x":x}]})) }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let issuer = format!("http://{address}");
        let verifier = AuthVerifier::new(issuer.clone(), None, reqwest::Client::new());
        let now = chrono::Utc::now().timestamp();
        assert!(
            verifier
                .verify(&sign_token(&signing, &issuer, "access", now + 60))
                .await
                .is_ok()
        );
        assert!(
            verifier
                .verify(&sign_token(&signing, &issuer, "refresh", now + 60))
                .await
                .is_err()
        );
        assert!(
            verifier
                .verify(&sign_token(&signing, "http://wrong", "access", now + 60))
                .await
                .is_err()
        );
        assert!(
            verifier
                .verify(&sign_token(&signing, &issuer, "access", now - 1))
                .await
                .is_err()
        );
    }
}
