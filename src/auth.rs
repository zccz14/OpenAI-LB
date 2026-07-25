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

use crate::{AppError, AppState, crypto::consumer_secret_hash};

#[derive(Clone, Debug, Serialize)]
pub struct UserIdentity {
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub role: String,
}

#[derive(Clone, Debug)]
pub struct ApiIdentity {
    pub consumer_id: String,
    pub user_id: String,
    pub request_archive: bool,
    pub all_providers: bool,
}

#[derive(Clone, Debug)]
pub struct VerifiedIdentity {
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
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

#[derive(Clone)]
pub struct AuthManager {
    client: reqwest::Client,
    verifier: Arc<RwLock<Option<AuthVerifier>>>,
}

impl AuthManager {
    pub fn new(issuer: Option<String>, audience: Option<String>, client: reqwest::Client) -> Self {
        let verifier = issuer.map(|issuer| AuthVerifier::new(issuer, audience, client.clone()));
        Self {
            client,
            verifier: Arc::new(RwLock::new(verifier)),
        }
    }

    pub async fn configure(&self, issuer: String, audience: Option<String>) {
        *self.verifier.write().await =
            Some(AuthVerifier::new(issuer, audience, self.client.clone()));
    }

    pub async fn verify_candidate(
        &self,
        issuer: String,
        audience: Option<String>,
        token: &str,
    ) -> Result<VerifiedIdentity, AppError> {
        let claims = AuthVerifier::new(issuer, audience, self.client.clone())
            .verify(token)
            .await?;
        Ok(VerifiedIdentity {
            id: claims.sub,
            email: claims.email,
            name: claims.name,
        })
    }

    async fn verify(&self, token: &str) -> Result<Claims, AppError> {
        let verifier = self
            .verifier
            .read()
            .await
            .clone()
            .ok_or_else(|| AppError::unavailable("OpenAI-LB setup is not complete"))?;
        verifier.verify(token).await
    }
}

pub async fn browser_identity(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<UserIdentity, AppError> {
    let token = bearer(headers)?;
    let claims = state.auth.verify(token).await?;
    upsert_user(&state.db, &claims).await
}

async fn upsert_user(pool: &SqlitePool, claims: &Claims) -> Result<UserIdentity, AppError> {
    let now = chrono::Utc::now().timestamp();
    sqlx::query("INSERT INTO users(id,email,display_name,role,created_at) VALUES(?,?,?,'user',?) ON CONFLICT(id) DO UPDATE SET email=excluded.email,display_name=CASE WHEN users.display_name_overridden=0 THEN excluded.display_name ELSE users.display_name END")
        .bind(&claims.sub)
        .bind(&claims.email)
        .bind(&claims.name)
        .bind(now)
        .execute(pool)
        .await?;
    let row = sqlx::query("SELECT email,display_name,role FROM users WHERE id=?")
        .bind(&claims.sub)
        .fetch_one(pool)
        .await?;
    Ok(UserIdentity {
        id: claims.sub.clone(),
        email: row.get(0),
        name: row.get(1),
        role: row.get(2),
    })
}

pub async fn api_identity(state: &AppState, headers: &HeaderMap) -> Result<ApiIdentity, AppError> {
    let secret = bearer(headers)?;
    if !secret.starts_with("sk-") {
        return Err(AppError::unauthorized("invalid consumer credential"));
    }
    let row = sqlx::query(
        "SELECT k.id,k.user_id,u.role,u.provider_access,k.request_archive FROM consumers k JOIN users u ON u.id=k.user_id WHERE k.secret_hash=? AND k.revoked_at IS NULL",
    )
            .bind(consumer_secret_hash(secret))
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| AppError::unauthorized("invalid consumer credential"))?;
    let role: String = row.get(2);
    let identity = ApiIdentity {
        consumer_id: row.get(0),
        user_id: row.get(1),
        request_archive: row.get::<i64, _>(4) != 0,
        all_providers: role != "user" || row.get::<i64, _>(3) != 0,
    };
    Ok(identity)
}

pub fn require_admin(identity: &UserIdentity) -> Result<(), AppError> {
    is_admin(identity)
        .then_some(())
        .ok_or_else(|| AppError::forbidden("administrator access required"))
}

pub fn is_admin(identity: &UserIdentity) -> bool {
    matches!(identity.role.as_str(), "root" | "admin")
}

pub fn require_root(identity: &UserIdentity) -> Result<(), AppError> {
    (identity.role == "root")
        .then_some(())
        .ok_or_else(|| AppError::forbidden("root access required"))
}

pub(crate) fn bearer(headers: &HeaderMap) -> Result<&str, AppError> {
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
    async fn consumer_auth_accepts_active_hash_and_rejects_revoked_key() {
        let state = crate::test_state("http://token.invalid").await;
        let now = chrono::Utc::now().timestamp();
        sqlx::query(
            "INSERT INTO users(id,role,provider_access,created_at) VALUES('user-1','user',1,?)",
        )
        .bind(now)
        .execute(&state.db)
        .await
        .unwrap();
        sqlx::query("INSERT INTO consumers(id,user_id,name,prefix,secret_hash,created_at) VALUES('key-1','user-1','test','sk-test',?,?)")
            .bind(consumer_secret_hash("sk-test-secret")).bind(now).execute(&state.db).await.unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer sk-test-secret"),
        );
        let identity = api_identity(&state, &headers).await.unwrap();
        assert_eq!(
            (identity.consumer_id.as_str(), identity.user_id.as_str()),
            ("key-1", "user-1")
        );
        sqlx::query("UPDATE consumers SET revoked_at=? WHERE id='key-1'")
            .bind(now)
            .execute(&state.db)
            .await
            .unwrap();
        assert!(api_identity(&state, &headers).await.is_err());
    }

    #[tokio::test]
    async fn consumer_identity_carries_global_provider_access() {
        let state = crate::test_state("http://token.invalid").await;
        let now = chrono::Utc::now().timestamp();
        for (id, role, secret) in [
            ("tenant", "user", "sk-tenant-secret"),
            ("admin", "admin", "sk-admin-secret"),
        ] {
            sqlx::query("INSERT INTO users(id,role,created_at) VALUES(?,?,?)")
                .bind(id)
                .bind(role)
                .bind(now)
                .execute(&state.db)
                .await
                .unwrap();
            sqlx::query("INSERT INTO consumers(id,user_id,name,prefix,secret_hash,created_at) VALUES(?,?,?,?,?,?)")
                .bind(format!("key-{id}"))
                .bind(id)
                .bind("test")
                .bind("sk-test")
                .bind(consumer_secret_hash(secret))
                .bind(now)
                .execute(&state.db)
                .await
                .unwrap();
        }
        let mut tenant_headers = HeaderMap::new();
        tenant_headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer sk-tenant-secret"),
        );
        assert!(
            !api_identity(&state, &tenant_headers)
                .await
                .unwrap()
                .all_providers
        );
        sqlx::query("UPDATE users SET provider_access=1 WHERE id='tenant'")
            .execute(&state.db)
            .await
            .unwrap();
        assert!(
            api_identity(&state, &tenant_headers)
                .await
                .unwrap()
                .all_providers
        );
        let mut admin_headers = HeaderMap::new();
        admin_headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer sk-admin-secret"),
        );
        assert!(
            api_identity(&state, &admin_headers)
                .await
                .unwrap()
                .all_providers
        );
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
    async fn ordinary_login_never_bootstraps_privilege() {
        let state = crate::test_state("http://token.invalid").await;
        let ordinary = upsert_user(&state.db, &claims("ordinary")).await.unwrap();
        assert_eq!(ordinary.role, "user");
    }

    #[tokio::test]
    async fn administrator_display_name_override_survives_later_logins() {
        let state = crate::test_state("http://token.invalid").await;
        let mut identity = claims("ordinary");
        identity.name = Some("Auth Mini name".to_owned());
        upsert_user(&state.db, &identity).await.unwrap();
        sqlx::query(
            "UPDATE users SET display_name='Operations name', display_name_overridden=1 WHERE id='ordinary'",
        )
        .execute(&state.db)
        .await
        .unwrap();

        identity.name = Some("Changed in Auth Mini".to_owned());
        let user = upsert_user(&state.db, &identity).await.unwrap();

        assert_eq!(user.name.as_deref(), Some("Operations name"));
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
