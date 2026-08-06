use std::sync::Arc;

use auth_mini_axum::{AuthMiniError, AuthMiniVerifier, JwksCachePolicy};
use axum::http::HeaderMap;
use serde::Serialize;
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
}

#[derive(Clone)]
pub struct AuthManager {
    verifier: Arc<RwLock<Option<AuthMiniVerifier>>>,
}

impl AuthManager {
    pub async fn new(issuer: Option<String>, audience: Option<String>) -> anyhow::Result<Self> {
        let verifier = match (issuer, audience) {
            (None, None) => None,
            (Some(issuer), Some(audience)) => Some(create_verifier(&issuer, audience).await?),
            _ => anyhow::bail!("Auth Mini issuer and audience must be configured together"),
        };
        Ok(Self {
            verifier: Arc::new(RwLock::new(verifier)),
        })
    }

    #[cfg(test)]
    pub async fn configure(&self, issuer: String, audience: String) -> Result<(), AppError> {
        self.install(
            create_verifier(&issuer, audience)
                .await
                .map_err(auth_error)?,
        )
        .await;
        Ok(())
    }

    pub async fn install(&self, verifier: AuthMiniVerifier) {
        *self.verifier.write().await = Some(verifier);
    }

    pub async fn verify_candidate(
        &self,
        issuer: String,
        audience: String,
        token: &str,
    ) -> Result<(VerifiedIdentity, AuthMiniVerifier), AppError> {
        let verifier = create_verifier(&issuer, audience)
            .await
            .map_err(auth_error)?;
        let principal = verifier.verify(token).await.map_err(auth_error)?;
        Ok((
            VerifiedIdentity {
                id: principal.subject,
            },
            verifier,
        ))
    }

    async fn verify(&self, token: &str) -> Result<String, AppError> {
        let verifier = self
            .verifier
            .read()
            .await
            .clone()
            .ok_or_else(|| AppError::unavailable("OpenAI-LB setup is not complete"))?;
        Ok(verifier.verify(token).await.map_err(auth_error)?.subject)
    }
}

async fn create_verifier(
    issuer: &str,
    audience: String,
) -> Result<AuthMiniVerifier, auth_mini_axum::AuthMiniError> {
    AuthMiniVerifier::from_issuer(issuer, audience, JwksCachePolicy::default()).await
}

fn auth_error(error: AuthMiniError) -> AppError {
    match error {
        AuthMiniError::JwksUnavailable => AppError::unavailable("Auth Mini JWKS is unavailable"),
        AuthMiniError::InvalidIssuer => AppError::bad_request("Auth Mini issuer is not valid"),
        AuthMiniError::InvalidToken => AppError::unauthorized("invalid or expired bearer token"),
    }
}

pub async fn browser_identity(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<UserIdentity, AppError> {
    let token = bearer(headers)?;
    let user_id = state.auth.verify(token).await?;
    upsert_user(&state.db, &user_id).await
}

async fn upsert_user(pool: &SqlitePool, user_id: &str) -> Result<UserIdentity, AppError> {
    let now = chrono::Utc::now().timestamp();
    sqlx::query(
        "INSERT INTO users(id,role,created_at) VALUES(?,'user',?) ON CONFLICT(id) DO NOTHING",
    )
    .bind(user_id)
    .bind(now)
    .execute(pool)
    .await?;
    let row = sqlx::query("SELECT email,display_name,role FROM users WHERE id=?")
        .bind(user_id)
        .fetch_one(pool)
        .await?;
    Ok(UserIdentity {
        id: user_id.to_owned(),
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
    Ok(ApiIdentity {
        consumer_id: row.get(0),
        user_id: row.get(1),
        request_archive: row.get::<i64, _>(4) != 0,
        all_providers: role != "user" || row.get::<i64, _>(3) != 0,
    })
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
    use axum::http::{HeaderMap, HeaderValue};

    use super::*;

    #[tokio::test]
    async fn configured_issuer_requires_an_audience() {
        assert!(
            AuthManager::new(Some("https://auth.example.com".to_owned()), None)
                .await
                .is_err()
        );
    }

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

    #[tokio::test]
    async fn ordinary_login_never_bootstraps_privilege() {
        let state = crate::test_state("http://token.invalid").await;
        let ordinary = upsert_user(&state.db, "ordinary").await.unwrap();
        assert_eq!(ordinary.role, "user");
    }
}
