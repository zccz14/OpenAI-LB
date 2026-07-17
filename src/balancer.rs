use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};

use arc_swap::ArcSwap;
use dashmap::{DashMap, DashSet};
use reqwest::{StatusCode, header::HeaderMap};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{FromRow, Row};

use crate::{AppError, AppState};

#[derive(Clone, FromRow, Serialize)]
pub struct Provider {
    pub id: String,
    pub name: String,
    pub account_id: String,
    #[serde(skip_serializing)]
    pub access_token: String,
    #[serde(skip_serializing)]
    pub refresh_token: String,
    pub expires_at: Option<i64>,
    pub status: String,
    pub manual_disabled: i64,
    pub cooldown_until: Option<i64>,
    pub rate_limit_json: Option<String>,
    pub last_error: Option<String>,
    pub last_used_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone)]
pub struct Balancer {
    inflight: Arc<DashMap<String, AtomicUsize>>,
    cursor: Arc<AtomicU64>,
    providers: Arc<ArcSwap<Vec<Provider>>>,
    affinities: Arc<DashMap<String, AffinityEntry>>,
    dirty_affinities: Arc<DashSet<String>>,
    provider_updates: Arc<DashMap<String, ProviderUpdate>>,
}

#[derive(Clone, PartialEq)]
struct AffinityEntry {
    provider_id: String,
    expires_at: i64,
    updated_at: i64,
}

#[derive(Clone, PartialEq)]
struct ProviderUpdate {
    status: String,
    cooldown_until: Option<i64>,
    rate_limit_json: String,
    last_error: Option<String>,
    last_used_at: Option<i64>,
    updated_at: i64,
}

pub struct Lease {
    pub provider: Provider,
    pub access_token: String,
    pub refresh_token: String,
    inflight: Arc<DashMap<String, AtomicUsize>>,
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(value) = self.inflight.get(&self.provider.id) {
            value.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl Default for Balancer {
    fn default() -> Self {
        Self {
            inflight: Arc::new(DashMap::new()),
            cursor: Arc::new(AtomicU64::new(0)),
            providers: Arc::new(ArcSwap::from_pointee(Vec::new())),
            affinities: Arc::new(DashMap::new()),
            dirty_affinities: Arc::new(DashSet::new()),
            provider_updates: Arc::new(DashMap::new()),
        }
    }
}

impl Balancer {
    pub async fn select(
        &self,
        state: &AppState,
        affinity: Option<&str>,
        excluded: Option<&str>,
    ) -> Result<Lease, AppError> {
        let now = chrono::Utc::now().timestamp();
        let providers = self.providers.load();
        let eligible: Vec<Provider> = providers
            .iter()
            .filter(|item| provider_is_available(item, now))
            .filter(|item| excluded != Some(item.id.as_str()))
            .cloned()
            .collect();
        if eligible.is_empty() {
            return Err(AppError::unavailable("no available CodeX provider"));
        }
        let chosen = match affinity {
            Some(key) => self.affinity_provider(key, &eligible, now),
            None => None,
        }
        .unwrap_or_else(|| self.least_inflight(&eligible));
        if let Some(key) = affinity {
            self.remember_affinity(
                key,
                &chosen.id,
                now,
                state.config.load().affinity_ttl_seconds,
            );
        }
        self.inflight
            .entry(chosen.id.clone())
            .or_default()
            .fetch_add(1, Ordering::Relaxed);
        Ok(Lease {
            access_token: chosen.access_token.clone(),
            refresh_token: chosen.refresh_token.clone(),
            provider: chosen,
            inflight: self.inflight.clone(),
        })
    }

    fn affinity_provider(&self, key: &str, eligible: &[Provider], now: i64) -> Option<Provider> {
        let hash = affinity_hash(key);
        let entry = self.affinities.get(&hash)?;
        (entry.expires_at > now)
            .then(|| {
                eligible
                    .iter()
                    .find(|provider| provider.id == entry.provider_id)
                    .cloned()
            })
            .flatten()
    }

    fn least_inflight(&self, providers: &[Provider]) -> Provider {
        let start = self.cursor.fetch_add(1, Ordering::Relaxed) as usize % providers.len();
        providers
            .iter()
            .cycle()
            .skip(start)
            .take(providers.len())
            .min_by_key(|provider| {
                self.inflight
                    .get(&provider.id)
                    .map(|value| value.load(Ordering::Relaxed))
                    .unwrap_or_default()
            })
            .expect("non-empty provider list")
            .clone()
    }

    pub fn inflight(&self, provider_id: &str) -> usize {
        self.inflight
            .get(provider_id)
            .map(|value| value.load(Ordering::Relaxed))
            .unwrap_or_default()
    }

    fn remember_affinity(&self, key: &str, provider_id: &str, now: i64, ttl: i64) {
        let hash = affinity_hash(key);
        self.affinities.insert(
            hash.clone(),
            AffinityEntry {
                provider_id: provider_id.to_owned(),
                expires_at: now + ttl,
                updated_at: now,
            },
        );
        self.dirty_affinities.insert(hash);
    }

    pub async fn hydrate(&self, pool: &sqlx::SqlitePool) -> Result<(), AppError> {
        self.reload_providers(pool).await?;
        let now = chrono::Utc::now().timestamp();
        let rows = sqlx::query("SELECT affinity_hash,provider_id,expires_at,updated_at FROM affinities WHERE expires_at>?")
            .bind(now)
            .fetch_all(pool)
            .await?;
        self.affinities.clear();
        for row in rows {
            self.affinities.insert(
                row.get(0),
                AffinityEntry {
                    provider_id: row.get(1),
                    expires_at: row.get(2),
                    updated_at: row.get(3),
                },
            );
        }
        Ok(())
    }

    pub async fn reload_providers(&self, pool: &sqlx::SqlitePool) -> Result<(), AppError> {
        let providers =
            sqlx::query_as::<_, Provider>("SELECT * FROM providers ORDER BY created_at,id")
                .fetch_all(pool)
                .await?;
        self.providers.store(Arc::new(providers));
        Ok(())
    }

    pub fn forget_provider(&self, provider_id: &str) {
        let mut providers = (**self.providers.load()).clone();
        providers.retain(|provider| provider.id != provider_id);
        self.providers.store(Arc::new(providers));
        self.inflight.remove(provider_id);
        self.provider_updates.remove(provider_id);

        let hashes = self
            .affinities
            .iter()
            .filter(|entry| entry.value().provider_id == provider_id)
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        for hash in hashes {
            let removed = self
                .affinities
                .remove_if(&hash, |_, entry| entry.provider_id == provider_id)
                .is_some();
            if removed {
                self.dirty_affinities.remove(&hash);
                if self.affinities.contains_key(&hash) {
                    self.dirty_affinities.insert(hash);
                }
            }
        }
    }

    pub fn start_maintenance(&self, pool: sqlx::SqlitePool) {
        let balancer = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                if let Err(error) = balancer.maintain(&pool).await {
                    tracing::error!(%error, "provider maintenance failed");
                }
            }
        });
    }

    async fn maintain(&self, pool: &sqlx::SqlitePool) -> Result<(), AppError> {
        let now = chrono::Utc::now().timestamp();
        let updates = self
            .provider_updates
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect::<Vec<_>>();
        let affinities = self
            .dirty_affinities
            .iter()
            .filter_map(|hash| {
                self.affinities
                    .get(hash.key())
                    .map(|entry| (hash.key().clone(), entry.clone()))
            })
            .collect::<Vec<_>>();
        let mut transaction = pool.begin().await?;
        for (id, update) in &updates {
            sqlx::query("UPDATE providers SET status=CASE WHEN manual_disabled=1 THEN 'disabled' ELSE ? END,cooldown_until=CASE WHEN manual_disabled=1 THEN NULL ELSE ? END,rate_limit_json=?,last_error=?,last_used_at=COALESCE(?,last_used_at),updated_at=? WHERE id=?")
                .bind(&update.status).bind(update.cooldown_until).bind(&update.rate_limit_json)
                .bind(&update.last_error).bind(update.last_used_at).bind(update.updated_at).bind(id)
                .execute(&mut *transaction).await?;
        }
        let mut persisted_affinities = Vec::with_capacity(affinities.len());
        for (hash, entry) in affinities {
            let persisted = sqlx::query("INSERT INTO affinities(affinity_hash,provider_id,expires_at,updated_at) SELECT ?,?,?,? FROM providers WHERE id=? ON CONFLICT(affinity_hash) DO UPDATE SET provider_id=excluded.provider_id,expires_at=excluded.expires_at,updated_at=excluded.updated_at")
                .bind(&hash).bind(&entry.provider_id).bind(entry.expires_at).bind(entry.updated_at)
                .bind(&entry.provider_id).execute(&mut *transaction).await?.rows_affected() > 0;
            persisted_affinities.push((hash, entry, persisted));
        }
        sqlx::query("UPDATE providers SET status='active',cooldown_until=NULL,last_error=NULL,updated_at=? WHERE manual_disabled=0 AND status='cooldown' AND cooldown_until<=?")
            .bind(now).bind(now).execute(&mut *transaction).await?;
        sqlx::query("DELETE FROM affinities WHERE expires_at<=?")
            .bind(now)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        for (id, update) in updates {
            if self
                .provider_updates
                .get(&id)
                .is_some_and(|current| *current == update)
            {
                self.provider_updates.remove(&id);
            }
        }
        for (hash, entry, persisted) in persisted_affinities {
            if self
                .affinities
                .get(&hash)
                .is_some_and(|current| *current == entry)
            {
                if !persisted {
                    self.affinities
                        .remove_if(&hash, |_, current| *current == entry);
                }
                self.dirty_affinities.remove(&hash);
                if self.affinities.contains_key(&hash) && !persisted {
                    self.dirty_affinities.insert(hash);
                }
            }
        }
        self.affinities.retain(|_, entry| entry.expires_at > now);
        self.recover_cached_providers(now);
        Ok(())
    }

    fn recover_cached_providers(&self, now: i64) {
        let mut providers = (**self.providers.load()).clone();
        for provider in &mut providers {
            if provider.manual_disabled == 0
                && provider.status == "cooldown"
                && provider.cooldown_until.is_some_and(|until| until <= now)
            {
                provider.status = "active".to_owned();
                provider.cooldown_until = None;
                provider.last_error = None;
                provider.updated_at = now;
            }
        }
        self.providers.store(Arc::new(providers));
    }

    fn observe(&self, provider_id: &str, update: ProviderUpdate) {
        let mut providers = (**self.providers.load()).clone();
        if let Some(provider) = providers
            .iter_mut()
            .find(|provider| provider.id == provider_id)
        {
            provider.status = if provider.manual_disabled == 1 {
                "disabled".to_owned()
            } else {
                update.status.clone()
            };
            provider.cooldown_until = (provider.manual_disabled == 0)
                .then_some(update.cooldown_until)
                .flatten();
            provider.rate_limit_json = Some(update.rate_limit_json.clone());
            provider.last_error = update.last_error.clone();
            provider.last_used_at = update.last_used_at.or(provider.last_used_at);
            provider.updated_at = update.updated_at;
        }
        self.providers.store(Arc::new(providers));
        self.provider_updates.insert(provider_id.to_owned(), update);
    }
}

fn provider_is_available(provider: &Provider, now: i64) -> bool {
    provider.manual_disabled == 0
        && (provider.status == "active"
            || (provider.status == "cooldown"
                && provider.cooldown_until.is_some_and(|until| until <= now)))
}

pub fn affinity_hash(key: &str) -> String {
    hex::encode(Sha256::digest(key.as_bytes()))
}

pub async fn track_response(
    state: &AppState,
    provider_id: &str,
    status: StatusCode,
    headers: &HeaderMap,
) -> Result<(), AppError> {
    let now = chrono::Utc::now().timestamp();
    let tracked = headers
        .iter()
        .filter_map(|(name, value)| {
            let name = name.as_str().to_ascii_lowercase();
            if name != "retry-after" && !name.starts_with("x-ratelimit-") {
                return None;
            }
            Some((
                name,
                serde_json::Value::String(value.to_str().ok()?.to_owned()),
            ))
        })
        .collect::<serde_json::Map<String, serde_json::Value>>();
    let rate_json = serde_json::Value::Object(tracked).to_string();
    let update = match status.as_u16() {
        401 | 403 => ProviderUpdate {
            status: "auth_error".to_owned(),
            cooldown_until: None,
            rate_limit_json: rate_json,
            last_error: Some(format!("upstream HTTP {}", status.as_u16())),
            last_used_at: Some(now),
            updated_at: now,
        },
        429 => {
            let cooldown = cooldown_until(headers, now);
            ProviderUpdate {
                status: "cooldown".to_owned(),
                cooldown_until: Some(cooldown),
                rate_limit_json: rate_json,
                last_error: Some("rate limited".to_owned()),
                last_used_at: Some(now),
                updated_at: now,
            }
        }
        _ => ProviderUpdate {
            status: "active".to_owned(),
            cooldown_until: None,
            rate_limit_json: rate_json,
            last_error: None,
            last_used_at: Some(now),
            updated_at: now,
        },
    };
    state.balancer.observe(provider_id, update);
    Ok(())
}

fn cooldown_until(headers: &HeaderMap, now: i64) -> i64 {
    headers
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .parse::<i64>()
                .ok()
                .map(|seconds| now + seconds.max(1))
                .or_else(|| {
                    httpdate::parse_http_date(value)
                        .ok()
                        .and_then(|time| time.duration_since(SystemTime::UNIX_EPOCH).ok())
                        .map(|duration| duration.as_secs() as i64)
                })
        })
        .or_else(|| {
            headers.iter().find_map(|(name, value)| {
                name.as_str()
                    .starts_with("x-ratelimit-reset")
                    .then(|| parse_reset(value.to_str().ok()?, now))
                    .flatten()
            })
        })
        .unwrap_or(now + 60)
}

fn parse_reset(value: &str, now: i64) -> Option<i64> {
    if let Ok(timestamp) = value.parse::<i64>() {
        return Some(if timestamp > 2_000_000_000 {
            timestamp / 1000
        } else if timestamp > now {
            timestamp
        } else {
            now + timestamp.max(1)
        });
    }
    let seconds = value.strip_suffix('s')?.parse::<f64>().ok()?;
    Some(now + Duration::from_secs_f64(seconds.max(1.0)).as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    #[test]
    fn retry_after_sets_cooldown() {
        let mut headers = HeaderMap::new();
        headers.insert("retry-after", HeaderValue::from_static("15"));
        assert_eq!(cooldown_until(&headers, 100), 115);
    }

    #[test]
    fn affinity_is_hashed_before_storage() {
        assert_ne!(affinity_hash("session-secret"), "session-secret");
    }

    #[tokio::test]
    async fn persistent_affinity_reuses_provider_and_cooldown_reallocates() {
        let state = crate::test_state("http://token.invalid").await;
        let now = chrono::Utc::now().timestamp();
        for (id, created) in [("provider-a", now), ("provider-b", now + 1)] {
            sqlx::query("INSERT INTO providers(id,name,account_id,access_token,refresh_token,status,created_at,updated_at) VALUES(?,?,?,?,?,'active',?,?)")
                .bind(id).bind(id).bind(format!("account-{id}"))
                .bind("access")
                .bind("refresh")
                .bind(created).bind(created).execute(&state.db).await.unwrap();
        }
        state.balancer.reload_providers(&state.db).await.unwrap();
        let first = state
            .balancer
            .select(&state, Some("session-1"), None)
            .await
            .unwrap();
        let first_id = first.provider.id.clone();
        drop(first);
        let sticky = state
            .balancer
            .select(&state, Some("session-1"), None)
            .await
            .unwrap();
        assert_eq!(sticky.provider.id, first_id);
        drop(sticky);
        sqlx::query("UPDATE providers SET status='cooldown',cooldown_until=? WHERE id=?")
            .bind(now + 60)
            .bind(&first_id)
            .execute(&state.db)
            .await
            .unwrap();
        state.balancer.reload_providers(&state.db).await.unwrap();
        let reallocated = state
            .balancer
            .select(&state, Some("session-1"), None)
            .await
            .unwrap();
        assert_ne!(reallocated.provider.id, first_id);
    }

    #[tokio::test]
    async fn deleted_provider_dirt_is_discarded_without_blocking_maintenance() {
        let pool = crate::db::connect_memory().await.unwrap();
        let balancer = Balancer::default();
        let now = chrono::Utc::now().timestamp();
        for id in ["deleted", "survivor"] {
            sqlx::query("INSERT INTO providers(id,name,account_id,access_token,refresh_token,status,created_at,updated_at) VALUES(?,?,?,?,?,'active',?,?)")
                .bind(id).bind(id).bind(id).bind("access").bind("refresh")
                .bind(now).bind(now).execute(&pool).await.unwrap();
        }
        balancer.reload_providers(&pool).await.unwrap();
        balancer.remember_affinity("before-delete", "deleted", now, 3_600);
        balancer.observe(
            "deleted",
            ProviderUpdate {
                status: "cooldown".to_owned(),
                cooldown_until: Some(now + 60),
                rate_limit_json: "before-delete".to_owned(),
                last_error: None,
                last_used_at: Some(now),
                updated_at: now,
            },
        );

        sqlx::query("DELETE FROM providers WHERE id='deleted'")
            .execute(&pool)
            .await
            .unwrap();
        balancer.forget_provider("deleted");
        assert!(balancer.affinities.is_empty());
        assert!(balancer.dirty_affinities.is_empty());
        assert!(!balancer.provider_updates.contains_key("deleted"));

        balancer.remember_affinity("concurrent-select", "deleted", now, 3_600);
        for (id, rate_limit_json) in [("deleted", "stale"), ("survivor", "committed")] {
            balancer.observe(
                id,
                ProviderUpdate {
                    status: "cooldown".to_owned(),
                    cooldown_until: Some(now + 60),
                    rate_limit_json: rate_limit_json.to_owned(),
                    last_error: None,
                    last_used_at: Some(now),
                    updated_at: now,
                },
            );
        }

        balancer.maintain(&pool).await.unwrap();
        let deleted_affinities: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM affinities WHERE provider_id='deleted'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(deleted_affinities, 0);
        assert!(balancer.affinities.is_empty());
        assert!(balancer.dirty_affinities.is_empty());
        assert!(balancer.provider_updates.is_empty());
        let survivor: (String, String) =
            sqlx::query_as("SELECT status,rate_limit_json FROM providers WHERE id='survivor'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(survivor, ("cooldown".to_owned(), "committed".to_owned()));
    }
}
