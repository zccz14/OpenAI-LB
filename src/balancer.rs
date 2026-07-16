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

use crate::{AppError, AppState, crypto::decrypt};

#[derive(Clone, Debug, FromRow, Serialize)]
pub struct Channel {
    pub id: String,
    pub name: String,
    pub account_id: String,
    #[serde(skip_serializing)]
    pub access_enc: String,
    #[serde(skip_serializing)]
    pub refresh_enc: String,
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
    channels: Arc<ArcSwap<Vec<Channel>>>,
    affinities: Arc<DashMap<String, AffinityEntry>>,
    dirty_affinities: Arc<DashSet<String>>,
    channel_updates: Arc<DashMap<String, ChannelUpdate>>,
}

#[derive(Clone, PartialEq)]
struct AffinityEntry {
    channel_id: String,
    expires_at: i64,
    updated_at: i64,
}

#[derive(Clone, PartialEq)]
struct ChannelUpdate {
    status: String,
    cooldown_until: Option<i64>,
    rate_limit_json: String,
    last_error: Option<String>,
    last_used_at: Option<i64>,
    updated_at: i64,
}

pub struct Lease {
    pub channel: Channel,
    pub access_token: String,
    pub refresh_token: String,
    inflight: Arc<DashMap<String, AtomicUsize>>,
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(value) = self.inflight.get(&self.channel.id) {
            value.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl Default for Balancer {
    fn default() -> Self {
        Self {
            inflight: Arc::new(DashMap::new()),
            cursor: Arc::new(AtomicU64::new(0)),
            channels: Arc::new(ArcSwap::from_pointee(Vec::new())),
            affinities: Arc::new(DashMap::new()),
            dirty_affinities: Arc::new(DashSet::new()),
            channel_updates: Arc::new(DashMap::new()),
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
        let channels = self.channels.load();
        let eligible: Vec<Channel> = channels
            .iter()
            .filter(|item| channel_is_available(item, now))
            .filter(|item| excluded != Some(item.id.as_str()))
            .cloned()
            .collect();
        if eligible.is_empty() {
            return Err(AppError::unavailable("no available CodeX channel"));
        }
        let chosen = match affinity {
            Some(key) => self.affinity_channel(key, &eligible, now),
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
            access_token: decrypt(&state.config.load().encryption_key, &chosen.access_enc)?,
            refresh_token: decrypt(&state.config.load().encryption_key, &chosen.refresh_enc)?,
            channel: chosen,
            inflight: self.inflight.clone(),
        })
    }

    fn affinity_channel(&self, key: &str, eligible: &[Channel], now: i64) -> Option<Channel> {
        let hash = affinity_hash(key);
        let entry = self.affinities.get(&hash)?;
        (entry.expires_at > now)
            .then(|| {
                eligible
                    .iter()
                    .find(|channel| channel.id == entry.channel_id)
                    .cloned()
            })
            .flatten()
    }

    fn least_inflight(&self, channels: &[Channel]) -> Channel {
        let start = self.cursor.fetch_add(1, Ordering::Relaxed) as usize % channels.len();
        channels
            .iter()
            .cycle()
            .skip(start)
            .take(channels.len())
            .min_by_key(|channel| {
                self.inflight
                    .get(&channel.id)
                    .map(|value| value.load(Ordering::Relaxed))
                    .unwrap_or_default()
            })
            .expect("non-empty channel list")
            .clone()
    }

    pub fn inflight(&self, channel_id: &str) -> usize {
        self.inflight
            .get(channel_id)
            .map(|value| value.load(Ordering::Relaxed))
            .unwrap_or_default()
    }

    fn remember_affinity(&self, key: &str, channel_id: &str, now: i64, ttl: i64) {
        let hash = affinity_hash(key);
        self.affinities.insert(
            hash.clone(),
            AffinityEntry {
                channel_id: channel_id.to_owned(),
                expires_at: now + ttl,
                updated_at: now,
            },
        );
        self.dirty_affinities.insert(hash);
    }

    pub async fn hydrate(&self, pool: &sqlx::SqlitePool) -> Result<(), AppError> {
        self.reload_channels(pool).await?;
        let now = chrono::Utc::now().timestamp();
        let rows = sqlx::query("SELECT affinity_hash,channel_id,expires_at,updated_at FROM affinities WHERE expires_at>?")
            .bind(now)
            .fetch_all(pool)
            .await?;
        self.affinities.clear();
        for row in rows {
            self.affinities.insert(
                row.get(0),
                AffinityEntry {
                    channel_id: row.get(1),
                    expires_at: row.get(2),
                    updated_at: row.get(3),
                },
            );
        }
        Ok(())
    }

    pub async fn reload_channels(&self, pool: &sqlx::SqlitePool) -> Result<(), AppError> {
        let channels =
            sqlx::query_as::<_, Channel>("SELECT * FROM channels ORDER BY created_at,id")
                .fetch_all(pool)
                .await?;
        self.channels.store(Arc::new(channels));
        Ok(())
    }

    pub fn start_maintenance(&self, pool: sqlx::SqlitePool) {
        let balancer = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                if let Err(error) = balancer.maintain(&pool).await {
                    tracing::error!(%error, "channel maintenance failed");
                }
            }
        });
    }

    async fn maintain(&self, pool: &sqlx::SqlitePool) -> Result<(), AppError> {
        let now = chrono::Utc::now().timestamp();
        let updates = self
            .channel_updates
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
            sqlx::query("UPDATE channels SET status=CASE WHEN manual_disabled=1 THEN 'disabled' ELSE ? END,cooldown_until=CASE WHEN manual_disabled=1 THEN NULL ELSE ? END,rate_limit_json=?,last_error=?,last_used_at=COALESCE(?,last_used_at),updated_at=? WHERE id=?")
                .bind(&update.status).bind(update.cooldown_until).bind(&update.rate_limit_json)
                .bind(&update.last_error).bind(update.last_used_at).bind(update.updated_at).bind(id)
                .execute(&mut *transaction).await?;
        }
        for (hash, entry) in &affinities {
            sqlx::query("INSERT INTO affinities(affinity_hash,channel_id,expires_at,updated_at) VALUES(?,?,?,?) ON CONFLICT(affinity_hash) DO UPDATE SET channel_id=excluded.channel_id,expires_at=excluded.expires_at,updated_at=excluded.updated_at")
                .bind(hash).bind(&entry.channel_id).bind(entry.expires_at).bind(entry.updated_at)
                .execute(&mut *transaction).await?;
        }
        sqlx::query("UPDATE channels SET status='active',cooldown_until=NULL,last_error=NULL,updated_at=? WHERE manual_disabled=0 AND status='cooldown' AND cooldown_until<=?")
            .bind(now).bind(now).execute(&mut *transaction).await?;
        sqlx::query("DELETE FROM affinities WHERE expires_at<=?")
            .bind(now)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        for (id, update) in updates {
            if self
                .channel_updates
                .get(&id)
                .is_some_and(|current| *current == update)
            {
                self.channel_updates.remove(&id);
            }
        }
        for (hash, entry) in affinities {
            if self
                .affinities
                .get(&hash)
                .is_some_and(|current| *current == entry)
            {
                self.dirty_affinities.remove(&hash);
            }
        }
        self.affinities.retain(|_, entry| entry.expires_at > now);
        self.recover_cached_channels(now);
        Ok(())
    }

    fn recover_cached_channels(&self, now: i64) {
        let mut channels = (**self.channels.load()).clone();
        for channel in &mut channels {
            if channel.manual_disabled == 0
                && channel.status == "cooldown"
                && channel.cooldown_until.is_some_and(|until| until <= now)
            {
                channel.status = "active".to_owned();
                channel.cooldown_until = None;
                channel.last_error = None;
                channel.updated_at = now;
            }
        }
        self.channels.store(Arc::new(channels));
    }

    fn observe(&self, channel_id: &str, update: ChannelUpdate) {
        let mut channels = (**self.channels.load()).clone();
        if let Some(channel) = channels.iter_mut().find(|channel| channel.id == channel_id) {
            channel.status = if channel.manual_disabled == 1 {
                "disabled".to_owned()
            } else {
                update.status.clone()
            };
            channel.cooldown_until = (channel.manual_disabled == 0)
                .then_some(update.cooldown_until)
                .flatten();
            channel.rate_limit_json = Some(update.rate_limit_json.clone());
            channel.last_error = update.last_error.clone();
            channel.last_used_at = update.last_used_at.or(channel.last_used_at);
            channel.updated_at = update.updated_at;
        }
        self.channels.store(Arc::new(channels));
        self.channel_updates.insert(channel_id.to_owned(), update);
    }
}

fn channel_is_available(channel: &Channel, now: i64) -> bool {
    channel.manual_disabled == 0
        && (channel.status == "active"
            || (channel.status == "cooldown"
                && channel.cooldown_until.is_some_and(|until| until <= now)))
}

pub fn affinity_hash(key: &str) -> String {
    hex::encode(Sha256::digest(key.as_bytes()))
}

pub async fn track_response(
    state: &AppState,
    channel_id: &str,
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
        401 | 403 => ChannelUpdate {
            status: "auth_error".to_owned(),
            cooldown_until: None,
            rate_limit_json: rate_json,
            last_error: Some(format!("upstream HTTP {}", status.as_u16())),
            last_used_at: Some(now),
            updated_at: now,
        },
        429 => {
            let cooldown = cooldown_until(headers, now);
            ChannelUpdate {
                status: "cooldown".to_owned(),
                cooldown_until: Some(cooldown),
                rate_limit_json: rate_json,
                last_error: Some("rate limited".to_owned()),
                last_used_at: Some(now),
                updated_at: now,
            }
        }
        _ => ChannelUpdate {
            status: "active".to_owned(),
            cooldown_until: None,
            rate_limit_json: rate_json,
            last_error: None,
            last_used_at: Some(now),
            updated_at: now,
        },
    };
    state.balancer.observe(channel_id, update);
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
    async fn persistent_affinity_reuses_channel_and_cooldown_reallocates() {
        let state = crate::test_state("http://token.invalid").await;
        let now = chrono::Utc::now().timestamp();
        for (id, created) in [("channel-a", now), ("channel-b", now + 1)] {
            sqlx::query("INSERT INTO channels(id,name,account_id,access_enc,refresh_enc,status,created_at,updated_at) VALUES(?,?,?,?,?,'active',?,?)")
                .bind(id).bind(id).bind(format!("account-{id}"))
                .bind(crate::crypto::encrypt(&state.config.load().encryption_key, "access").unwrap())
                .bind(crate::crypto::encrypt(&state.config.load().encryption_key, "refresh").unwrap())
                .bind(created).bind(created).execute(&state.db).await.unwrap();
        }
        state.balancer.reload_channels(&state.db).await.unwrap();
        let first = state
            .balancer
            .select(&state, Some("session-1"), None)
            .await
            .unwrap();
        let first_id = first.channel.id.clone();
        drop(first);
        let sticky = state
            .balancer
            .select(&state, Some("session-1"), None)
            .await
            .unwrap();
        assert_eq!(sticky.channel.id, first_id);
        drop(sticky);
        sqlx::query("UPDATE channels SET status='cooldown',cooldown_until=? WHERE id=?")
            .bind(now + 60)
            .bind(&first_id)
            .execute(&state.db)
            .await
            .unwrap();
        state.balancer.reload_channels(&state.db).await.unwrap();
        let reallocated = state
            .balancer
            .select(&state, Some("session-1"), None)
            .await
            .unwrap();
        assert_ne!(reallocated.channel.id, first_id);
    }
}
