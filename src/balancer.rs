use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};

use dashmap::DashMap;
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
        sqlx::query("UPDATE channels SET status='active',cooldown_until=NULL,last_error=NULL,updated_at=? WHERE manual_disabled=0 AND status='cooldown' AND cooldown_until<=?")
            .bind(now).bind(now).execute(&state.db).await?;
        sqlx::query("DELETE FROM affinities WHERE expires_at<=?")
            .bind(now)
            .execute(&state.db)
            .await?;
        let channels = sqlx::query_as::<_, Channel>("SELECT * FROM channels WHERE manual_disabled=0 AND status='active' AND (cooldown_until IS NULL OR cooldown_until<=?) ORDER BY created_at,id")
            .bind(now).fetch_all(&state.db).await?;
        let eligible: Vec<Channel> = channels
            .into_iter()
            .filter(|item| excluded != Some(item.id.as_str()))
            .collect();
        if eligible.is_empty() {
            return Err(AppError::unavailable("no available CodeX channel"));
        }
        let chosen = match affinity {
            Some(key) => self.affinity_channel(state, key, &eligible, now).await?,
            None => None,
        }
        .unwrap_or_else(|| self.least_inflight(&eligible));
        if let Some(key) = affinity {
            persist_affinity(state, key, &chosen.id, now).await?;
        }
        self.inflight
            .entry(chosen.id.clone())
            .or_default()
            .fetch_add(1, Ordering::Relaxed);
        Ok(Lease {
            access_token: decrypt(&state.config.encryption_key, &chosen.access_enc)?,
            refresh_token: decrypt(&state.config.encryption_key, &chosen.refresh_enc)?,
            channel: chosen,
            inflight: self.inflight.clone(),
        })
    }

    async fn affinity_channel(
        &self,
        state: &AppState,
        key: &str,
        eligible: &[Channel],
        now: i64,
    ) -> Result<Option<Channel>, AppError> {
        let hash = affinity_hash(key);
        let row =
            sqlx::query("SELECT channel_id FROM affinities WHERE affinity_hash=? AND expires_at>?")
                .bind(hash)
                .bind(now)
                .fetch_optional(&state.db)
                .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let id: String = row.get(0);
        Ok(eligible.iter().find(|channel| channel.id == id).cloned())
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
}

async fn persist_affinity(
    state: &AppState,
    key: &str,
    channel_id: &str,
    now: i64,
) -> Result<(), AppError> {
    sqlx::query("INSERT INTO affinities(affinity_hash,channel_id,expires_at,updated_at) VALUES(?,?,?,?) ON CONFLICT(affinity_hash) DO UPDATE SET channel_id=excluded.channel_id,expires_at=excluded.expires_at,updated_at=excluded.updated_at")
        .bind(affinity_hash(key)).bind(channel_id).bind(now + state.config.affinity_ttl_seconds).bind(now).execute(&state.db).await?;
    Ok(())
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
    match status.as_u16() {
        401 | 403 => {
            sqlx::query("UPDATE channels SET status='auth_error',last_error=?,rate_limit_json=?,updated_at=? WHERE id=?")
            .bind(format!("upstream HTTP {}", status.as_u16())).bind(rate_json).bind(now).bind(channel_id).execute(&state.db).await?;
        }
        429 => {
            let cooldown = cooldown_until(headers, now);
            sqlx::query("UPDATE channels SET status='cooldown',cooldown_until=?,last_error='rate limited',rate_limit_json=?,updated_at=? WHERE id=? AND manual_disabled=0")
                .bind(cooldown).bind(rate_json).bind(now).bind(channel_id).execute(&state.db).await?;
        }
        _ => {
            sqlx::query(
                "UPDATE channels SET rate_limit_json=?,last_used_at=?,updated_at=? WHERE id=?",
            )
            .bind(rate_json)
            .bind(now)
            .bind(now)
            .bind(channel_id)
            .execute(&state.db)
            .await?;
        }
    };
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
                .bind(crate::crypto::encrypt(&state.config.encryption_key, "access").unwrap())
                .bind(crate::crypto::encrypt(&state.config.encryption_key, "refresh").unwrap())
                .bind(created).bind(created).execute(&state.db).await.unwrap();
        }
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
        let reallocated = state
            .balancer
            .select(&state, Some("session-1"), None)
            .await
            .unwrap();
        assert_ne!(reallocated.channel.id, first_id);
    }
}
