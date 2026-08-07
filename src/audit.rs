use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use arc_swap::ArcSwap;
use sqlx::{Sqlite, SqlitePool, Transaction};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

use crate::config::Config;

const QUEUE_CAPACITY: usize = 4_096;
const BATCH_CAPACITY: usize = 128;
const QUEUE_BYTE_CAPACITY: usize = 64 * 1024 * 1024;
pub const ARCHIVE_BODY_LIMIT: usize = 1024 * 1024;
const ARCHIVE_RESERVATION_BYTES: u32 = (ARCHIVE_BODY_LIMIT * 2 + 16 * 1024) as u32;
const RETRY_INITIAL_DELAY: Duration = Duration::from_millis(100);
const RETRY_MAX_DELAY: Duration = Duration::from_secs(5);

static DROPPED_EVENTS: AtomicU64 = AtomicU64::new(0);
static DROPPED_ARCHIVES: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
static WRITE_RETRIES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
pub(crate) fn write_retries() -> usize {
    WRITE_RETRIES.load(std::sync::atomic::Ordering::Relaxed)
}

#[cfg(test)]
pub(crate) fn dropped_events() -> u64 {
    DROPPED_EVENTS.load(Ordering::Relaxed)
}

#[derive(Debug)]
pub struct AuditEvent {
    pub id: String,
    pub request_id: String,
    pub thread_id: Option<String>,
    pub consumer_id: String,
    pub user_id: String,
    pub request_archive: bool,
    pub provider_id: Option<String>,
    pub affinity_hash: Option<String>,
    pub affinity_source: Option<String>,
    pub method: String,
    pub path: String,
    pub model: Option<String>,
    pub reasoning_effort: Option<String>,
    pub status: i64,
    pub upstream_http_version: Option<String>,
    pub first_byte_latency_ms: Option<i64>,
    pub request_bytes: i64,
    pub response_bytes: i64,
    pub request_transport_bytes: i64,
    pub response_transport_bytes: i64,
    pub downstream_accept_encoding: Option<String>,
    pub downstream_content_encoding: Option<String>,
    pub upstream_accept_encoding: Option<String>,
    pub upstream_content_encoding: Option<String>,
    pub latency_ms: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cached_tokens: i64,
    pub cost_usd_nanos: Option<i64>,
    pub error: Option<String>,
    pub client_ip: String,
    pub created_at: i64,
    pub request_headers_json: String,
    pub request_body: Vec<u8>,
    pub request_body_truncated: bool,
    pub upstream_request_headers_json: Option<String>,
    pub response_headers_json: Option<String>,
    pub response_body: Option<Vec<u8>>,
    pub response_body_truncated: bool,
}

#[derive(Clone)]
pub struct AuditWriter {
    sender: mpsc::Sender<QueuedAudit>,
    budget: Arc<Semaphore>,
}

pub(crate) struct AuditReservation {
    permit: mpsc::OwnedPermit<QueuedAudit>,
}

enum QueuedAudit {
    Event {
        event: Box<AuditEvent>,
        _archive_budget: Option<OwnedSemaphorePermit>,
    },
    ResponseTransport {
        id: String,
        bytes: i64,
        encoding: Option<String>,
        downstream_response_headers_json: Option<String>,
    },
}

impl AuditReservation {
    pub(crate) fn send(self, event: AuditEvent, archive_budget: Option<OwnedSemaphorePermit>) {
        self.permit.send(QueuedAudit::Event {
            event: Box::new(event),
            _archive_budget: archive_budget,
        });
    }
}

impl AuditWriter {
    pub fn new(pool: SqlitePool, config: Arc<ArcSwap<Config>>) -> Self {
        let (sender, receiver) = mpsc::channel(QUEUE_CAPACITY);
        tokio::spawn(run(pool.clone(), receiver));
        tokio::spawn(cleanup(pool, config));
        Self {
            sender,
            budget: Arc::new(Semaphore::new(QUEUE_BYTE_CAPACITY)),
        }
    }

    pub(crate) fn try_reserve(&self) -> Option<AuditReservation> {
        let permit = match self.sender.clone().try_reserve_owned() {
            Ok(permit) => permit,
            Err(_) => return dropped(),
        };
        Some(AuditReservation { permit })
    }

    pub(crate) fn try_reserve_archive(&self) -> Option<OwnedSemaphorePermit> {
        self.budget
            .clone()
            .try_acquire_many_owned(ARCHIVE_RESERVATION_BYTES)
            .ok()
            .or_else(dropped_archive)
    }

    pub(crate) fn record_response_transport(
        &self,
        id: String,
        bytes: i64,
        encoding: Option<String>,
        downstream_response_headers_json: Option<String>,
    ) {
        if self
            .sender
            .try_send(QueuedAudit::ResponseTransport {
                id,
                bytes,
                encoding,
                downstream_response_headers_json,
            })
            .is_err()
        {
            let _ = dropped::<()>();
        }
    }
}

fn dropped<T>() -> Option<T> {
    let count = DROPPED_EVENTS.fetch_add(1, Ordering::Relaxed) + 1;
    if count == 1 || count.is_power_of_two() {
        tracing::warn!(
            dropped_events = count,
            "audit queue is full; dropping request audit"
        );
    }
    None
}

fn dropped_archive<T>() -> Option<T> {
    let count = DROPPED_ARCHIVES.fetch_add(1, Ordering::Relaxed) + 1;
    if count == 1 || count.is_power_of_two() {
        tracing::warn!(
            dropped_archives = count,
            "audit archive memory budget is full; dropping request diagnostics"
        );
    }
    None
}

async fn run(pool: SqlitePool, mut receiver: mpsc::Receiver<QueuedAudit>) {
    while let Some(first) = receiver.recv().await {
        let mut batch = Vec::with_capacity(BATCH_CAPACITY);
        batch.push(first);
        tokio::time::sleep(Duration::from_millis(5)).await;
        while batch.len() < BATCH_CAPACITY {
            match receiver.try_recv() {
                Ok(event) => batch.push(event),
                Err(_) => break,
            }
        }
        let mut retry_delay = RETRY_INITIAL_DELAY;
        loop {
            match persist(&pool, &batch).await {
                Ok(()) => break,
                Err(error) => {
                    #[cfg(test)]
                    WRITE_RETRIES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tracing::error!(events = batch.len(), retry_ms = retry_delay.as_millis(), %error, "audit batch write failed; retrying");
                    tokio::time::sleep(retry_delay).await;
                    retry_delay = retry_delay.saturating_mul(2).min(RETRY_MAX_DELAY);
                }
            }
        }
    }
}

async fn persist(pool: &SqlitePool, batch: &[QueuedAudit]) -> Result<(), sqlx::Error> {
    let mut transaction = pool.begin().await?;
    let mut touched_keys = std::collections::HashSet::new();
    for queued in batch {
        match queued {
            QueuedAudit::Event { event, .. } => {
                insert(&mut transaction, event).await?;
                touched_keys.insert(event.consumer_id.as_str());
            }
            QueuedAudit::ResponseTransport {
                id,
                bytes,
                encoding,
                downstream_response_headers_json,
            } => {
                sqlx::query("UPDATE api_calls SET response_transport_bytes=?,downstream_content_encoding=? WHERE id=?")
                    .bind(bytes)
                    .bind(encoding)
                    .bind(id)
                    .execute(&mut *transaction)
                    .await?;
                if let Some(headers) = downstream_response_headers_json {
                    sqlx::query("UPDATE request_archives SET downstream_response_headers_json=? WHERE api_call_id=?")
                        .bind(headers)
                        .bind(id)
                        .execute(&mut *transaction)
                        .await?;
                }
            }
        }
    }
    let used_at = chrono::Utc::now().timestamp();
    for consumer_id in touched_keys {
        sqlx::query("UPDATE consumers SET last_used_at=? WHERE id=?")
            .bind(used_at)
            .bind(consumer_id)
            .execute(&mut *transaction)
            .await?;
    }
    transaction.commit().await
}

async fn insert(
    transaction: &mut Transaction<'_, Sqlite>,
    event: &AuditEvent,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO api_calls(id,request_id,thread_id,consumer_id,user_id,provider_id,affinity_hash,affinity_source,method,path,model,reasoning_effort,status,first_byte_latency_ms,request_bytes,response_bytes,request_transport_bytes,response_transport_bytes,downstream_accept_encoding,downstream_content_encoding,upstream_accept_encoding,upstream_content_encoding,latency_ms,input_tokens,output_tokens,cached_tokens,cost_usd_nanos,error,client_ip,created_at,upstream_http_version) VALUES(?,?,?,?,?,(SELECT id FROM providers WHERE id=?),?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
        .bind(&event.id)
        .bind(&event.request_id)
        .bind(&event.thread_id)
        .bind(&event.consumer_id)
        .bind(&event.user_id)
        .bind(&event.provider_id)
        .bind(&event.affinity_hash)
        .bind(&event.affinity_source)
        .bind(&event.method)
        .bind(&event.path)
        .bind(&event.model)
        .bind(&event.reasoning_effort)
        .bind(event.status)
        .bind(event.first_byte_latency_ms)
        .bind(event.request_bytes)
        .bind(event.response_bytes)
        .bind(event.request_transport_bytes)
        .bind(event.response_transport_bytes)
        .bind(&event.downstream_accept_encoding)
        .bind(&event.downstream_content_encoding)
        .bind(&event.upstream_accept_encoding)
        .bind(&event.upstream_content_encoding)
        .bind(event.latency_ms)
        .bind(event.input_tokens)
        .bind(event.output_tokens)
        .bind(event.cached_tokens)
        .bind(event.cost_usd_nanos)
        .bind(&event.error)
        .bind(&event.client_ip)
        .bind(event.created_at)
        .bind(&event.upstream_http_version)
        .execute(&mut **transaction)
        .await?;
    if event.request_archive {
        sqlx::query("INSERT INTO request_archives(api_call_id,request_headers_json,upstream_request_headers_json,request_body,request_body_truncated,response_headers_json,downstream_response_headers_json,response_body,response_body_truncated,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
            .bind(&event.id)
            .bind(&event.request_headers_json)
            .bind(&event.upstream_request_headers_json)
            .bind(&event.request_body)
            .bind(event.request_body_truncated)
            .bind(&event.response_headers_json)
            .bind(Option::<String>::None)
            .bind(&event.response_body)
            .bind(event.response_body_truncated)
            .bind(event.created_at)
            .execute(&mut **transaction)
            .await?;
    }
    Ok(())
}

async fn cleanup(pool: SqlitePool, config: Arc<ArcSwap<Config>>) {
    let mut interval = tokio::time::interval(Duration::from_secs(60 * 60));
    loop {
        interval.tick().await;
        if let Err(error) = delete_expired(
            &pool,
            config.load().request_archive_retention_days,
            chrono::Utc::now().timestamp(),
        )
        .await
        {
            tracing::error!(%error, "request archive cleanup failed");
        }
    }
}

async fn delete_expired(
    pool: &SqlitePool,
    retention_days: i64,
    now: i64,
) -> Result<u64, sqlx::Error> {
    let cutoff = now - retention_days * 24 * 60 * 60;
    Ok(
        sqlx::query("DELETE FROM request_archives WHERE created_at<?")
            .bind(cutoff)
            .execute(pool)
            .await?
            .rows_affected(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn retention_cleanup_removes_only_expired_diagnostics() {
        let pool = crate::db::connect_memory().await.unwrap();
        sqlx::query("INSERT INTO users(id,role,created_at) VALUES('user','user',0)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO consumers(id,user_id,name,prefix,secret_hash,created_at) VALUES('key','user','key','sk-test','hash',0)")
            .execute(&pool)
            .await
            .unwrap();
        for (id, created_at) in [("expired", 0_i64), ("retained", 200_000_i64)] {
            sqlx::query("INSERT INTO api_calls(id,request_id,consumer_id,user_id,method,path,status,latency_ms,created_at) VALUES(?,?, 'key','user','POST','/v1/responses',200,1,?)")
                .bind(id)
                .bind(id)
                .bind(created_at)
                .execute(&pool)
                .await
                .unwrap();
            sqlx::query("INSERT INTO request_archives(api_call_id,request_headers_json,request_body,request_body_truncated,response_body_truncated,created_at) VALUES(?,'[]',X'',0,0,?)")
                .bind(id)
                .bind(created_at)
                .execute(&pool)
                .await
                .unwrap();
        }

        assert_eq!(delete_expired(&pool, 1, 200_000).await.unwrap(), 1);
        let ids: Vec<String> = sqlx::query_scalar("SELECT api_call_id FROM request_archives")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(ids, vec!["retained"]);
    }
}
