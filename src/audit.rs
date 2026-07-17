use std::{sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use sqlx::{Sqlite, SqlitePool, Transaction};
use tokio::sync::mpsc;

use crate::config::Config;

const QUEUE_CAPACITY: usize = 4_096;
const BATCH_CAPACITY: usize = 128;

#[cfg(test)]
static WRITE_RETRIES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
pub(crate) fn write_retries() -> usize {
    WRITE_RETRIES.load(std::sync::atomic::Ordering::Relaxed)
}

#[derive(Debug)]
pub struct AuditEvent {
    pub id: String,
    pub request_id: String,
    pub consumer_id: String,
    pub user_id: String,
    pub request_archive: bool,
    pub provider_id: Option<String>,
    pub affinity_hash: Option<String>,
    pub affinity_source: Option<String>,
    pub method: String,
    pub path: String,
    pub model: Option<String>,
    pub status: i64,
    pub latency_ms: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cached_tokens: i64,
    pub error: Option<String>,
    pub client_ip: String,
    pub created_at: i64,
    pub request_headers_json: String,
    pub request_body: Vec<u8>,
    pub request_body_truncated: bool,
    pub response_headers_json: Option<String>,
    pub response_body: Option<Vec<u8>>,
    pub response_body_truncated: bool,
}

#[derive(Clone)]
pub struct AuditWriter {
    sender: mpsc::Sender<AuditEvent>,
}

impl AuditWriter {
    pub fn new(pool: SqlitePool, config: Arc<ArcSwap<Config>>) -> Self {
        let (sender, receiver) = mpsc::channel(QUEUE_CAPACITY);
        tokio::spawn(run(pool.clone(), receiver));
        tokio::spawn(cleanup(pool, config));
        Self { sender }
    }

    pub async fn reserve(&self) -> Option<mpsc::OwnedPermit<AuditEvent>> {
        self.sender.clone().reserve_owned().await.ok()
    }
}

async fn run(pool: SqlitePool, mut receiver: mpsc::Receiver<AuditEvent>) {
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
        loop {
            match persist(&pool, &batch).await {
                Ok(()) => break,
                Err(error) => {
                    #[cfg(test)]
                    WRITE_RETRIES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tracing::error!(events = batch.len(), %error, "audit batch write failed; retrying");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
}

async fn persist(pool: &SqlitePool, batch: &[AuditEvent]) -> Result<(), sqlx::Error> {
    let mut transaction = pool.begin().await?;
    let mut touched_keys = std::collections::HashSet::new();
    for event in batch {
        insert(&mut transaction, event).await?;
        touched_keys.insert(event.consumer_id.as_str());
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
    sqlx::query("INSERT INTO api_calls(id,request_id,consumer_id,user_id,provider_id,affinity_hash,affinity_source,method,path,model,status,latency_ms,input_tokens,output_tokens,cached_tokens,error,client_ip,created_at) VALUES(?,?,?,?,(SELECT id FROM providers WHERE id=?),?,?,?,?,?,?,?,?,?,?,?,?,?)")
        .bind(&event.id)
        .bind(&event.request_id)
        .bind(&event.consumer_id)
        .bind(&event.user_id)
        .bind(&event.provider_id)
        .bind(&event.affinity_hash)
        .bind(&event.affinity_source)
        .bind(&event.method)
        .bind(&event.path)
        .bind(&event.model)
        .bind(event.status)
        .bind(event.latency_ms)
        .bind(event.input_tokens)
        .bind(event.output_tokens)
        .bind(event.cached_tokens)
        .bind(&event.error)
        .bind(&event.client_ip)
        .bind(event.created_at)
        .execute(&mut **transaction)
        .await?;
    if event.request_archive {
        sqlx::query("INSERT INTO request_archives(api_call_id,request_headers_json,request_body,request_body_truncated,response_headers_json,response_body,response_body_truncated,created_at) VALUES(?,?,?,?,?,?,?,?)")
            .bind(&event.id)
            .bind(&event.request_headers_json)
            .bind(&event.request_body)
            .bind(event.request_body_truncated)
            .bind(&event.response_headers_json)
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
