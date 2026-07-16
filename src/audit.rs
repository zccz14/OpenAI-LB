use std::time::Duration;

use sqlx::{Sqlite, SqlitePool, Transaction};
use tokio::sync::mpsc;

const QUEUE_CAPACITY: usize = 4_096;
const BATCH_CAPACITY: usize = 128;

#[derive(Debug)]
pub struct AuditEvent {
    pub id: String,
    pub request_id: String,
    pub api_key_id: String,
    pub user_id: String,
    pub channel_id: Option<String>,
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
}

#[derive(Clone)]
pub struct AuditWriter {
    sender: mpsc::Sender<AuditEvent>,
}

impl AuditWriter {
    pub fn new(pool: SqlitePool) -> Self {
        let (sender, receiver) = mpsc::channel(QUEUE_CAPACITY);
        tokio::spawn(run(pool, receiver));
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
        touched_keys.insert(event.api_key_id.as_str());
    }
    let used_at = chrono::Utc::now().timestamp();
    for key_id in touched_keys {
        sqlx::query("UPDATE api_keys SET last_used_at=? WHERE id=?")
            .bind(used_at)
            .bind(key_id)
            .execute(&mut *transaction)
            .await?;
    }
    transaction.commit().await
}

async fn insert(
    transaction: &mut Transaction<'_, Sqlite>,
    event: &AuditEvent,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO api_calls(id,request_id,api_key_id,user_id,channel_id,method,path,model,status,latency_ms,input_tokens,output_tokens,cached_tokens,error,client_ip,created_at) VALUES(?,?,?,?,(SELECT id FROM channels WHERE id=?),?,?,?,?,?,?,?,?,?,?,?)")
        .bind(&event.id)
        .bind(&event.request_id)
        .bind(&event.api_key_id)
        .bind(&event.user_id)
        .bind(&event.channel_id)
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
    Ok(())
}
