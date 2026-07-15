use anyhow::Result;
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};

pub async fn connect(url: &str) -> Result<SqlitePool> {
    let connections = if url.contains(":memory:") { 1 } else { 16 };
    let pool = SqlitePoolOptions::new()
        .max_connections(connections)
        .connect(url)
        .await?;
    sqlx::query("PRAGMA journal_mode=WAL")
        .execute(&pool)
        .await?;
    sqlx::query("PRAGMA foreign_keys=ON").execute(&pool).await?;
    sqlx::query("PRAGMA busy_timeout=5000")
        .execute(&pool)
        .await?;
    migrate(&pool).await?;
    Ok(pool)
}

async fn migrate(pool: &SqlitePool) -> Result<()> {
    for statement in MIGRATIONS {
        sqlx::query(statement).execute(pool).await?;
    }
    migrate_api_calls_request_id(pool).await?;
    Ok(())
}

async fn migrate_api_calls_request_id(pool: &SqlitePool) -> Result<()> {
    let schema: Option<String> =
        sqlx::query_scalar("SELECT sql FROM sqlite_master WHERE type='table' AND name='api_calls'")
            .fetch_optional(pool)
            .await?;
    if !schema.is_some_and(|sql| sql.contains("request_id TEXT NOT NULL UNIQUE")) {
        return Ok(());
    }
    let mut connection = pool.acquire().await?;
    sqlx::query("PRAGMA foreign_keys=OFF")
        .execute(&mut *connection)
        .await?;
    sqlx::query("ALTER TABLE api_calls RENAME TO api_calls_legacy")
        .execute(&mut *connection)
        .await?;
    sqlx::query(API_CALLS_TABLE)
        .execute(&mut *connection)
        .await?;
    sqlx::query("INSERT INTO api_calls SELECT * FROM api_calls_legacy")
        .execute(&mut *connection)
        .await?;
    sqlx::query("DROP TABLE api_calls_legacy")
        .execute(&mut *connection)
        .await?;
    sqlx::query("CREATE INDEX api_calls_key_time_idx ON api_calls(api_key_id, created_at DESC)")
        .execute(&mut *connection)
        .await?;
    sqlx::query("CREATE INDEX api_calls_user_time_idx ON api_calls(user_id, created_at DESC)")
        .execute(&mut *connection)
        .await?;
    sqlx::query("PRAGMA foreign_keys=ON")
        .execute(&mut *connection)
        .await?;
    Ok(())
}

const API_CALLS_TABLE: &str = "CREATE TABLE api_calls (id TEXT PRIMARY KEY, request_id TEXT NOT NULL, api_key_id TEXT NOT NULL REFERENCES api_keys(id), user_id TEXT NOT NULL REFERENCES users(id), channel_id TEXT REFERENCES channels(id), method TEXT NOT NULL, path TEXT NOT NULL, model TEXT, status INTEGER NOT NULL, latency_ms INTEGER NOT NULL, input_tokens INTEGER NOT NULL DEFAULT 0, output_tokens INTEGER NOT NULL DEFAULT 0, cached_tokens INTEGER NOT NULL DEFAULT 0, error TEXT, client_ip TEXT, created_at INTEGER NOT NULL)";

const MIGRATIONS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT, display_name TEXT, role TEXT NOT NULL CHECK(role IN ('admin','user')), created_at INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS api_keys (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, name TEXT NOT NULL, prefix TEXT NOT NULL, secret_hash TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL, last_used_at INTEGER, revoked_at INTEGER)",
    "CREATE INDEX IF NOT EXISTS api_keys_user_idx ON api_keys(user_id, created_at DESC)",
    "CREATE TABLE IF NOT EXISTS channels (id TEXT PRIMARY KEY, name TEXT NOT NULL, account_id TEXT NOT NULL, access_enc TEXT NOT NULL, refresh_enc TEXT NOT NULL, expires_at INTEGER, status TEXT NOT NULL DEFAULT 'active', manual_disabled INTEGER NOT NULL DEFAULT 0, cooldown_until INTEGER, rate_limit_json TEXT, last_error TEXT, last_used_at INTEGER, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)",
    "CREATE INDEX IF NOT EXISTS channels_available_idx ON channels(manual_disabled, status, cooldown_until)",
    "CREATE TABLE IF NOT EXISTS oauth_flows (state_hash TEXT PRIMARY KEY, verifier_enc TEXT NOT NULL, created_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS affinities (affinity_hash TEXT PRIMARY KEY, channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)",
    "CREATE INDEX IF NOT EXISTS affinities_expiry_idx ON affinities(expires_at)",
    "CREATE TABLE IF NOT EXISTS api_calls (id TEXT PRIMARY KEY, request_id TEXT NOT NULL, api_key_id TEXT NOT NULL REFERENCES api_keys(id), user_id TEXT NOT NULL REFERENCES users(id), channel_id TEXT REFERENCES channels(id), method TEXT NOT NULL, path TEXT NOT NULL, model TEXT, status INTEGER NOT NULL, latency_ms INTEGER NOT NULL, input_tokens INTEGER NOT NULL DEFAULT 0, output_tokens INTEGER NOT NULL DEFAULT 0, cached_tokens INTEGER NOT NULL DEFAULT 0, error TEXT, client_ip TEXT, created_at INTEGER NOT NULL)",
    "CREATE INDEX IF NOT EXISTS api_calls_key_time_idx ON api_calls(api_key_id, created_at DESC)",
    "CREATE INDEX IF NOT EXISTS api_calls_user_time_idx ON api_calls(user_id, created_at DESC)",
    "CREATE TABLE IF NOT EXISTS admin_audit (id TEXT PRIMARY KEY, admin_user_id TEXT NOT NULL REFERENCES users(id), action TEXT NOT NULL, target_id TEXT, client_ip TEXT, created_at INTEGER NOT NULL)",
    "CREATE INDEX IF NOT EXISTS admin_audit_time_idx ON admin_audit(created_at DESC)",
];
