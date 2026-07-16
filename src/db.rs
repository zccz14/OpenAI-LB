use std::{path::Path, time::Duration};

use anyhow::{Context, Result, ensure};
use sqlx::{
    Acquire, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

pub async fn connect(path: &Path, encryption_key: &[u8; 32]) -> Result<SqlitePool> {
    let options = options(path, true)?;
    let pool = connect_with_options(options, 4, encryption_key).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(pool)
}

#[cfg(test)]
pub async fn connect_memory() -> Result<SqlitePool> {
    let options = "sqlite::memory:"
        .parse::<SqliteConnectOptions>()?
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));
    connect_with_options(options, 1, &[0_u8; 32]).await
}

#[cfg(test)]
pub async fn connect_test_file(path: &Path, encryption_key: &[u8; 32]) -> Result<SqlitePool> {
    let options = options(path, true)?;
    connect_with_options(options, 4, encryption_key).await
}

fn options(path: &Path, create: bool) -> Result<SqliteConnectOptions> {
    Ok(SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(create)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5))
        .synchronous(SqliteSynchronous::Normal))
}

async fn connect_with_options(
    options: SqliteConnectOptions,
    max_connections: u32,
    encryption_key: &[u8; 32],
) -> Result<SqlitePool> {
    let pool = SqlitePoolOptions::new()
        .max_connections(max_connections)
        .connect_with(options)
        .await?;
    let mut connection = pool.acquire().await?;
    sqlx::query("PRAGMA foreign_keys=OFF")
        .execute(&mut *connection)
        .await?;
    MIGRATOR.run(&mut *connection).await?;
    migrate_channel_tokens(&mut connection, encryption_key).await?;
    let foreign_key_violations: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM pragma_foreign_key_check")
            .fetch_one(&mut *connection)
            .await?;
    sqlx::query("PRAGMA foreign_keys=ON")
        .execute(&mut *connection)
        .await?;
    ensure!(
        foreign_key_violations == 0,
        "database migration left {foreign_key_violations} foreign key violation(s)"
    );
    drop(connection);
    Ok(pool)
}

async fn migrate_channel_tokens(
    connection: &mut sqlx::pool::PoolConnection<sqlx::Sqlite>,
    encryption_key: &[u8; 32],
) -> Result<()> {
    let plaintext: String =
        sqlx::query_scalar("SELECT value FROM app_meta WHERE key='channel_tokens_plaintext'")
            .fetch_one(&mut **connection)
            .await?;
    if plaintext == "true" {
        return Ok(());
    }

    let mut transaction = connection.begin().await?;
    let channels: Vec<(String, String, String)> =
        sqlx::query_as("SELECT id,access_token,refresh_token FROM channels")
            .fetch_all(&mut *transaction)
            .await?;
    for (id, access_token, refresh_token) in channels {
        let access_token = crate::crypto::decrypt(encryption_key, &access_token)
            .with_context(|| format!("failed to migrate access Token for channel {id}"))?;
        let refresh_token = crate::crypto::decrypt(encryption_key, &refresh_token)
            .with_context(|| format!("failed to migrate refresh Token for channel {id}"))?;
        sqlx::query("UPDATE channels SET access_token=?,refresh_token=? WHERE id=?")
            .bind(access_token)
            .bind(refresh_token)
            .bind(id)
            .execute(&mut *transaction)
            .await?;
    }
    sqlx::query("UPDATE app_meta SET value='true',updated_at=unixepoch() WHERE key='channel_tokens_plaintext'")
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use sqlx::Row;

    use super::*;

    #[tokio::test]
    async fn every_pooled_connection_has_required_pragmas() {
        let path =
            std::env::temp_dir().join(format!("openai-lb-db-{}.sqlite3", uuid::Uuid::new_v4()));
        let pool = connect_test_file(&path, &[0_u8; 32]).await.unwrap();
        let mut connections = Vec::new();
        for _ in 0..4 {
            connections.push(pool.acquire().await.unwrap());
        }
        for connection in &mut connections {
            let row = sqlx::query("SELECT (SELECT * FROM pragma_foreign_keys()), (SELECT timeout FROM pragma_busy_timeout()), (SELECT * FROM pragma_synchronous())")
                .fetch_one(&mut **connection)
                .await
                .unwrap();
            assert_eq!(row.get::<i64, _>(0), 1);
            assert_eq!(row.get::<i64, _>(1), 5000);
            assert_eq!(row.get::<i64, _>(2), 1);
        }
        drop(connections);
        pool.close().await;
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    #[tokio::test]
    async fn versioned_migrations_upgrade_the_legacy_user_role_schema() {
        let path = std::env::temp_dir().join(format!(
            "openai-lb-upgrade-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        let legacy = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(&path)
                    .create_if_missing(true),
            )
            .await
            .unwrap();
        let schema = [
            "CREATE TABLE users (id TEXT PRIMARY KEY,email TEXT,display_name TEXT,role TEXT NOT NULL CHECK(role IN ('admin','user')),created_at INTEGER NOT NULL)",
            "CREATE TABLE api_keys (id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,name TEXT NOT NULL,prefix TEXT NOT NULL,secret_hash TEXT NOT NULL UNIQUE,created_at INTEGER NOT NULL,last_used_at INTEGER,revoked_at INTEGER)",
            "CREATE TABLE channels (id TEXT PRIMARY KEY,name TEXT NOT NULL,account_id TEXT NOT NULL,access_enc TEXT NOT NULL,refresh_enc TEXT NOT NULL,expires_at INTEGER,status TEXT NOT NULL DEFAULT 'active',manual_disabled INTEGER NOT NULL DEFAULT 0,cooldown_until INTEGER,rate_limit_json TEXT,last_error TEXT,last_used_at INTEGER,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL)",
            "CREATE TABLE oauth_flows (state_hash TEXT PRIMARY KEY,verifier_enc TEXT NOT NULL,created_by TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires_at INTEGER NOT NULL)",
            "CREATE TABLE affinities (affinity_hash TEXT PRIMARY KEY,channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,expires_at INTEGER NOT NULL,updated_at INTEGER NOT NULL)",
            "CREATE TABLE api_calls (id TEXT PRIMARY KEY,request_id TEXT NOT NULL,api_key_id TEXT NOT NULL REFERENCES api_keys(id),user_id TEXT NOT NULL REFERENCES users(id),channel_id TEXT REFERENCES channels(id),method TEXT NOT NULL,path TEXT NOT NULL,model TEXT,status INTEGER NOT NULL,latency_ms INTEGER NOT NULL,input_tokens INTEGER NOT NULL DEFAULT 0,output_tokens INTEGER NOT NULL DEFAULT 0,cached_tokens INTEGER NOT NULL DEFAULT 0,error TEXT,client_ip TEXT,created_at INTEGER NOT NULL)",
            "CREATE TABLE admin_audit (id TEXT PRIMARY KEY,admin_user_id TEXT NOT NULL REFERENCES users(id),action TEXT NOT NULL,target_id TEXT,client_ip TEXT,created_at INTEGER NOT NULL)",
        ];
        for statement in schema {
            sqlx::query(statement).execute(&legacy).await.unwrap();
        }
        let encryption_key = [11_u8; 32];
        let fixtures = [
            "INSERT INTO users(id,email,role,created_at) VALUES('legacy-admin','admin@example.com','admin',1)",
            "INSERT INTO api_keys(id,user_id,name,prefix,secret_hash,created_at) VALUES('key','legacy-admin','legacy','sk-old','hash',2)",
            "INSERT INTO oauth_flows(state_hash,verifier_enc,created_by,expires_at) VALUES('flow','verifier','legacy-admin',100)",
            "INSERT INTO admin_audit(id,admin_user_id,action,created_at) VALUES('audit','legacy-admin','legacy.action',6)",
        ];
        for statement in fixtures {
            sqlx::query(statement).execute(&legacy).await.unwrap();
        }
        sqlx::query("INSERT INTO channels(id,name,account_id,access_enc,refresh_enc,created_at,updated_at) VALUES('channel','legacy','account',?,?,3,3)")
            .bind(crate::crypto::encrypt(&encryption_key, "access").unwrap())
            .bind(crate::crypto::encrypt(&encryption_key, "refresh").unwrap())
            .execute(&legacy)
            .await
            .unwrap();
        for statement in [
            "INSERT INTO affinities(affinity_hash,channel_id,expires_at,updated_at) VALUES('affinity','channel',100,4)",
            "INSERT INTO api_calls(id,request_id,api_key_id,user_id,channel_id,method,path,status,latency_ms,created_at) VALUES('call','request','key','legacy-admin','channel','POST','/v1/responses',200,5,5)",
        ] {
            sqlx::query(statement).execute(&legacy).await.unwrap();
        }
        legacy.close().await;

        let pool = connect_test_file(&path, &encryption_key).await.unwrap();
        let role: String = sqlx::query_scalar("SELECT role FROM users WHERE id='legacy-admin'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(role, "admin");
        for table in [
            "users",
            "api_keys",
            "channels",
            "oauth_flows",
            "affinities",
            "api_calls",
            "admin_audit",
        ] {
            let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(count, 1, "legacy row was lost from {table}");
        }
        let foreign_key_violations: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM pragma_foreign_key_check")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(foreign_key_violations, 0);
        let tokens: (String, String) =
            sqlx::query_as("SELECT access_token,refresh_token FROM channels WHERE id='channel'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(tokens, ("access".to_owned(), "refresh".to_owned()));
        sqlx::query("INSERT INTO users(id,role,created_at) VALUES('root','root',2)")
            .execute(&pool)
            .await
            .unwrap();
        let second_root =
            sqlx::query("INSERT INTO users(id,role,created_at) VALUES('root-2','root',3)")
                .execute(&pool)
                .await;
        assert!(second_root.is_err());
        pool.close().await;
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }
}
