use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use anyhow::{Context, Result};
use sqlx::{Row, SqlitePool};

pub const DEFAULT_LISTEN: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080);

#[derive(Clone, Debug)]
pub struct BootstrapConfig {
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    pub database_path: PathBuf,
}

impl BootstrapConfig {
    pub fn load() -> Result<Self> {
        let home =
            dirs::home_dir().context("cannot determine the current user's home directory")?;
        Self::in_data_dir(home.join(".openai-lb"), DEFAULT_LISTEN)
    }

    pub fn in_data_dir(data_dir: PathBuf, listen: SocketAddr) -> Result<Self> {
        fs::create_dir_all(&data_dir)
            .with_context(|| format!("failed to create {}", data_dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self {
            listen,
            database_path: data_dir.join("openai-lb.sqlite3"),
            data_dir,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    pub database_path: PathBuf,
    pub setup_complete: bool,
    pub auth_issuer: Option<String>,
    pub auth_audience: Option<String>,
    pub upstream_base: String,
    pub upstream_openai_beta: Option<String>,
    pub image_host_model: String,
    pub oauth_authorize_url: String,
    pub oauth_token_url: String,
    pub oauth_redirect_uri: String,
    pub oauth_client_id: String,
    pub response_body_limit: usize,
    pub image_body_limit: usize,
    pub audio_body_limit: usize,
    pub affinity_ttl_seconds: i64,
    pub request_archive_retention_days: i64,
}

impl Config {
    pub async fn load(bootstrap: BootstrapConfig, pool: &SqlitePool) -> Result<Self> {
        let rows = sqlx::query("SELECT key,value FROM app_meta")
            .fetch_all(pool)
            .await?;
        let values = rows
            .into_iter()
            .map(|row| (row.get::<String, _>(0), row.get::<String, _>(1)))
            .collect::<std::collections::HashMap<_, _>>();
        let value = |key: &str| -> Result<&str> {
            values
                .get(key)
                .map(String::as_str)
                .with_context(|| format!("app_meta is missing {key}"))
        };
        let optional = |key: &str| -> Result<Option<String>> {
            Ok(match value(key)?.trim() {
                "" => None,
                configured => Some(configured.trim_end_matches('/').to_owned()),
            })
        };
        Ok(Self {
            listen: bootstrap.listen,
            data_dir: bootstrap.data_dir,
            database_path: bootstrap.database_path,
            setup_complete: value("setup_complete")?.parse()?,
            auth_issuer: optional("auth_issuer")?,
            auth_audience: optional("auth_audience")?,
            upstream_base: value("upstream_base")?.trim_end_matches('/').to_owned(),
            upstream_openai_beta: match value("upstream_openai_beta")?.trim() {
                "" => None,
                value => Some(value.to_owned()),
            },
            image_host_model: value("image_host_model")?.to_owned(),
            oauth_authorize_url: value("oauth_authorize_url")?.to_owned(),
            oauth_token_url: value("oauth_token_url")?.to_owned(),
            oauth_redirect_uri: value("oauth_redirect_uri")?.to_owned(),
            oauth_client_id: value("oauth_client_id")?.to_owned(),
            response_body_limit: value("response_body_limit")?.parse()?,
            image_body_limit: value("image_body_limit")?.parse()?,
            audio_body_limit: value("audio_body_limit")?.parse()?,
            affinity_ttl_seconds: value("affinity_ttl_seconds")?.parse()?,
            request_archive_retention_days: value("request_archive_retention_days")?.parse()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_directory_is_private_without_creating_a_master_key() {
        let dir = std::env::temp_dir().join(format!("openai-lb-config-{}", uuid::Uuid::new_v4()));
        let first = BootstrapConfig::in_data_dir(dir.clone(), DEFAULT_LISTEN).unwrap();
        let second = BootstrapConfig::in_data_dir(dir.clone(), DEFAULT_LISTEN).unwrap();
        assert_eq!(first.database_path, dir.join("openai-lb.sqlite3"));
        assert_eq!(second.database_path, dir.join("openai-lb.sqlite3"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        assert!(!dir.join("master.key").exists());
        fs::remove_dir_all(dir).unwrap();
    }
}
