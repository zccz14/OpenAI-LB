use std::{
    fs::{self, OpenOptions},
    io::{ErrorKind, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use rand::RngCore;
use sqlx::{Row, SqlitePool};

pub const DEFAULT_LISTEN: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080);

#[derive(Clone, Debug)]
pub struct BootstrapConfig {
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    pub database_path: PathBuf,
    pub encryption_key: [u8; 32],
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
        let encryption_key = load_or_create_master_key(&data_dir.join("master.key"))?;
        Ok(Self {
            listen,
            database_path: data_dir.join("openai-lb.sqlite3"),
            data_dir,
            encryption_key,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    pub database_path: PathBuf,
    pub encryption_key: [u8; 32],
    pub setup_complete: bool,
    pub auth_issuer: Option<String>,
    pub auth_audience: Option<String>,
    pub upstream_base: String,
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
            encryption_key: bootstrap.encryption_key,
            setup_complete: value("setup_complete")?.parse()?,
            auth_issuer: optional("auth_issuer")?,
            auth_audience: optional("auth_audience")?,
            upstream_base: value("upstream_base")?.trim_end_matches('/').to_owned(),
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

fn load_or_create_master_key(path: &Path) -> Result<[u8; 32]> {
    match create_master_key(path) {
        Ok(key) => Ok(key),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => read_master_key(path),
        Err(error) => Err(error).with_context(|| format!("failed to create {}", path.display())),
    }
}

fn create_master_key(path: &Path) -> std::io::Result<[u8; 32]> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    let mut key = [0_u8; 32];
    rand::rng().fill_bytes(&mut key);
    file.write_all(&key)?;
    file.sync_all()?;
    Ok(key)
}

fn read_master_key(path: &Path) -> Result<[u8; 32]> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        bail!("master key path is not a regular file: {}", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.mode() & 0o077 != 0 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
    }
    let mut bytes = Vec::with_capacity(32);
    OpenOptions::new()
        .read(true)
        .open(path)?
        .read_to_end(&mut bytes)?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("master key must contain exactly 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_key_is_created_once_with_private_permissions() {
        let dir = std::env::temp_dir().join(format!("openai-lb-config-{}", uuid::Uuid::new_v4()));
        let first = BootstrapConfig::in_data_dir(dir.clone(), DEFAULT_LISTEN).unwrap();
        let second = BootstrapConfig::in_data_dir(dir.clone(), DEFAULT_LISTEN).unwrap();
        assert_eq!(first.encryption_key, second.encryption_key);
        assert_eq!(first.database_path, dir.join("openai-lb.sqlite3"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(dir.join("master.key"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
