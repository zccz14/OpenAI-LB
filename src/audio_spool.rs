use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use axum::body::{Body, Bytes};
use futures_util::StreamExt;
use tokio::{
    fs::{self, OpenOptions},
    io::{AsyncReadExt, AsyncWriteExt},
};
use uuid::Uuid;

use crate::AppError;

const DIRECTORY: &str = "audio-retry";
const MAX_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
// Delete one scan early so an orphan never reaches the 24-hour maximum between scans.
const RETENTION: Duration = MAX_RETENTION.saturating_sub(CLEANUP_INTERVAL);
const READ_BUFFER_SIZE: usize = 64 * 1024;

pub(crate) struct AudioSpool {
    path: PathBuf,
    pub preview: Vec<u8>,
    pub preview_truncated: bool,
    pub bytes: i64,
}

impl AudioSpool {
    pub(crate) async fn create(
        data_dir: &Path,
        body: Body,
        preview_limit: usize,
    ) -> Result<Self, AppError> {
        let directory = ensure_directory(data_dir).await?;
        let path = directory.join(format!("{}.upload", Uuid::new_v4()));
        let mut spool = Self {
            path,
            preview: Vec::new(),
            preview_truncated: false,
            bytes: 0,
        };
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&spool.path)
            .await?;
        let mut stream = body.into_data_stream();
        while let Some(item) = stream.next().await {
            let chunk = item.map_err(|error| {
                tracing::warn!(%error, "audio upload stream failed");
                AppError::bad_request("failed to read audio request body")
            })?;
            file.write_all(&chunk).await?;
            spool.bytes += chunk.len() as i64;
            let remaining = preview_limit.saturating_sub(spool.preview.len());
            let copied = remaining.min(chunk.len());
            spool.preview.extend_from_slice(&chunk[..copied]);
            spool.preview_truncated |= copied < chunk.len();
        }
        file.flush().await?;
        Ok(spool)
    }

    pub(crate) async fn body(&self) -> Result<reqwest::Body, AppError> {
        let mut file = fs::File::open(&self.path).await?;
        let stream = async_stream::stream! {
            let mut buffer = vec![0_u8; READ_BUFFER_SIZE];
            loop {
                match file.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(read) => yield Ok::<Bytes, std::io::Error>(Bytes::copy_from_slice(&buffer[..read])),
                    Err(error) => {
                        yield Err::<Bytes, std::io::Error>(error);
                        break;
                    }
                }
            }
        };
        Ok(reqwest::Body::wrap_stream(stream))
    }
}

impl Drop for AudioSpool {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_file(&self.path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(path = %self.path.display(), %error, "failed to remove audio retry file");
        }
    }
}

#[cfg_attr(test, allow(dead_code))]
pub(crate) fn start_cleanup(data_dir: PathBuf) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
        loop {
            interval.tick().await;
            if let Err(error) = cleanup(&data_dir, SystemTime::now()).await {
                tracing::error!(%error, "audio retry file cleanup failed");
            }
        }
    });
}

async fn ensure_directory(data_dir: &Path) -> Result<PathBuf, AppError> {
    let directory = directory(data_dir);
    fs::create_dir_all(&directory).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).await?;
    }
    Ok(directory)
}

pub(crate) fn directory(data_dir: &Path) -> PathBuf {
    data_dir.join(DIRECTORY)
}

async fn cleanup(data_dir: &Path, now: SystemTime) -> Result<(), AppError> {
    let directory = ensure_directory(data_dir).await?;
    let mut entries = fs::read_dir(directory).await?;
    while let Some(entry) = entries.next_entry().await? {
        if entry.path().extension().and_then(|value| value.to_str()) != Some("upload") {
            continue;
        }
        let metadata = entry.metadata().await?;
        if metadata.is_file()
            && now.duration_since(metadata.modified()?).unwrap_or_default() >= RETENTION
        {
            fs::remove_file(entry.path()).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cleanup_removes_files_before_the_24_hour_bound() {
        let data_dir = std::env::temp_dir().join(format!("openai-lb-spool-{}", Uuid::new_v4()));
        let spool_dir = ensure_directory(&data_dir).await.unwrap();
        let expired = spool_dir.join("expired.upload");
        let retained = spool_dir.join("retained.upload");
        fs::write(&expired, b"expired").await.unwrap();
        fs::write(&retained, b"retained").await.unwrap();
        let now = SystemTime::now();
        std::fs::File::open(&expired)
            .unwrap()
            .set_times(
                std::fs::FileTimes::new().set_modified(now - RETENTION - Duration::from_secs(1)),
            )
            .unwrap();
        std::fs::File::open(&retained)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(now))
            .unwrap();

        cleanup(&data_dir, now).await.unwrap();

        assert!(!expired.exists());
        assert!(retained.exists());
        fs::remove_dir_all(data_dir).await.unwrap();
    }
}
