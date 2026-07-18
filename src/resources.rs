use std::{
    io,
    path::{Path, PathBuf},
    time::Instant,
};

use serde::Serialize;
use sysinfo::{CpuRefreshKind, Disks, Networks, System};

#[derive(Debug, Serialize)]
pub struct SystemResourcesSnapshot {
    pub sampled_at: i64,
    pub sample_interval_ms: u64,
    pub cpu: CpuSnapshot,
    pub memory: MemorySnapshot,
    pub network: NetworkSnapshot,
    pub disk: Option<DiskSnapshot>,
    pub sqlite: SqliteSnapshot,
}

#[derive(Debug, Serialize)]
pub struct CpuSnapshot {
    pub usage_percent: f32,
    pub load_1m: f64,
    pub logical_cpus: usize,
}

#[derive(Debug, Serialize)]
pub struct MemorySnapshot {
    pub used_bytes: u64,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub usage_percent: f64,
    pub swap_used_bytes: u64,
    pub swap_total_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct NetworkSnapshot {
    pub receive_bytes_per_second: u64,
    pub transmit_bytes_per_second: u64,
    pub interfaces: usize,
}

#[derive(Debug, Serialize)]
pub struct DiskSnapshot {
    pub mount_point: String,
    pub used_bytes: u64,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub usage_percent: f64,
}

#[derive(Debug, Serialize)]
pub struct SqliteSnapshot {
    pub main_bytes: u64,
    pub wal_bytes: u64,
    pub shm_bytes: u64,
    pub total_bytes: u64,
}

pub struct ResourceMonitor {
    database_path: PathBuf,
    system: System,
    disks: Disks,
    networks: Networks,
    last_sample: Instant,
}

impl ResourceMonitor {
    pub fn new(database_path: PathBuf) -> Self {
        let mut system = System::new();
        system.refresh_memory();
        system.refresh_cpu_list(CpuRefreshKind::nothing().with_cpu_usage());
        Self {
            database_path,
            system,
            disks: Disks::new_with_refreshed_list(),
            networks: Networks::new_with_refreshed_list(),
            last_sample: Instant::now(),
        }
    }

    pub fn sample(&mut self) -> io::Result<SystemResourcesSnapshot> {
        self.system.refresh_cpu_usage();
        self.system.refresh_memory();
        self.disks.refresh(true);
        self.networks.refresh(true);

        let now = Instant::now();
        let elapsed = now.duration_since(self.last_sample);
        self.last_sample = now;
        let sample_seconds = elapsed
            .max(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL)
            .as_secs_f64();
        let received = self
            .networks
            .values()
            .map(sysinfo::NetworkData::received)
            .sum::<u64>();
        let transmitted = self
            .networks
            .values()
            .map(sysinfo::NetworkData::transmitted)
            .sum::<u64>();
        let memory_used = self.system.used_memory();
        let memory_total = self.system.total_memory();
        let sqlite = sqlite_usage(&self.database_path)?;

        Ok(SystemResourcesSnapshot {
            sampled_at: chrono::Utc::now().timestamp(),
            sample_interval_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            cpu: CpuSnapshot {
                usage_percent: self.system.global_cpu_usage(),
                load_1m: System::load_average().one,
                logical_cpus: self.system.cpus().len(),
            },
            memory: MemorySnapshot {
                used_bytes: memory_used,
                total_bytes: memory_total,
                available_bytes: self.system.available_memory(),
                usage_percent: percentage(memory_used, memory_total),
                swap_used_bytes: self.system.used_swap(),
                swap_total_bytes: self.system.total_swap(),
            },
            network: NetworkSnapshot {
                receive_bytes_per_second: rate(received, sample_seconds),
                transmit_bytes_per_second: rate(transmitted, sample_seconds),
                interfaces: self.networks.len(),
            },
            disk: disk_usage(&self.disks, &self.database_path),
            sqlite,
        })
    }
}

fn disk_usage(disks: &Disks, database_path: &Path) -> Option<DiskSnapshot> {
    let disk = disks
        .list()
        .iter()
        .filter(|disk| database_path.starts_with(disk.mount_point()))
        .max_by_key(|disk| disk.mount_point().components().count())?;
    let total = disk.total_space();
    let available = disk.available_space();
    let used = total.saturating_sub(available);
    Some(DiskSnapshot {
        mount_point: disk.mount_point().to_string_lossy().into_owned(),
        used_bytes: used,
        total_bytes: total,
        available_bytes: available,
        usage_percent: percentage(used, total),
    })
}

fn sqlite_usage(database_path: &Path) -> io::Result<SqliteSnapshot> {
    let main_bytes = file_size(database_path)?;
    let wal_bytes = file_size(&with_suffix(database_path, "-wal"))?;
    let shm_bytes = file_size(&with_suffix(database_path, "-shm"))?;
    Ok(SqliteSnapshot {
        main_bytes,
        wal_bytes,
        shm_bytes,
        total_bytes: main_bytes
            .saturating_add(wal_bytes)
            .saturating_add(shm_bytes),
    })
}

fn file_size(path: &Path) -> io::Result<u64> {
    match std::fs::metadata(path) {
        Ok(metadata) => Ok(metadata.len()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error),
    }
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(suffix);
    value.into()
}

fn percentage(used: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        used as f64 / total as f64 * 100.0
    }
}

fn rate(bytes: u64, seconds: f64) -> u64 {
    (bytes as f64 / seconds).round() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_usage_includes_wal_and_shared_memory_files() {
        let directory =
            std::env::temp_dir().join(format!("openai-lb-resource-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let database = directory.join("openai-lb.sqlite3");
        std::fs::write(&database, [0_u8; 11]).unwrap();
        std::fs::write(with_suffix(&database, "-wal"), [0_u8; 7]).unwrap();
        std::fs::write(with_suffix(&database, "-shm"), [0_u8; 3]).unwrap();

        let usage = sqlite_usage(&database).unwrap();

        assert_eq!(usage.main_bytes, 11);
        assert_eq!(usage.wal_bytes, 7);
        assert_eq!(usage.shm_bytes, 3);
        assert_eq!(usage.total_bytes, 21);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn missing_wal_and_shared_memory_files_count_as_zero() {
        let database = std::env::temp_dir().join(format!(
            "openai-lb-resource-test-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&database, [0_u8; 5]).unwrap();

        let usage = sqlite_usage(&database).unwrap();

        assert_eq!(usage.main_bytes, 5);
        assert_eq!(usage.wal_bytes, 0);
        assert_eq!(usage.shm_bytes, 0);
        assert_eq!(usage.total_bytes, 5);
        std::fs::remove_file(database).unwrap();
    }

    #[test]
    fn monitor_samples_host_resources_without_a_physical_database() {
        let mut monitor = ResourceMonitor::new(PathBuf::from(":memory:"));
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);

        let snapshot = monitor.sample().unwrap();

        assert!(snapshot.cpu.logical_cpus > 0);
        assert!(snapshot.memory.total_bytes > 0);
        assert_eq!(snapshot.sqlite.total_bytes, 0);
        assert!(snapshot.sampled_at > 0);
    }
}
