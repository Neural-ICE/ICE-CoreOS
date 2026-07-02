//! Data-volume disk usage via `df`.

use std::process::{Command, Stdio};

use crate::paths;

/// Usage of the appliance data volume, in bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct DiskUsage {
    pub used_bytes: u64,
    pub total_bytes: u64,
}

impl DiskUsage {
    pub fn used_gb(&self) -> f64 {
        self.used_bytes as f64 / 1024.0 / 1024.0 / 1024.0
    }

    pub fn total_gb(&self) -> f64 {
        self.total_bytes as f64 / 1024.0 / 1024.0 / 1024.0
    }

    pub fn percent(&self) -> u8 {
        if self.total_bytes == 0 {
            return 0;
        }
        ((self.used_bytes as f64 / self.total_bytes as f64) * 100.0).min(100.0) as u8
    }
}

/// Read used/total bytes for the data volume. Missing mount or `df`
/// failure yields a zeroed `DiskUsage` rather than panicking.
pub fn read_data_volume_usage() -> DiskUsage {
    let output = match Command::new("df")
        .args(["-B1", paths::DATA_VOLUME])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return DiskUsage::default(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = match stdout.lines().nth(1) {
        Some(l) => l,
        None => return DiskUsage::default(),
    };

    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 3 {
        return DiskUsage::default();
    }

    let total_bytes = fields[1].parse().unwrap_or(0);
    let used_bytes = fields[2].parse().unwrap_or(0);

    DiskUsage {
        used_bytes,
        total_bytes,
    }
}
