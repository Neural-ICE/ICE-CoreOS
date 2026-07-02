//! GPU information from nvidia-smi

use std::process::{Command, Stdio};

/// GPU metrics. On the GB10 / DGX Spark, GPU memory is the same unified
/// pool as system RAM, not a separate bank — callers should label it
/// accordingly rather than presenting two independent memory pools.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GpuMetrics {
    pub name: String,
    pub memory_total_gb: u32,
    pub memory_used_gb: u32,
    pub memory_percent: u8,
    pub temperature: Option<u32>,
    pub power_draw: Option<u32>,
    pub utilization: Option<u8>,
}

impl GpuMetrics {
    /// Collect GPU metrics from nvidia-smi
    pub fn collect() -> Self {
        // Redirect stderr to null to prevent console pollution
        let output = match Command::new("nvidia-smi")
            .args([
                "--query-gpu=name,memory.total,memory.used,temperature.gpu,power.draw,utilization.gpu",
                "--format=csv,noheader,nounits"
            ])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
        {
            Ok(o) if o.status.success() => o,
            _ => return Self::default(),
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let line = stdout.trim();

        // Format: "NVIDIA GB10, 128000, 1234, 45, 120.5, 30"
        let parts: Vec<&str> = line.split(", ").collect();
        if parts.len() >= 3 {
            let name = parts[0].to_string();
            let mem_total_mib = parts[1].parse::<u64>().unwrap_or(0);
            let mem_used_mib = parts[2].parse::<u64>().unwrap_or(0);
            let temperature = parts.get(3).and_then(|s| s.parse().ok());
            let power_draw = parts
                .get(4)
                .and_then(|s| s.parse::<f32>().ok())
                .map(|p| p as u32);
            let utilization = parts.get(5).and_then(|s| s.parse().ok());

            let memory_total_gb = (mem_total_mib / 1024) as u32;
            let memory_used_gb = (mem_used_mib / 1024) as u32;
            let memory_percent = if mem_total_mib > 0 {
                ((mem_used_mib * 100) / mem_total_mib) as u8
            } else {
                0
            };

            return Self {
                name,
                memory_total_gb,
                memory_used_gb,
                memory_percent,
                temperature,
                power_draw,
                utilization,
            };
        }

        Self::default()
    }

    /// Format as a simple string (for backward compatibility)
    pub fn to_summary(&self) -> String {
        if self.name.is_empty() {
            return "No NVIDIA GPU detected".to_string();
        }

        let mut parts = vec![format!("{} ({}GB)", self.name, self.memory_total_gb)];

        if let Some(temp) = self.temperature {
            parts.push(format!("{}C", temp));
        }

        if let Some(util) = self.utilization {
            parts.push(format!("{}%", util));
        }

        parts.join(" | ")
    }

    /// Check if GPU data is available
    pub fn is_available(&self) -> bool {
        !self.name.is_empty()
    }
}
