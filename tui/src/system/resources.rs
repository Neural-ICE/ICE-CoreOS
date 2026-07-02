//! CPU and memory metrics from `/proc` (no subprocess).

use std::fs;

/// Raw CPU jiffie counters sampled from the `cpu` line of `/proc/stat`.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct CpuTimes {
    idle: u64,
    total: u64,
}

/// Read the aggregate `cpu` line from `/proc/stat`. Returns `None` if the
/// file is missing or malformed.
pub fn read_cpu_times() -> Option<CpuTimes> {
    let stat = fs::read_to_string("/proc/stat").ok()?;
    let line = stat.lines().next()?;

    let mut fields = line.split_whitespace();
    if fields.next()? != "cpu" {
        return None;
    }

    let values: Vec<u64> = fields.filter_map(|f| f.parse().ok()).collect();
    if values.len() < 4 {
        return None;
    }

    // user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice
    let idle = values[3] + values.get(4).copied().unwrap_or(0); // idle + iowait
    let total: u64 = values.iter().sum();

    Some(CpuTimes { idle, total })
}

/// Compute CPU utilization percentage from two samples of `/proc/stat`.
pub fn cpu_percent(prev: CpuTimes, cur: CpuTimes) -> u8 {
    let total_delta = cur.total.saturating_sub(prev.total);
    if total_delta == 0 {
        return 0;
    }
    let idle_delta = cur.idle.saturating_sub(prev.idle);
    let busy_delta = total_delta.saturating_sub(idle_delta);
    ((busy_delta as f64 / total_delta as f64) * 100.0)
        .round()
        .clamp(0.0, 100.0) as u8
}

/// Number of logical CPU cores.
pub fn core_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// System load averages (1/5/15 minute).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct LoadAvg {
    pub one: f32,
    pub five: f32,
    pub fifteen: f32,
}

/// Read `/proc/loadavg`. Missing/malformed file yields zeroed averages.
pub fn read_loadavg() -> LoadAvg {
    let content = match fs::read_to_string("/proc/loadavg") {
        Ok(c) => c,
        Err(_) => return LoadAvg::default(),
    };

    let mut fields = content.split_whitespace();
    let one = fields.next().and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let five = fields.next().and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let fifteen = fields.next().and_then(|s| s.parse().ok()).unwrap_or(0.0);

    LoadAvg { one, five, fifteen }
}

/// System memory usage (unified with GPU VRAM on the GB10 / DGX Spark).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct MemInfo {
    pub used_gb: f32,
    pub total_gb: f32,
    pub percent: u8,
}

/// Read `/proc/meminfo`. Missing/malformed file yields a zeroed `MemInfo`.
pub fn read_meminfo() -> MemInfo {
    let meminfo = match fs::read_to_string("/proc/meminfo") {
        Ok(s) => s,
        Err(_) => return MemInfo::default(),
    };

    let mut total_kb: u64 = 0;
    let mut available_kb: u64 = 0;

    for line in meminfo.lines() {
        if line.starts_with("MemTotal:") {
            total_kb = parse_meminfo_value(line);
        } else if line.starts_with("MemAvailable:") {
            available_kb = parse_meminfo_value(line);
        }
    }

    if total_kb == 0 {
        return MemInfo::default();
    }

    let used_kb = total_kb.saturating_sub(available_kb);
    let percent = ((used_kb as f64 / total_kb as f64) * 100.0) as u8;
    let used_gb = used_kb as f32 / 1024.0 / 1024.0;
    let total_gb = total_kb as f32 / 1024.0 / 1024.0;

    MemInfo {
        used_gb,
        total_gb,
        percent,
    }
}

/// Parse a meminfo line like "MemTotal:       123456 kB"
fn parse_meminfo_value(line: &str) -> u64 {
    line.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}
