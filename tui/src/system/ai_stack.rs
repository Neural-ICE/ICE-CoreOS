//! AI stack service status via `systemctl`.
//!
//! Each service is checked with a cheap `systemctl is-active` /
//! `systemctl show` subprocess call. Kept on the 5s cadence — never call
//! this per-frame.

use std::fs;
use std::process::{Command, Stdio};

use crate::paths;

/// Coarse status of a single AI stack service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    Running,
    Failed,
    Inactive,
    Unknown,
}

/// Status of one monitored AI stack service.
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceStatus {
    pub name: String,
    pub state: ServiceState,
    /// Human-readable uptime (e.g. "3h12m"), present only while running.
    pub uptime: Option<String>,
}

/// Collect status for every service in [`paths::AI_STACK`].
// TODO(ICE-AC1): confirm real Quadlet unit names
pub fn collect_ai_stack() -> Vec<ServiceStatus> {
    paths::AI_STACK
        .iter()
        .map(|&name| collect_one(name))
        .collect()
}

fn collect_one(name: &str) -> ServiceStatus {
    let unit = format!("{name}.service");
    let state = is_active(&unit);
    let uptime = if state == ServiceState::Running {
        active_uptime(&unit)
    } else {
        None
    };

    ServiceStatus {
        name: name.to_string(),
        state,
        uptime,
    }
}

fn is_active(unit: &str) -> ServiceState {
    let output = match Command::new("systemctl")
        .args(["is-active", unit])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    {
        Ok(o) => o,
        Err(_) => return ServiceState::Unknown,
    };

    match String::from_utf8_lossy(&output.stdout).trim() {
        "active" => ServiceState::Running,
        "failed" => ServiceState::Failed,
        "inactive" | "activating" | "deactivating" => ServiceState::Inactive,
        _ => ServiceState::Unknown,
    }
}

/// Derive "how long has this unit been active" from
/// `ActiveEnterTimestampMonotonic` (microseconds since boot) compared
/// against `/proc/uptime`. Avoids parsing systemd's locale-dependent wall
/// clock timestamp string.
fn active_uptime(unit: &str) -> Option<String> {
    let output = Command::new("systemctl")
        .args([
            "show",
            "-p",
            "ActiveEnterTimestampMonotonic",
            "--value",
            unit,
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let micros: u64 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .ok()?;
    if micros == 0 {
        return None;
    }

    let entered_secs = micros as f64 / 1_000_000.0;
    let now_secs = read_uptime_secs()?;
    let delta = (now_secs - entered_secs).max(0.0);

    Some(format_duration(delta))
}

fn read_uptime_secs() -> Option<f64> {
    fs::read_to_string("/proc/uptime")
        .ok()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn format_duration(secs: f64) -> String {
    let total_mins = (secs / 60.0) as u64;
    let days = total_mins / 60 / 24;
    let hours = (total_mins / 60) % 24;
    let mins = total_mins % 60;

    if days > 0 {
        format!("{days}d{hours}h")
    } else if hours > 0 {
        format!("{hours}h{mins}m")
    } else {
        format!("{mins}m")
    }
}
