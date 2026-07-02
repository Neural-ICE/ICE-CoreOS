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
    /// Display-ready detail: "up 3h12m" when the whole row runs, "2/4 up"
    /// when only part of an aggregated row is running.
    pub uptime: Option<String>,
}

/// Collect status for every row in [`paths::AI_STACK`]. A row aggregates one
/// or more Quadlet units (e.g. "vllm" = the four vllm-*.service units): the
/// row state is the WORST unit state, and a partially-up row shows "x/y up"
/// instead of an uptime.
pub fn collect_ai_stack() -> Vec<ServiceStatus> {
    paths::AI_STACK
        .iter()
        .map(|&(name, units)| collect_group(name, units))
        .collect()
}

fn collect_group(name: &str, units: &[&str]) -> ServiceStatus {
    let states: Vec<(ServiceState, String)> = units
        .iter()
        .map(|u| {
            let unit = format!("{u}.service");
            (is_active(&unit), unit)
        })
        .collect();

    let worst = states
        .iter()
        .map(|(s, _)| *s)
        .max_by_key(|s| match s {
            ServiceState::Running => 0,
            ServiceState::Unknown => 1,
            ServiceState::Inactive => 2,
            ServiceState::Failed => 3,
        })
        .unwrap_or(ServiceState::Unknown);

    let uptime = if worst == ServiceState::Running {
        // All units running: show the most recent start (shortest uptime).
        states
            .iter()
            .filter_map(|(_, u)| active_uptime(u))
            .min_by_key(|s| parse_duration_key(s))
            .map(|d| format!("up {d}"))
    } else {
        let up = states
            .iter()
            .filter(|(s, _)| *s == ServiceState::Running)
            .count();
        (up > 0).then(|| format!("{up}/{} up", states.len()))
    };

    ServiceStatus {
        name: name.to_string(),
        state: worst,
        uptime,
    }
}

/// Sort key so "3m" < "2h5m" < "1d4h" without re-deriving raw seconds.
fn parse_duration_key(s: &str) -> u64 {
    let (mut days, mut hours, mut mins, mut num) = (0u64, 0u64, 0u64, 0u64);
    for c in s.chars() {
        match c {
            '0'..='9' => num = num * 10 + (c as u64 - '0' as u64),
            'd' => { days = num; num = 0 }
            'h' => { hours = num; num = 0 }
            'm' => { mins = num; num = 0 }
            _ => {}
        }
    }
    (days * 24 + hours) * 60 + mins
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
