//! NTP sync status via `chronyc`.

use std::process::{Command, Stdio};

/// NTP synchronization status.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NtpStatus {
    pub synced: bool,
    pub offset_ms: Option<f64>,
    pub source: Option<String>,
}

/// Collect NTP sync status from `chronyc -c tracking` (CSV output).
///
/// Field layout (0-indexed): 0=Reference ID, 1=Reference name, 2=Stratum,
/// 3=Ref time, 4=System time offset (s), ..., last=Leap status. If
/// `chronyc` is missing, fails, or the output doesn't parse, this reports
/// "not synced" rather than panicking or guessing.
// TODO(ICE-AC1): verify the exact chronyc -c field layout against a live
// chronyd instance on target hardware; the offset/leap-status field
// indices below are inferred from chrony's csv report format.
pub fn collect_ntp() -> NtpStatus {
    let output = match Command::new("chronyc")
        .args(["-c", "tracking"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return NtpStatus::default(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = match stdout.lines().next() {
        Some(l) if !l.is_empty() => l,
        _ => return NtpStatus::default(),
    };

    let fields: Vec<&str> = line.split(',').collect();
    if fields.len() < 13 {
        return NtpStatus::default();
    }

    let source = fields
        .get(1)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let offset_ms = fields
        .get(4)
        .and_then(|s| s.trim().parse::<f64>().ok())
        .map(|v| v * 1000.0);

    let leap = fields.last().map(|s| s.trim()).unwrap_or("");
    let synced = leap.eq_ignore_ascii_case("Normal")
        || leap.eq_ignore_ascii_case("Insert second")
        || leap.eq_ignore_ascii_case("Delete second");

    NtpStatus {
        synced,
        offset_ms,
        source,
    }
}
