//! Local wall-clock time for the dashboard header.

use chrono::Local;

/// Formatted local time and date, refreshed every second.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClockState {
    pub time: String,
    pub date: String,
}

/// Collect the current local time as `HH:MM:SS` and `Mon 2 Jul 2026`.
pub fn collect_clock() -> ClockState {
    let now = Local::now();
    ClockState {
        time: now.format("%H:%M:%S").to_string(),
        date: now.format("%a %-d %b %Y").to_string(),
    }
}
