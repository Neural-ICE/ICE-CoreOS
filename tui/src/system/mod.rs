//! System data collectors.
//!
//! Each submodule owns one data source. Collectors are called directly by
//! `app::App`'s tiered scheduler, each at its own cadence — there is no
//! single `SystemInfo::collect()` that gathers everything at once, since
//! that would force every source (including the heavy `nvidia-smi` and
//! `systemctl` subprocess calls) onto the fastest cadence in the app.

pub mod ai_stack;
pub mod clock;
pub mod disk;
pub mod gpu;
pub mod identity;
pub mod license;
pub mod network;
pub mod ntp;
pub mod resources;

pub use ai_stack::{ServiceState, ServiceStatus};
pub use clock::ClockState;
pub use disk::DiskUsage;
pub use gpu::GpuMetrics;
pub use license::{EnrollmentState, LicenseInfo};
pub use network::{format_rate, NetworkStats};
pub use ntp::NtpStatus;
pub use resources::{CpuTimes, LoadAvg, MemInfo};
