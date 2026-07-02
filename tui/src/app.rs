//! Application state, tiered refresh scheduler, and event loop.
//!
//! This is a plain synchronous `std` loop — no async runtime. Each data
//! source is re-collected on its own cadence (see the `*_CADENCE` consts
//! below) rather than every tick, so the heavier subprocess-backed
//! collectors (nvidia-smi, systemctl, df, chronyc) don't run 4x/sec just
//! because the clock does.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    layout::Rect,
    widgets::{Clear, Widget},
    DefaultTerminal,
};

use crate::system::{
    self, ClockState, DiskUsage, EnrollmentState, GpuMetrics, LicenseInfo, LoadAvg, MemInfo,
    NetworkStats, NtpStatus, ServiceStatus,
};
use crate::ui;

/// History size for the CPU/GPU/MEM sparklines (60 samples).
pub const HISTORY_SIZE: usize = 60;

const CLOCK_CADENCE: Duration = Duration::from_secs(1);
const FAST_CADENCE: Duration = Duration::from_secs(1);
const GPU_CADENCE: Duration = Duration::from_secs(2);
const STACK_CADENCE: Duration = Duration::from_secs(5);
const DISK_NET_CADENCE: Duration = Duration::from_secs(5);
const SLOW_CADENCE: Duration = Duration::from_secs(15);

/// Input poll timeout. Short enough to keep the clock display responsive,
/// long enough that the loop blocks (no busy-spin) between events.
const POLL_TIMEOUT: Duration = Duration::from_millis(250);

/// Network rate information (calculated between refreshes)
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct NetworkRate {
    pub rx_bytes_per_sec: f64,
    pub tx_bytes_per_sec: f64,
}

/// Application run mode
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    Running,
    Quit,
}

/// Per-source next-refresh-due timestamps (monotonic).
struct Schedule {
    clock: Instant,
    fast: Instant,
    gpu: Instant,
    stack: Instant,
    disk_net: Instant,
    slow: Instant,
}

impl Schedule {
    fn due_now() -> Self {
        let now = Instant::now();
        Self {
            clock: now,
            fast: now,
            gpu: now,
            stack: now,
            disk_net: now,
            slow: now,
        }
    }
}

/// Main application state — single screen, no navigation.
pub struct App {
    pub mode: Mode,
    pub version: String,
    needs_redraw: bool,

    // Brief visual flash on manual refresh ('r').
    pub show_refresh_flash: bool,
    flash_until: Option<Instant>,

    // -- Displayed state, one field group per refresh tier --
    pub clock: ClockState,

    pub cpu_percent: u8,
    pub load: LoadAvg,
    pub cores: usize,
    pub mem: MemInfo,

    pub gpu: GpuMetrics,

    pub ai_stack: Vec<ServiceStatus>,

    pub disk: DiskUsage,
    pub net_rate: NetworkRate,
    pub interface: String,
    pub ip_address: String,
    pub link_speed_mbps: Option<u32>,

    pub hostname: String,
    pub mdns_hostname: Option<String>,
    pub access_url: String,
    pub license: LicenseInfo,
    pub ntp: NtpStatus,

    // Rolling sparkline history (ring buffers).
    pub cpu_history: VecDeque<u8>,
    pub gpu_history: VecDeque<u8>,
    pub mem_history: VecDeque<u8>,

    // Scheduler + delta-calculation state.
    due: Schedule,
    prev_cpu_times: Option<system::CpuTimes>,
    prev_net_stats: Option<NetworkStats>,
    prev_net_time: Option<Instant>,
}

impl App {
    /// Create a new application with the given version string.
    pub fn new(version: String) -> Self {
        Self {
            mode: Mode::Running,
            version,
            needs_redraw: true,
            show_refresh_flash: false,
            flash_until: None,

            clock: ClockState::default(),

            cpu_percent: 0,
            load: LoadAvg::default(),
            cores: system::resources::core_count(),
            mem: MemInfo::default(),

            gpu: GpuMetrics::default(),

            ai_stack: Vec::new(),

            disk: DiskUsage::default(),
            net_rate: NetworkRate::default(),
            interface: String::new(),
            ip_address: String::new(),
            link_speed_mbps: None,

            hostname: String::new(),
            mdns_hostname: None,
            access_url: String::new(),
            license: LicenseInfo::default(),
            ntp: NtpStatus::default(),

            cpu_history: VecDeque::with_capacity(HISTORY_SIZE),
            gpu_history: VecDeque::with_capacity(HISTORY_SIZE),
            mem_history: VecDeque::with_capacity(HISTORY_SIZE),

            due: Schedule::due_now(),
            prev_cpu_times: None,
            prev_net_stats: None,
            prev_net_time: None,
        }
    }

    /// Run the application event loop.
    pub fn run(mut self, mut terminal: DefaultTerminal) -> Result<()> {
        // Initial collect across every tier so the first frame isn't blank.
        self.tick(true);

        while self.mode == Mode::Running {
            if let Some(until) = self.flash_until {
                if Instant::now() >= until {
                    self.show_refresh_flash = false;
                    self.flash_until = None;
                    self.needs_redraw = true;
                }
            }

            // Only redraw when a displayed value actually changed (or the
            // clock ticked). On ARM64 framebuffer consoles, every
            // terminal.draw() triggers drm_fb_helper_damage_work in the
            // kernel workqueue; skipping unnecessary draws keeps that path
            // quiet.
            if self.needs_redraw {
                terminal.draw(|frame| frame.render_widget(&self, frame.area()))?;
                self.needs_redraw = false;
            }

            // Block on input up to POLL_TIMEOUT — no busy-spin, near-zero
            // idle CPU — but wake often enough that the 1s clock tier
            // never has to wait long past its due time.
            if event::poll(POLL_TIMEOUT)? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        self.handle_key(key.code);
                    }
                }
            }

            self.tick(false);
        }

        Ok(())
    }

    /// Handle a key press. Single screen: only quit and force-refresh.
    fn handle_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => self.mode = Mode::Quit,
            KeyCode::Char('r') | KeyCode::Char('R') => self.force_refresh(),
            _ => {}
        }
    }

    /// Force every tier to refresh immediately, regardless of cadence.
    fn force_refresh(&mut self) {
        self.tick(true);
        self.show_refresh_flash = true;
        self.flash_until = Some(Instant::now() + Duration::from_millis(300));
        self.needs_redraw = true;
    }

    /// Advance the tiered scheduler: refresh only the sources whose
    /// cadence has elapsed (or all of them, if `force` is set), and mark
    /// the frame dirty only if something displayed actually changed.
    fn tick(&mut self, force: bool) {
        let now = Instant::now();
        let mut changed = false;

        if force || now >= self.due.clock {
            changed |= self.refresh_clock();
            self.due.clock = now + CLOCK_CADENCE;
        }
        if force || now >= self.due.fast {
            changed |= self.refresh_cpu_ram();
            self.due.fast = now + FAST_CADENCE;
        }
        if force || now >= self.due.gpu {
            changed |= self.refresh_gpu();
            self.due.gpu = now + GPU_CADENCE;
        }
        if force || now >= self.due.stack {
            changed |= self.refresh_ai_stack();
            self.due.stack = now + STACK_CADENCE;
        }
        if force || now >= self.due.disk_net {
            changed |= self.refresh_disk_net();
            self.due.disk_net = now + DISK_NET_CADENCE;
        }
        if force || now >= self.due.slow {
            changed |= self.refresh_slow();
            self.due.slow = now + SLOW_CADENCE;
        }

        if changed {
            self.needs_redraw = true;
        }
    }

    fn refresh_clock(&mut self) -> bool {
        let new = system::clock::collect_clock();
        if new != self.clock {
            self.clock = new;
            true
        } else {
            false
        }
    }

    fn refresh_cpu_ram(&mut self) -> bool {
        let mut changed = false;

        if let Some(cur) = system::resources::read_cpu_times() {
            if let Some(prev) = self.prev_cpu_times {
                let pct = system::resources::cpu_percent(prev, cur);
                if pct != self.cpu_percent {
                    self.cpu_percent = pct;
                    changed = true;
                }
            }
            self.prev_cpu_times = Some(cur);
        }
        push_history(&mut self.cpu_history, self.cpu_percent);

        let load = system::resources::read_loadavg();
        if load != self.load {
            self.load = load;
            changed = true;
        }

        let mem = system::resources::read_meminfo();
        if mem != self.mem {
            self.mem = mem;
            changed = true;
        }
        push_history(&mut self.mem_history, self.mem.percent);

        changed
    }

    fn refresh_gpu(&mut self) -> bool {
        let new = GpuMetrics::collect();
        push_history(&mut self.gpu_history, new.utilization.unwrap_or(0));
        if new != self.gpu {
            self.gpu = new;
            true
        } else {
            false
        }
    }

    fn refresh_ai_stack(&mut self) -> bool {
        let new = system::ai_stack::collect_ai_stack();
        if new != self.ai_stack {
            self.ai_stack = new;
            true
        } else {
            false
        }
    }

    fn refresh_disk_net(&mut self) -> bool {
        let mut changed = false;
        let now = Instant::now();

        let disk = system::disk::read_data_volume_usage();
        if disk != self.disk {
            self.disk = disk;
            changed = true;
        }

        let net_stats = NetworkStats::collect();
        if net_stats.interface != self.interface {
            self.interface = net_stats.interface.clone();
            changed = true;
        }
        if net_stats.ip_address != self.ip_address {
            self.ip_address = net_stats.ip_address.clone();
            changed = true;
        }
        if net_stats.link_speed_mbps != self.link_speed_mbps {
            self.link_speed_mbps = net_stats.link_speed_mbps;
            changed = true;
        }

        if let (Some(prev_stats), Some(prev_time)) = (&self.prev_net_stats, self.prev_net_time) {
            let elapsed = now.duration_since(prev_time).as_secs_f64();
            if elapsed > 0.0 {
                let rx_diff = net_stats.rx_bytes.saturating_sub(prev_stats.rx_bytes);
                let tx_diff = net_stats.tx_bytes.saturating_sub(prev_stats.tx_bytes);
                let new_rate = NetworkRate {
                    rx_bytes_per_sec: rx_diff as f64 / elapsed,
                    tx_bytes_per_sec: tx_diff as f64 / elapsed,
                };
                if new_rate != self.net_rate {
                    self.net_rate = new_rate;
                    changed = true;
                }
            }
        }

        self.prev_net_stats = Some(net_stats);
        self.prev_net_time = Some(now);

        changed
    }

    fn refresh_slow(&mut self) -> bool {
        let mut changed = false;

        let hostname = system::identity::get_hostname();
        if hostname != self.hostname {
            self.hostname = hostname;
            changed = true;
        }

        let mdns = system::identity::get_mdns_hostname();
        if mdns != self.mdns_hostname {
            self.mdns_hostname = mdns;
            changed = true;
        }

        let access_url = system::identity::get_access_url(&self.mdns_hostname, &self.ip_address);
        if access_url != self.access_url {
            self.access_url = access_url;
            changed = true;
        }

        let license = system::license::get_license_info();
        if license != self.license {
            self.license = license;
            changed = true;
        }

        let ntp = system::ntp::collect_ntp();
        if ntp != self.ntp {
            self.ntp = ntp;
            changed = true;
        }

        changed
    }

    /// Get CPU history as `u64` samples for the `Sparkline` widget.
    pub fn cpu_history_data(&self) -> Vec<u64> {
        self.cpu_history.iter().map(|&v| v as u64).collect()
    }

    /// Get GPU history as `u64` samples for the `Sparkline` widget.
    pub fn gpu_history_data(&self) -> Vec<u64> {
        self.gpu_history.iter().map(|&v| v as u64).collect()
    }

    /// Get MEM history as `u64` samples for the `Sparkline` widget.
    pub fn mem_history_data(&self) -> Vec<u64> {
        self.mem_history.iter().map(|&v| v as u64).collect()
    }

    /// Whether the licence is currently active.
    pub fn license_active(&self) -> bool {
        self.license.state == EnrollmentState::Activated
    }
}

fn push_history(history: &mut VecDeque<u8>, value: u8) {
    if history.len() >= HISTORY_SIZE {
        history.pop_front();
    }
    history.push_back(value);
}

/// Implement Widget for &App to render by reference (avoids cloning)
impl Widget for &App {
    fn render(self, area: Rect, buf: &mut ratatui::buffer::Buffer) {
        // Clear the entire area first to prevent external terminal output
        // from polluting the display.
        Clear.render(area, buf);
        ui::dashboard::render(self, area, buf);
    }
}
