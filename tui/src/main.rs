//! Neural ICE Core TUI - single-screen terminal dashboard for Neural ICE
//! Core AI appliances.
//!
//! Built with Ratatui. Runs as a plain synchronous loop (no async runtime):
//! the appliance framebuffer console has no work worth spawning a reactor
//! for, and a `std`-only loop keeps the binary small and the idle footprint
//! near zero.

mod app;
mod paths;
mod system;
mod ui;

use anyhow::Result;

use crate::app::App;

fn main() -> Result<()> {
    let version = system::identity::get_version();

    // ratatui::init() already enables raw mode and enters the alternate screen.
    // Doing both manually here can leave the service without a usable tty.
    let terminal = ratatui::init();

    // Run application
    let app_result = App::new(version).run(terminal);

    // Restore terminal
    ratatui::restore();

    app_result
}
