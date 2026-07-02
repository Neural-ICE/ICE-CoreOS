//! Cyberpunk theme for Neural ICE Core TUI
//!
//! Centralized theme configuration following Ratatui demo2 patterns.

use ratatui::style::{Color, Modifier, Style};

/// Color palette - dark theme with light text
pub mod palette {
    use super::*;

    // Primary colors
    pub const CYAN_BRIGHT: Color = Color::Rgb(0, 255, 255); // Electric cyan #00FFFF
    pub const CYAN_DARK: Color = Color::Rgb(0, 170, 204); // Deep cyan #00AACC
    pub const PURPLE_BRIGHT: Color = Color::Rgb(157, 78, 221); // Neon purple #9D4EDD

    // Text colors (20% black = 80% white)
    pub const TEXT: Color = Color::Rgb(204, 204, 204); // Light gray #CCCCCC (80% white)
    pub const MUTED: Color = Color::Rgb(128, 128, 128); // Medium gray #808080
    pub const DIM: Color = Color::Rgb(80, 80, 80); // Dim gray #505050
}

/// Status-dot colors used across the dashboard.
/// green = ok/running, amber = warn, red = error/failed, gray = unknown.
pub mod status {
    use super::*;

    pub const OK: Color = Color::Rgb(48, 209, 88);
    pub const WARN: Color = Color::Rgb(255, 179, 64);
    pub const ERROR: Color = Color::Rgb(255, 69, 58);
    pub const UNKNOWN: Color = Color::Rgb(128, 128, 128);
}

/// Theme structure containing all style definitions
pub struct Theme {
    pub logo: Style,
    pub section: Style,
    pub label: Style,
    pub value: Style,
    pub help: Style,
    pub key: Style,
    pub muted: Style,
}

/// Global theme instance
pub static THEME: Theme = Theme {
    logo: Style::new()
        .fg(palette::CYAN_BRIGHT)
        .add_modifier(Modifier::BOLD),
    section: Style::new()
        .fg(palette::PURPLE_BRIGHT)
        .add_modifier(Modifier::BOLD),
    label: Style::new().fg(palette::CYAN_DARK),
    value: Style::new().fg(palette::TEXT),
    help: Style::new().fg(palette::MUTED),
    key: Style::new()
        .fg(palette::CYAN_BRIGHT)
        .add_modifier(Modifier::BOLD),
    muted: Style::new().fg(palette::MUTED),
};
