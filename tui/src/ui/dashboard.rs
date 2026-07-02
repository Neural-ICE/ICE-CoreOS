//! Single-screen dashboard rendering: header, identity block, CPU/GPU/MEM
//! cards, AI stack + storage/net/security panels, footer hint.

use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Paragraph, Widget, Wrap},
};

use crate::app::App;
use crate::system::EnrollmentState;

use super::theme::{self, THEME};

mod cards;
mod panels;

/// Below this width, metric cards and bottom panels stack vertically
/// instead of sitting side by side, so nothing (hostname, access URL)
/// ever gets truncated.
const WIDE_LAYOUT_MIN_WIDTH: u16 = 92;

/// Render the whole dashboard — the only screen this TUI has.
pub fn render(app: &App, area: Rect, buf: &mut Buffer) {
    let wide = area.width >= WIDE_LAYOUT_MIN_WIDTH;

    let cards_height = if wide { 7 } else { 19 }; // 3 stacked cards @ ~6-7 rows each
    let panels_height = if wide { 8 } else { 15 }; // 2 stacked panels

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),             // brand + clock, divider
            Constraint::Length(5),             // identity block (wraps, never cut)
            Constraint::Length(1),             // spacer
            Constraint::Length(cards_height),  // CPU | GPU | MEM
            Constraint::Length(1),             // spacer
            Constraint::Length(panels_height), // AI STACK | STORAGE-NET-SECURITY
            Constraint::Length(1),             // footer hint
        ])
        .split(area);

    render_header(app, layout[0], buf);
    render_identity(app, layout[1], buf);
    cards::render(app, layout[3], buf, wide);
    panels::render(app, layout[5], buf, wide);
    render_footer(layout[6], buf);
}

/// Brand + clock/date line, followed by a divider.
fn render_header(app: &App, area: Rect, buf: &mut Buffer) {
    if area.height == 0 {
        return;
    }

    let dot_color = if !app.ip_address.is_empty() && app.ip_address != "unknown" {
        theme::status::OK
    } else {
        theme::status::ERROR
    };

    let left = Line::from(vec![
        Span::styled("● ", Style::default().fg(dot_color)),
        Span::styled("NEURAL ICE", THEME.logo),
    ]);
    let right = Line::from(vec![
        Span::styled(
            app.clock.time.clone(),
            Style::default()
                .fg(theme::palette::TEXT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("   ·   ", THEME.muted),
        Span::styled(app.clock.date.clone(), THEME.muted),
    ]);

    Paragraph::new(left).render(Rect::new(area.x, area.y, area.width, 1), buf);
    Paragraph::new(right)
        .right_aligned()
        .render(Rect::new(area.x, area.y, area.width, 1), buf);

    if area.height > 1 {
        let divider = "═".repeat(area.width as usize);
        Paragraph::new(Line::styled(
            divider,
            Style::default().fg(theme::palette::DIM),
        ))
        .render(Rect::new(area.x, area.y + 1, area.width, 1), buf);
    }
}

/// Appliance / Access / Licence / Time identity block. Uses `Paragraph`
/// wrapping (never manual truncation) so the hostname and access URL are
/// always fully visible, even on a narrow console.
fn render_identity(app: &App, area: Rect, buf: &mut Buffer) {
    let hostname_display = app
        .mdns_hostname
        .as_ref()
        .map(|h| format!("{h}.local"))
        .unwrap_or_else(|| app.hostname.clone());
    let ip_display = if app.ip_address.is_empty() || app.ip_address == "unknown" {
        "—".to_string()
    } else {
        app.ip_address.clone()
    };

    let appliance_line = Line::from(vec![
        Span::styled(" Appliance   ", THEME.label),
        Span::styled(format!("{hostname_display:<30}"), THEME.value),
        Span::styled(
            format!("{ip_display:<20}"),
            Style::default().fg(theme::palette::CYAN_BRIGHT),
        ),
        Span::styled(format!("v{}", app.version), THEME.muted),
    ]);

    let access_line = Line::from(vec![
        Span::styled(" Access      ", THEME.label),
        Span::styled(
            app.access_url.clone(),
            Style::default()
                .fg(theme::palette::CYAN_BRIGHT)
                .add_modifier(Modifier::BOLD),
        ),
    ]);

    let (lic_color, lic_text) = license_display(app);
    let license_line = Line::from(vec![
        Span::styled(" Licence     ", THEME.label),
        Span::styled("● ", Style::default().fg(lic_color)),
        Span::styled(lic_text, Style::default().fg(lic_color)),
    ]);

    let (ntp_color, ntp_text) = ntp_display(app);
    let time_line = Line::from(vec![
        Span::styled(" Time        ", THEME.label),
        Span::styled("● ", Style::default().fg(ntp_color)),
        Span::styled(ntp_text, THEME.value),
    ]);

    Paragraph::new(vec![appliance_line, access_line, license_line, time_line])
        .wrap(Wrap { trim: true })
        .render(area, buf);
}

fn license_display(app: &App) -> (Color, String) {
    match app.license.state {
        EnrollmentState::Activated => {
            let tier = app.license.tier.as_deref().unwrap_or("—");
            (
                theme::status::OK,
                format!("Active · {tier} · expires {}", app.license.expiry),
            )
        }
        EnrollmentState::Expired => (theme::status::ERROR, "Expired".to_string()),
        EnrollmentState::NotActivated => (theme::status::WARN, "Not activated".to_string()),
    }
}

fn ntp_display(app: &App) -> (Color, String) {
    if app.ntp.synced {
        let offset = app
            .ntp
            .offset_ms
            .map(|v| format!("{v:.1} ms"))
            .unwrap_or_else(|| "—".to_string());
        let source = app.ntp.source.as_deref().unwrap_or("ntp");
        (
            theme::status::OK,
            format!("NTP synced · {source} · offset {offset}"),
        )
    } else {
        (theme::status::WARN, "NTP not synced".to_string())
    }
}

fn render_footer(area: Rect, buf: &mut Buffer) {
    let line = Line::from(vec![
        Span::styled("[Q]", THEME.key),
        Span::styled(" quit  ", THEME.help),
        Span::styled("[R]", THEME.key),
        Span::styled(" refresh", THEME.help),
    ]);
    Paragraph::new(line).centered().render(area, buf);
}
