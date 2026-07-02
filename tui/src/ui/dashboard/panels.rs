//! AI stack status panel and storage/network/security panel.

use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, BorderType, Gauge, Paragraph, Widget},
};

use crate::app::App;
use crate::system::{format_rate, ServiceState};
use crate::ui::theme::{self, THEME};

pub(super) fn render(app: &App, area: Rect, buf: &mut Buffer, wide: bool) {
    let direction = if wide {
        Direction::Horizontal
    } else {
        Direction::Vertical
    };
    let rects = Layout::default()
        .direction(direction)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    render_ai_stack(app, rects[0], buf);
    render_storage_net_security(app, rects[1], buf);
}

fn render_ai_stack(app: &App, area: Rect, buf: &mut Buffer) {
    let block = Block::bordered()
        .border_type(BorderType::Thick)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Line::from(" AI STACK ").style(THEME.section));

    let inner = block.inner(area);
    block.render(area, buf);

    if app.ai_stack.is_empty() {
        Paragraph::new(Line::styled(
            " No AI stack services configured",
            THEME.muted,
        ))
        .render(inner, buf);
        return;
    }

    let lines: Vec<Line> = app
        .ai_stack
        .iter()
        .map(|svc| {
            let (state_text, color) = match svc.state {
                ServiceState::Running => ("running", theme::status::OK),
                ServiceState::Failed => ("failed", theme::status::ERROR),
                ServiceState::Inactive => ("inactive", theme::status::WARN),
                ServiceState::Unknown => ("unknown", theme::status::UNKNOWN),
            };
            // Already formatted by ai_stack ("up 3h12m" or "2/4 up").
            let uptime = svc.uptime.clone().unwrap_or_default();
            Line::from(vec![
                Span::styled(" ● ", Style::default().fg(color)),
                Span::styled(format!("{:<14}", svc.name), THEME.value),
                Span::styled(format!("{state_text:<10}"), Style::default().fg(color)),
                Span::styled(uptime, THEME.muted),
            ])
        })
        .collect();

    Paragraph::new(lines).render(inner, buf);
}

fn render_storage_net_security(app: &App, area: Rect, buf: &mut Buffer) {
    let block = Block::bordered()
        .border_type(BorderType::Thick)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Line::from(" STORAGE · NET · SECURITY ").style(THEME.section));

    let inner = block.inner(area);
    block.render(area, buf);

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // data volume gauge
            Constraint::Length(1), // net rates
            Constraint::Length(1), // spacer
            Constraint::Length(1), // encryption line
        ])
        .split(inner);

    let disk = &app.disk;
    Gauge::default()
        .gauge_style(
            Style::default()
                .fg(disk_color(disk.percent()))
                .bg(Color::DarkGray),
        )
        .ratio((disk.percent() as f64 / 100.0).clamp(0.0, 1.0))
        .label(Span::styled(
            format!("Data  {:.0} / {:.0} GB", disk.used_gb(), disk.total_gb()),
            Style::default().fg(Color::White).bold(),
        ))
        .render(layout[0], buf);

    let rx = format_rate(app.net_rate.rx_bytes_per_sec);
    let tx = format_rate(app.net_rate.tx_bytes_per_sec);
    Paragraph::new(Line::from(vec![
        Span::styled(" ↓ ", Style::default().fg(Color::Green)),
        Span::styled(format!("{rx:<14}"), THEME.value),
        Span::styled("↑ ", Style::default().fg(Color::Yellow)),
        Span::styled(tx, THEME.value),
    ]))
    .render(layout[1], buf);

    Paragraph::new(Line::from(vec![
        Span::styled(" ● ", Style::default().fg(theme::status::OK)),
        Span::styled("LUKS2 · TPM2 auto-unlock", THEME.muted),
    ]))
    .render(layout[3], buf);
}

fn disk_color(percent: u8) -> Color {
    match percent {
        0..=75 => Color::Green,
        76..=90 => Color::Rgb(255, 165, 0),
        _ => Color::Red,
    }
}
