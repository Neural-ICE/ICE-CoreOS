//! CPU / GPU / MEM metric cards, each with a rolling sparkline history.

use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, BorderType, Paragraph, Sparkline, SparklineBar, Widget},
};

use crate::app::App;
use crate::ui::theme::THEME;

/// Render the CPU | GPU | MEM cards: side by side if `wide`, stacked otherwise.
pub(super) fn render(app: &App, area: Rect, buf: &mut Buffer, wide: bool) {
    let direction = if wide {
        Direction::Horizontal
    } else {
        Direction::Vertical
    };
    let rects = Layout::default()
        .direction(direction)
        .constraints([
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Fill(1),
        ])
        .split(area);

    render_cpu_card(app, rects[0], buf);
    render_gpu_card(app, rects[1], buf);
    render_mem_card(app, rects[2], buf);
}

fn render_cpu_card(app: &App, area: Rect, buf: &mut Buffer) {
    let color = gauge_color(app.cpu_percent);
    let title = format!(" CPU  {}% ", app.cpu_percent);
    let detail = Line::from(Span::styled(
        format!(
            " load {:.1}·{:.1}·{:.1}   {} cores",
            app.load.one, app.load.five, app.load.fifteen, app.cores
        ),
        THEME.muted,
    ));
    render_card(&title, color, &app.cpu_history_data(), detail, area, buf);
}

fn render_gpu_card(app: &App, area: Rect, buf: &mut Buffer) {
    let gpu = &app.gpu;
    let util = gpu.utilization.unwrap_or(0);
    let color = gauge_color(util);

    let mut title = format!(" GPU  {util}%");
    if let Some(temp) = gpu.temperature {
        title.push_str(&format!(" · {temp}°C"));
    }
    if let Some(power) = gpu.power_draw {
        title.push_str(&format!(" · {power}W"));
    }
    title.push(' ');

    let detail = if gpu.is_available() {
        // GB10 / DGX Spark: GPU memory is the system RAM (unified). nvidia-smi
        // reports memory.total as [N/A] there (parsed as 0) — show the real
        // unified pool from /proc/meminfo instead of a bogus "0 / 0".
        if gpu.memory_total_gb == 0 {
            Line::from(Span::styled(
                format!(
                    " unified mem {:.0} / {:.0} GB (system RAM)",
                    app.mem.used_gb, app.mem.total_gb
                ),
                THEME.muted,
            ))
        } else {
            Line::from(Span::styled(
                format!(
                    " VRAM {} / {} GB (unified)",
                    gpu.memory_used_gb, gpu.memory_total_gb
                ),
                THEME.muted,
            ))
        }
    } else {
        Line::from(Span::styled(" No NVIDIA GPU detected", THEME.muted))
    };

    render_card(&title, color, &app.gpu_history_data(), detail, area, buf);
}

fn render_mem_card(app: &App, area: Rect, buf: &mut Buffer) {
    let mem = &app.mem;
    let color = gauge_color(mem.percent);
    let title = format!(" MEM  {}% ", mem.percent);
    let detail = Line::from(Span::styled(
        format!(" {:.0} / {:.0} GB", mem.used_gb, mem.total_gb),
        THEME.muted,
    ));
    render_card(&title, color, &app.mem_history_data(), detail, area, buf);
}

/// Render one bordered card: title, sparkline history, one detail line.
fn render_card(
    title: &str,
    color: Color,
    history: &[u64],
    detail: Line,
    area: Rect,
    buf: &mut Buffer,
) {
    let block = Block::bordered()
        .border_type(BorderType::Thick)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            title.to_string(),
            Style::default().fg(color).bold(),
        ));

    let inner = block.inner(area);
    block.render(area, buf);

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);

    if !history.is_empty() {
        let bars: Vec<SparklineBar> = history.iter().copied().map(SparklineBar::from).collect();
        Sparkline::default()
            .data(bars)
            .max(100)
            .style(Style::default().fg(color))
            .render(layout[0], buf);
    }

    Paragraph::new(detail).render(layout[1], buf);
}

/// Color based on percentage (green -> yellow -> orange -> red).
fn gauge_color(percent: u8) -> Color {
    match percent {
        0..=50 => Color::Green,
        51..=75 => Color::Yellow,
        76..=90 => Color::Rgb(255, 165, 0),
        _ => Color::Red,
    }
}
