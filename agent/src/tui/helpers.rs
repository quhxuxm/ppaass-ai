use ratatui::{
    Frame,
    layout::{Margin, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Scrollbar, ScrollbarOrientation, ScrollbarState},
};
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn rect_contains(area: Rect, column: u16, row: u16) -> bool {
    column >= area.x
        && column < area.x.saturating_add(area.width)
        && row >= area.y
        && row < area.y.saturating_add(area.height)
}

pub(super) fn traffic_table_viewport_rows(area: Rect) -> usize {
    area.height.saturating_sub(3) as usize
}

pub(super) fn tokio_tasks_table_viewport_rows(area: Rect) -> usize {
    area.height.saturating_sub(3) as usize
}

pub(super) fn config_table_viewport_rows(area: Rect) -> usize {
    area.height.saturating_sub(3) as usize
}

pub(super) fn render_vertical_scrollbar(
    frame: &mut Frame,
    area: Rect,
    content_length: usize,
    viewport_length: usize,
    position: usize,
    color: Color,
) {
    if area.width < 3 || area.height < 4 || content_length <= viewport_length.max(1) {
        return;
    }

    let mut scrollbar_state = ScrollbarState::new(content_length)
        .viewport_content_length(viewport_length.max(1))
        .position(position.min(content_length.saturating_sub(1)));
    let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
        .begin_symbol(None)
        .end_symbol(None)
        .thumb_style(Style::default().fg(color))
        .track_style(Style::default().fg(Color::DarkGray));
    frame.render_stateful_widget(
        scrollbar,
        area.inner(Margin {
            vertical: 1,
            horizontal: 0,
        }),
        &mut scrollbar_state,
    );
}

pub(super) fn format_hhmmss(timestamp_secs: u64) -> String {
    let day_secs = timestamp_secs % 86_400;
    let hours = day_secs / 3_600;
    let minutes = (day_secs % 3_600) / 60;
    let seconds = day_secs % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

pub(super) fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;

    let bytes_f = bytes as f64;
    if bytes_f >= GB {
        format!("{:.2} GB", bytes_f / GB)
    } else if bytes_f >= MB {
        format!("{:.2} MB", bytes_f / MB)
    } else if bytes_f >= KB {
        format!("{:.2} KB", bytes_f / KB)
    } else {
        format!("{bytes} B")
    }
}

pub(super) fn format_duration_ns(nanos: u64) -> String {
    const US: f64 = 1_000.0;
    const MS: f64 = 1_000_000.0;
    const S: f64 = 1_000_000_000.0;

    let value = nanos as f64;
    if value >= S {
        format!("{:.2}s", value / S)
    } else if value >= MS {
        format!("{:.2}ms", value / MS)
    } else if value >= US {
        format!("{:.2}us", value / US)
    } else {
        format!("{nanos}ns")
    }
}

pub(super) fn tail_fit_text(input: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }

    let total = input.chars().count();
    if total <= max_chars {
        return input.to_string();
    }

    if max_chars <= 3 {
        return input
            .chars()
            .skip(total.saturating_sub(max_chars))
            .collect::<String>();
    }

    let keep = max_chars.saturating_sub(3);
    let tail = input
        .chars()
        .skip(total.saturating_sub(keep))
        .collect::<String>();
    format!("...{tail}")
}

pub(super) fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(super) fn styled_log_line(line: &str) -> Line<'static> {
    let Some((level_start, level_end, level_color)) = detect_log_level(line) else {
        return Line::from(line.to_string());
    };

    let mut spans = Vec::with_capacity(3);
    if level_start > 0 {
        spans.push(Span::raw(line[..level_start].to_string()));
    }
    spans.push(Span::styled(
        line[level_start..level_end].to_string(),
        Style::default()
            .fg(level_color)
            .add_modifier(Modifier::BOLD),
    ));
    if level_end < line.len() {
        spans.push(Span::raw(line[level_end..].to_string()));
    }

    Line::from(spans)
}

pub(super) fn detect_log_level(line: &str) -> Option<(usize, usize, Color)> {
    let (first_start, first_end, next_cursor) = next_token_range(line, 0)?;
    if let Some(color) = level_color(&line[first_start..first_end]) {
        return Some((first_start, first_end, color));
    }

    if let Some((second_start, second_end, _)) = next_token_range(line, next_cursor)
        && let Some(color) = level_color(&line[second_start..second_end])
    {
        return Some((second_start, second_end, color));
    }

    None
}

fn next_token_range(text: &str, cursor: usize) -> Option<(usize, usize, usize)> {
    let bytes = text.as_bytes();
    let mut idx = cursor;

    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }
    if idx >= bytes.len() {
        return None;
    }

    let start = idx;
    while idx < bytes.len() && !bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }

    Some((start, idx, idx))
}

fn level_color(token: &str) -> Option<Color> {
    let normalized = token
        .trim_matches(|c: char| matches!(c, '[' | ']' | ':'))
        .to_ascii_uppercase();

    match normalized.as_str() {
        "ERROR" => Some(Color::Red),
        "WARN" => Some(Color::Yellow),
        "INFO" => Some(Color::Green),
        "DEBUG" => Some(Color::Cyan),
        "TRACE" => Some(Color::Magenta),
        _ => None,
    }
}

#[cfg(test)]
mod log_level_tests {
    use super::*;

    #[test]
    fn highlights_level_token_from_header_only() {
        let line = "2026-02-10T23:26:42.085536Z  INFO ThreadId(01) agent: this is an error message";
        let result = detect_log_level(line);
        let (start, end, color) = result.expect("level should be found");
        assert_eq!(&line[start..end], "INFO");
        assert_eq!(color, Color::Green);
    }

    #[test]
    fn does_not_highlight_message_body_keyword_when_no_level_field() {
        let line = "this message mentions error and warn but has no log header";
        assert!(detect_log_level(line).is_none());
    }
}
