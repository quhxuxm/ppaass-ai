use super::App;
use super::helpers::traffic_table_viewport_rows;
use super::types::*;
use ratatui::layout::{Constraint, Direction, Layout, Rect};

impl App {
    pub(super) fn current_content_body_rect(&self) -> Option<Rect> {
        let Ok((width, height)) = crossterm::terminal::size() else {
            return None;
        };
        if width == 0 || height <= TABS_HEIGHT + STATUS_HEIGHT + FOOTER_HEIGHT {
            return None;
        }

        let body_y = TABS_HEIGHT + STATUS_HEIGHT;
        let footer_y = height.saturating_sub(FOOTER_HEIGHT);
        if footer_y <= body_y {
            return None;
        }

        let body_h = footer_y.saturating_sub(body_y);
        if body_h < 6 {
            return None;
        }
        Some(Rect::new(0, body_y, width, body_h))
    }

    pub(super) fn agent_layout_from_body(&self, body: Rect) -> AgentLayoutRects {
        let log_height_percent = self
            .log_height_percent
            .clamp(LOG_HEIGHT_MIN_PERCENT, LOG_HEIGHT_MAX_PERCENT);
        let trends_width_percent = self
            .trends_width_percent
            .clamp(TRENDS_LEFT_MIN_PERCENT, TRENDS_LEFT_MAX_PERCENT);
        let split = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(100 - log_height_percent),
                Constraint::Percentage(log_height_percent),
            ])
            .split(body);
        let top = split[0];
        let logs = split[1];

        let top_split = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(trends_width_percent),
                Constraint::Percentage(100 - trends_width_percent),
            ])
            .split(top);
        let trends = top_split[0];
        let sessions = top_split[1];

        let sessions_table = sessions;

        AgentLayoutRects {
            body,
            top,
            logs,
            trends,
            sessions,
            sessions_table,
        }
    }

    pub(super) fn current_agent_layout_rects(&self) -> Option<AgentLayoutRects> {
        if self.active_tab != AppTab::Agent {
            return None;
        }

        let body = self.current_content_body_rect()?;
        Some(self.agent_layout_from_body(body))
    }

    pub(super) fn tokio_console_layout_from_body(&self, body: Rect) -> TokioConsoleLayoutRects {
        let sections = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(7), Constraint::Min(4)])
            .split(body);

        let task_split = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(TOKIO_TASKS_WIDTH_PERCENT),
                Constraint::Percentage(100 - TOKIO_TASKS_WIDTH_PERCENT),
            ])
            .split(sections[1]);

        TokioConsoleLayoutRects {
            summary: sections[0],
            tasks_table: task_split[0],
            task_details: task_split[1],
        }
    }

    pub(super) fn current_tokio_console_layout_rects(&self) -> Option<TokioConsoleLayoutRects> {
        if self.active_tab != AppTab::TokioConsole {
            return None;
        }
        let body = self.current_content_body_rect()?;
        Some(self.tokio_console_layout_from_body(body))
    }

    pub(super) fn config_layout_from_body(&self, body: Rect) -> ConfigLayoutRects {
        let sections = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(6),
                Constraint::Min(5),
                Constraint::Length(4),
            ])
            .split(body);
        ConfigLayoutRects {
            summary: sections[0],
            fields_table: sections[1],
            editor: sections[2],
        }
    }

    pub(super) fn current_config_layout_rects(&self) -> Option<ConfigLayoutRects> {
        if self.active_tab != AppTab::Config {
            return None;
        }
        let body = self.current_content_body_rect()?;
        Some(self.config_layout_from_body(body))
    }

    pub(super) fn current_log_viewport_lines(&self) -> usize {
        self.current_agent_layout_rects()
            .map(|layout| layout.logs.height.saturating_sub(2) as usize)
            .unwrap_or(1)
            .max(1)
    }

    pub(super) fn current_traffic_viewport_lines(&self) -> usize {
        self.current_agent_layout_rects()
            .map(|layout| traffic_table_viewport_rows(layout.sessions_table))
            .unwrap_or(1)
            .max(1)
    }

    pub(super) fn max_log_scroll(&self, viewport_lines: usize) -> usize {
        self.logs.len().saturating_sub(viewport_lines.max(1))
    }

    pub(super) fn clamp_log_scroll(&mut self, viewport_lines: usize) {
        self.log_scroll_from_bottom = self
            .log_scroll_from_bottom
            .min(self.max_log_scroll(viewport_lines));
    }

    pub(super) fn scroll_logs_older(&mut self, lines: usize) {
        let max_scroll = self.max_log_scroll(self.current_log_viewport_lines());
        self.log_scroll_from_bottom = self
            .log_scroll_from_bottom
            .saturating_add(lines)
            .min(max_scroll);
    }

    pub(super) fn scroll_logs_newer(&mut self, lines: usize) {
        self.log_scroll_from_bottom = self.log_scroll_from_bottom.saturating_sub(lines);
    }

    pub(super) fn scroll_logs_to_oldest(&mut self) {
        self.log_scroll_from_bottom = self.max_log_scroll(self.current_log_viewport_lines());
    }

    pub(super) fn scroll_logs_to_latest(&mut self) {
        self.log_scroll_from_bottom = 0;
    }

    pub(super) fn max_traffic_scroll(&self, viewport_rows: usize) -> usize {
        self.traffic.len().saturating_sub(viewport_rows.max(1))
    }

    pub(super) fn clamp_traffic_scroll(&mut self, viewport_rows: usize) {
        self.traffic_scroll_from_top = self
            .traffic_scroll_from_top
            .min(self.max_traffic_scroll(viewport_rows));
    }

    pub(super) fn scroll_traffic_older(&mut self, rows: usize) {
        let max_scroll = self.max_traffic_scroll(self.current_traffic_viewport_lines());
        self.traffic_scroll_from_top = self
            .traffic_scroll_from_top
            .saturating_add(rows)
            .min(max_scroll);
    }

    pub(super) fn scroll_traffic_newer(&mut self, rows: usize) {
        self.traffic_scroll_from_top = self.traffic_scroll_from_top.saturating_sub(rows);
    }

    pub(super) fn scroll_traffic_to_oldest(&mut self) {
        self.traffic_scroll_from_top =
            self.max_traffic_scroll(self.current_traffic_viewport_lines());
    }

    pub(super) fn scroll_traffic_to_latest(&mut self) {
        self.traffic_scroll_from_top = 0;
    }
}
