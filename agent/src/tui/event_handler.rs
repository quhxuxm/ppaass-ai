use super::App;
use super::helpers::rect_contains;
use super::types::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::layout::Rect;

impl App {
    pub(super) async fn handle_key_event(&mut self, key_event: KeyEvent) -> bool {
        if self.active_tab == AppTab::Config && self.config_is_editing {
            self.handle_config_edit_input(key_event);
            return false;
        }

        if key_event.modifiers.contains(KeyModifiers::SHIFT) && self.active_tab == AppTab::Agent {
            match key_event.code {
                KeyCode::Up => {
                    self.scroll_traffic_older(1);
                    return false;
                }
                KeyCode::Down => {
                    self.scroll_traffic_newer(1);
                    return false;
                }
                KeyCode::PageUp => {
                    self.scroll_traffic_older(12);
                    return false;
                }
                KeyCode::PageDown => {
                    self.scroll_traffic_newer(12);
                    return false;
                }
                KeyCode::Home => {
                    self.scroll_traffic_to_oldest();
                    return false;
                }
                KeyCode::End => {
                    self.scroll_traffic_to_latest();
                    return false;
                }
                _ => {}
            }
        }

        match key_event.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => return true,
            KeyCode::Tab => {
                self.switch_tab();
                return false;
            }
            KeyCode::Char('1') => {
                self.active_tab = AppTab::Agent;
                return false;
            }
            KeyCode::Char('2') => {
                self.active_tab = AppTab::TokioConsole;
                self.ensure_console_task_selection();
                return false;
            }
            KeyCode::Char('3') => {
                self.active_tab = AppTab::Config;
                return false;
            }
            KeyCode::Char('s') | KeyCode::Char('S') => {
                self.start_agent();
                return false;
            }
            KeyCode::Char('x') | KeyCode::Char('X') => {
                self.request_stop();
                return false;
            }
            KeyCode::Char('k') | KeyCode::Char('K') => {
                self.start_tokio_console().await;
                return false;
            }
            KeyCode::Char('l') | KeyCode::Char('L') => {
                self.stop_tokio_console().await;
                return false;
            }
            _ => {}
        }

        if self.active_tab == AppTab::TokioConsole {
            return self.handle_tokio_console_key_event(key_event).await;
        }
        if self.active_tab == AppTab::Config {
            return self.handle_config_key_event(key_event);
        }

        match key_event.code {
            KeyCode::Char('c') | KeyCode::Char('C') => {
                self.logs.clear();
                self.log_scroll_from_bottom = 0;
                false
            }
            KeyCode::Up => {
                self.scroll_logs_older(1);
                false
            }
            KeyCode::Down => {
                self.scroll_logs_newer(1);
                false
            }
            KeyCode::PageUp => {
                self.scroll_logs_older(12);
                false
            }
            KeyCode::PageDown => {
                self.scroll_logs_newer(12);
                false
            }
            KeyCode::Home => {
                self.scroll_logs_to_oldest();
                false
            }
            KeyCode::End => {
                self.scroll_logs_to_latest();
                false
            }
            _ => false,
        }
    }

    fn switch_tab(&mut self) {
        self.active_tab = match self.active_tab {
            AppTab::Agent => AppTab::TokioConsole,
            AppTab::TokioConsole => AppTab::Config,
            AppTab::Config => AppTab::Agent,
        };
        if self.active_tab == AppTab::TokioConsole {
            self.ensure_console_task_selection();
        }
    }

    pub(super) fn handle_mouse_event(&mut self, mouse_event: MouseEvent) {
        let left_release = matches!(mouse_event.kind, MouseEventKind::Up(MouseButton::Left));

        if self.active_tab == AppTab::TokioConsole {
            self.is_hovering_trends_split = false;
            self.is_hovering_log_split = false;
            if let Some(layout) = self.current_tokio_console_layout_rects() {
                match mouse_event.kind {
                    MouseEventKind::ScrollUp
                        if rect_contains(
                            layout.tasks_table,
                            mouse_event.column,
                            mouse_event.row,
                        ) =>
                    {
                        self.move_console_selection(-3);
                    }
                    MouseEventKind::ScrollDown
                        if rect_contains(
                            layout.tasks_table,
                            mouse_event.column,
                            mouse_event.row,
                        ) =>
                    {
                        self.move_console_selection(3);
                    }
                    MouseEventKind::Down(MouseButton::Left)
                        if rect_contains(
                            layout.tasks_table,
                            mouse_event.column,
                            mouse_event.row,
                        ) =>
                    {
                        self.select_console_task_from_row(layout.tasks_table, mouse_event.row);
                    }
                    _ => {}
                }
            }
            if left_release {
                self.is_resizing_trends_split = false;
                self.is_resizing_log_split = false;
            }
            return;
        }

        if self.active_tab == AppTab::Config {
            self.is_hovering_trends_split = false;
            self.is_hovering_log_split = false;
            if let Some(layout) = self.current_config_layout_rects() {
                match mouse_event.kind {
                    MouseEventKind::ScrollUp
                        if rect_contains(
                            layout.fields_table,
                            mouse_event.column,
                            mouse_event.row,
                        ) =>
                    {
                        self.move_config_selection(-2);
                    }
                    MouseEventKind::ScrollDown
                        if rect_contains(
                            layout.fields_table,
                            mouse_event.column,
                            mouse_event.row,
                        ) =>
                    {
                        self.move_config_selection(2);
                    }
                    MouseEventKind::Down(MouseButton::Left)
                        if rect_contains(
                            layout.fields_table,
                            mouse_event.column,
                            mouse_event.row,
                        ) =>
                    {
                        self.select_config_row_from_mouse(layout.fields_table, mouse_event.row);
                    }
                    _ => {}
                }
            }

            if left_release {
                self.is_resizing_trends_split = false;
                self.is_resizing_log_split = false;
            }
            return;
        }

        let Some(layout) = self.current_agent_layout_rects() else {
            self.is_hovering_trends_split = false;
            self.is_hovering_log_split = false;
            if left_release {
                self.is_resizing_trends_split = false;
                self.is_resizing_log_split = false;
            }
            return;
        };

        let body = layout.body;
        if body.width < 10 || body.height < 6 {
            self.is_hovering_trends_split = false;
            self.is_hovering_log_split = false;
            if left_release {
                self.is_resizing_trends_split = false;
                self.is_resizing_log_split = false;
            }
            return;
        }

        let split_y = layout.logs.y;
        let split_x = layout.sessions.x;
        let in_top_rows = mouse_event.row >= layout.top.y
            && mouse_event.row < layout.top.y.saturating_add(layout.top.height);
        let near_vertical_split = mouse_event.column >= split_x.saturating_sub(1)
            && mouse_event.column <= split_x.saturating_add(1);
        let in_body_cols =
            mouse_event.column >= body.x && mouse_event.column < body.x.saturating_add(body.width);
        let near_horizontal_split = mouse_event.row >= split_y.saturating_sub(1)
            && mouse_event.row <= split_y.saturating_add(1);
        self.is_hovering_trends_split = in_top_rows && near_vertical_split;
        self.is_hovering_log_split = in_body_cols && near_horizontal_split;

        match mouse_event.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                if in_top_rows && near_vertical_split {
                    self.is_resizing_trends_split = true;
                    self.is_resizing_log_split = false;
                    self.update_trends_width_from_mouse(mouse_event.column, layout.top);
                } else if in_body_cols && near_horizontal_split {
                    self.is_resizing_log_split = true;
                    self.is_resizing_trends_split = false;
                    self.update_log_height_from_mouse(mouse_event.row, body);
                }
            }
            MouseEventKind::Drag(MouseButton::Left) => {
                if self.is_resizing_trends_split {
                    self.update_trends_width_from_mouse(mouse_event.column, layout.top);
                } else if self.is_resizing_log_split {
                    self.update_log_height_from_mouse(mouse_event.row, body);
                }
            }
            MouseEventKind::Moved => {
                // Some terminals emit Moved (instead of Drag) while the left button is held.
                if self.is_resizing_trends_split {
                    self.update_trends_width_from_mouse(mouse_event.column, layout.top);
                } else if self.is_resizing_log_split {
                    self.update_log_height_from_mouse(mouse_event.row, body);
                }
            }
            MouseEventKind::Up(MouseButton::Left) => {
                if self.is_resizing_trends_split {
                    self.update_trends_width_from_mouse(mouse_event.column, layout.top);
                }
                if self.is_resizing_log_split {
                    self.update_log_height_from_mouse(mouse_event.row, body);
                }
                self.is_resizing_trends_split = false;
                self.is_resizing_log_split = false;
            }
            MouseEventKind::ScrollUp
                if rect_contains(layout.logs, mouse_event.column, mouse_event.row) =>
            {
                self.scroll_logs_older(3);
            }
            MouseEventKind::ScrollDown
                if rect_contains(layout.logs, mouse_event.column, mouse_event.row) =>
            {
                self.scroll_logs_newer(3);
            }
            MouseEventKind::ScrollUp
                if rect_contains(layout.sessions_table, mouse_event.column, mouse_event.row) =>
            {
                self.scroll_traffic_older(3);
            }
            MouseEventKind::ScrollDown
                if rect_contains(layout.sessions_table, mouse_event.column, mouse_event.row) =>
            {
                self.scroll_traffic_newer(3);
            }
            _ => {}
        }
    }

    fn update_trends_width_from_mouse(&mut self, column: u16, top: Rect) {
        let relative_x = column.saturating_sub(top.x);
        let width = top.width.max(1);
        let percent = ((relative_x as u32 * 100) / width as u32) as u16;
        self.trends_width_percent = percent.clamp(TRENDS_LEFT_MIN_PERCENT, TRENDS_LEFT_MAX_PERCENT);
    }

    fn update_log_height_from_mouse(&mut self, row: u16, body: Rect) {
        let relative_y = row.saturating_sub(body.y);
        let height = body.height.max(1);
        let top_percent = ((relative_y as u32 * 100) / height as u32) as u16;
        let log_percent = 100u16.saturating_sub(top_percent);
        self.log_height_percent = log_percent.clamp(LOG_HEIGHT_MIN_PERCENT, LOG_HEIGHT_MAX_PERCENT);
    }
}
