use super::App;
use super::helpers::{config_table_viewport_rows, now_unix_secs};
use super::types::*;
use crate::config::AgentConfig;
use crate::telemetry::reload_log_level;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::Rect;
use std::path::Path;

impl App {
    pub(super) fn config_fields() -> &'static [ConfigFieldKey] {
        &ConfigFieldKey::ALL
    }

    pub(super) fn selected_config_field(&self) -> ConfigFieldKey {
        let fields = Self::config_fields();
        let index = self
            .config_selected_index
            .min(fields.len().saturating_sub(1));
        fields[index]
    }

    pub(super) fn current_config_viewport_rows(&self) -> usize {
        self.current_config_layout_rects()
            .map(|layout| config_table_viewport_rows(layout.fields_table))
            .unwrap_or(1)
            .max(1)
    }

    pub(super) fn max_config_scroll(&self, viewport_rows: usize) -> usize {
        Self::config_fields()
            .len()
            .saturating_sub(viewport_rows.max(1))
    }

    pub(super) fn clamp_config_scroll(&mut self, viewport_rows: usize) {
        self.config_scroll_from_top = self
            .config_scroll_from_top
            .min(self.max_config_scroll(viewport_rows));
    }

    pub(super) fn keep_config_selection_visible(&mut self, viewport_rows: usize) {
        if self.config_selected_index < self.config_scroll_from_top {
            self.config_scroll_from_top = self.config_selected_index;
            return;
        }

        let end = self
            .config_scroll_from_top
            .saturating_add(viewport_rows.max(1));
        if self.config_selected_index >= end {
            self.config_scroll_from_top = self
                .config_selected_index
                .saturating_add(1)
                .saturating_sub(viewport_rows.max(1));
        }
    }

    pub(super) fn move_config_selection(&mut self, delta: isize) {
        if self.config_is_editing {
            return;
        }
        let field_count = Self::config_fields().len();
        if field_count == 0 {
            self.config_selected_index = 0;
            self.config_scroll_from_top = 0;
            return;
        }

        let last = field_count.saturating_sub(1);
        self.config_selected_index = if delta < 0 {
            self.config_selected_index
                .saturating_sub(delta.unsigned_abs())
        } else {
            self.config_selected_index
                .saturating_add(delta as usize)
                .min(last)
        };

        let viewport = self.current_config_viewport_rows();
        self.clamp_config_scroll(viewport);
        self.keep_config_selection_visible(viewport);
    }

    pub(super) fn select_config_row_from_mouse(&mut self, table_area: Rect, mouse_row: u16) {
        if self.config_is_editing {
            return;
        }

        let row_start = table_area.y.saturating_add(2);
        if mouse_row < row_start {
            return;
        }
        let row_offset = mouse_row.saturating_sub(row_start) as usize;
        let viewport_rows = config_table_viewport_rows(table_area);
        if row_offset >= viewport_rows {
            return;
        }

        let row_index = self.config_scroll_from_top.saturating_add(row_offset);
        if row_index < Self::config_fields().len() {
            self.config_selected_index = row_index;
            self.clamp_config_scroll(viewport_rows);
            self.keep_config_selection_visible(viewport_rows);
        }
    }

    pub(super) fn handle_config_key_event(&mut self, key_event: KeyEvent) -> bool {
        match key_event.code {
            KeyCode::Up => {
                self.move_config_selection(-1);
                false
            }
            KeyCode::Down => {
                self.move_config_selection(1);
                false
            }
            KeyCode::PageUp => {
                self.move_config_selection(-8);
                false
            }
            KeyCode::PageDown => {
                self.move_config_selection(8);
                false
            }
            KeyCode::Home => {
                self.config_selected_index = 0;
                self.config_scroll_from_top = 0;
                false
            }
            KeyCode::End => {
                let last = Self::config_fields().len().saturating_sub(1);
                self.config_selected_index = last;
                let viewport = self.current_config_viewport_rows();
                self.config_scroll_from_top = self.max_config_scroll(viewport);
                false
            }
            KeyCode::Enter | KeyCode::Char('e') | KeyCode::Char('E') => {
                self.start_config_editing();
                false
            }
            KeyCode::Char('w') | KeyCode::Char('W') => {
                self.save_config_to_file();
                false
            }
            KeyCode::Char('r') | KeyCode::Char('R') => {
                self.reload_config_from_file();
                false
            }
            _ => false,
        }
    }

    pub(super) fn handle_config_edit_input(&mut self, key_event: KeyEvent) {
        match key_event.code {
            KeyCode::Esc => {
                self.config_is_editing = false;
                self.config_edit_buffer.clear();
                self.set_config_message("Edit cancelled", false);
            }
            KeyCode::Enter => {
                self.apply_config_edit_value();
            }
            KeyCode::Backspace => {
                self.config_edit_buffer.pop();
            }
            KeyCode::Char(ch) => {
                if key_event.modifiers.contains(KeyModifiers::CONTROL) {
                    return;
                }
                self.config_edit_buffer.push(ch);
            }
            KeyCode::Tab => {}
            _ => {}
        }
    }

    pub(super) fn set_config_message<S: Into<String>>(&mut self, message: S, is_error: bool) {
        self.config_message = Some(message.into());
        self.config_message_is_error = is_error;
    }

    fn start_config_editing(&mut self) {
        if self.config_is_editing {
            return;
        }
        let field = self.selected_config_field();
        self.config_edit_buffer = field.value(&self.config);
        self.config_is_editing = true;
        self.set_config_message(
            format!(
                "Editing {}. Press Enter to apply, Esc to cancel.",
                field.label()
            ),
            false,
        );
    }

    fn apply_config_edit_value(&mut self) {
        let field = self.selected_config_field();
        let mut next_config = self.config.clone();
        match field.apply(&mut next_config, &self.config_edit_buffer) {
            Ok(()) => {
                self.config = next_config;
                self.config_is_editing = false;
                self.config_edit_buffer.clear();
                self.config_dirty = true;
                self.sync_ui_state_with_config();
                self.set_config_message(
                    format!("Updated {}. Press W to save file.", field.label()),
                    false,
                );
            }
            Err(err) => {
                self.set_config_message(
                    format!("Invalid value for {}: {}", field.label(), err),
                    true,
                );
            }
        }
    }

    pub(super) fn sync_ui_state_with_config(&mut self) {
        self.log_buffer_lines = self.config.log_buffer_lines.max(1);
        while self.logs.len() > self.log_buffer_lines {
            self.logs.pop_front();
        }
        self.clamp_log_scroll(self.current_log_viewport_lines());
        self.console_state = match self.config.console_port {
            Some(_) if cfg!(feature = "console") => TokioConsoleState::Running,
            Some(_) => TokioConsoleState::Unsupported,
            None => TokioConsoleState::Disabled,
        };
        if self.config.console_port.is_none() {
            self.console_temporality = None;
            self.console_tasks.clear();
            self.console_live_tasks = 0;
            self.console_dropped_task_events = 0;
            self.console_last_error = None;
            self.console_selected_task_id = None;
            self.console_task_details = None;
            self.console_task_details_error = None;
        }
        self.last_console_probe_secs = None;
        self.console_last_details_probe_secs = None;
    }

    fn save_config_to_file(&mut self) {
        if self.config_is_editing {
            self.set_config_message("Finish editing first (Enter or Esc).", true);
            return;
        }

        if let Some(parent) = Path::new(&self.config_path).parent()
            && !parent.as_os_str().is_empty()
            && let Err(err) = std::fs::create_dir_all(parent)
        {
            self.set_config_message(format!("Failed to create config directory: {err}"), true);
            return;
        }

        match self.config.save(&self.config_path) {
            Ok(()) => {
                self.config_dirty = false;
                self.config_last_saved_secs = Some(now_unix_secs());
                self.set_config_message(
                    format!("Configuration saved to {}", self.config_path),
                    false,
                );
            }
            Err(err) => {
                self.set_config_message(
                    format!("Failed to save {}: {}", self.config_path, err),
                    true,
                );
            }
        }
    }

    fn reload_config_from_file(&mut self) {
        let _ = self.reload_config_from_file_internal(false);
    }

    pub(super) fn reload_config_from_file_internal(&mut self, for_agent_action: bool) -> bool {
        if self.config_is_editing {
            self.set_config_message("Finish editing first (Enter or Esc).", true);
            return false;
        }

        match AgentConfig::load(&self.config_path) {
            Ok(config) => {
                if let Err(err) = reload_log_level(&config.log_level) {
                    self.set_config_message(
                        format!(
                            "Failed to apply log_level from {}: {}",
                            self.config_path, err
                        ),
                        true,
                    );
                    return false;
                }
                self.config = config;
                self.config_dirty = false;
                self.sync_ui_state_with_config();
                if for_agent_action {
                    self.set_config_message(
                        format!(
                            "Reloaded configuration from {} before agent action",
                            self.config_path
                        ),
                        false,
                    );
                } else {
                    self.set_config_message(
                        format!("Reloaded configuration from {}", self.config_path),
                        false,
                    );
                }
                true
            }
            Err(err) => {
                self.set_config_message(
                    format!("Failed to reload {}: {}", self.config_path, err),
                    true,
                );
                false
            }
        }
    }
}
