use super::App;
use super::helpers::*;
use super::types::*;
use crate::telemetry::{RuntimeStatus, TrafficRecord};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Cell, Paragraph, Row, Sparkline, Table, Tabs, Wrap},
};

impl App {
    pub(super) fn render(&mut self, frame: &mut Frame) {
        let root = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(TABS_HEIGHT),
                Constraint::Length(STATUS_HEIGHT),
                Constraint::Min(8),
                Constraint::Length(FOOTER_HEIGHT),
            ])
            .split(frame.area());

        self.render_tabs(frame, root[0]);
        self.render_status(frame, root[1]);
        match self.active_tab {
            AppTab::Agent => {
                let layout = self.agent_layout_from_body(root[2]);
                let highlight_trends_split =
                    self.is_hovering_trends_split || self.is_resizing_trends_split;
                let highlight_log_split = self.is_hovering_log_split || self.is_resizing_log_split;
                self.render_trends(frame, layout.trends);
                self.render_traffic_table(frame, layout.sessions_table, highlight_trends_split);
                self.render_logs(frame, layout.logs, highlight_log_split);
            }
            AppTab::TokioConsole => self.render_tokio_console_tab(frame, root[2]),
            AppTab::Config => self.render_config_tab(frame, root[2]),
        }
        self.render_help(frame, root[3]);
    }

    fn render_tabs(&self, frame: &mut Frame, area: Rect) {
        let titles = vec!["Agent", "Tokio Console", "Config"];
        let selected = match self.active_tab {
            AppTab::Agent => 0,
            AppTab::TokioConsole => 1,
            AppTab::Config => 2,
        };
        let tabs = Tabs::new(titles)
            .block(Block::bordered().title("Views"))
            .select(selected)
            .style(Style::default().fg(Color::DarkGray))
            .highlight_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            );
        frame.render_widget(tabs, area);
    }

    fn render_status(&self, frame: &mut Frame, area: Rect) {
        let (status_text, status_color) = match &self.status {
            RuntimeStatus::Starting => ("STARTING".to_string(), Color::Yellow),
            RuntimeStatus::Running => ("RUNNING".to_string(), Color::Green),
            RuntimeStatus::Stopping => ("STOPPING".to_string(), Color::Yellow),
            RuntimeStatus::Stopped => ("STOPPED".to_string(), Color::DarkGray),
            RuntimeStatus::Failed(message) => (format!("FAILED: {message}"), Color::Red),
        };
        let (console_text, console_color) = match self.console_state {
            TokioConsoleState::Running => ("RUNNING", Color::Green),
            TokioConsoleState::Stopped => ("STOPPED", Color::Yellow),
            TokioConsoleState::Disabled => ("DISABLED", Color::DarkGray),
            TokioConsoleState::Unsupported => ("UNSUPPORTED", Color::Red),
        };

        let line = Line::from(vec![
            Span::styled(" Status ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(status_text, Style::default().fg(status_color)),
            Span::raw(" | "),
            Span::styled("Sessions ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(self.completed_sessions.to_string()),
            Span::raw(" | "),
            Span::styled("Outbound ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format_bytes(self.total_outbound)),
            Span::raw(" | "),
            Span::styled("Inbound ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format_bytes(self.total_inbound)),
            Span::raw(" | "),
            Span::styled("Console ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(console_text, Style::default().fg(console_color)),
        ]);

        let widget = Paragraph::new(line)
            .block(
                Block::bordered()
                    .title("Agent")
                    .title_alignment(ratatui::layout::Alignment::Left),
            )
            .wrap(Wrap { trim: true });

        frame.render_widget(widget, area);
    }

    fn render_logs(&mut self, frame: &mut Frame, area: Rect, highlight_edge: bool) {
        let viewport_lines = area.height.saturating_sub(2) as usize;
        let max_scroll = self.max_log_scroll(viewport_lines);
        self.clamp_log_scroll(viewport_lines);
        let scroll_top = max_scroll.saturating_sub(self.log_scroll_from_bottom);
        let scroll_y = u16::try_from(scroll_top).unwrap_or(u16::MAX);

        let content = if self.logs.is_empty() {
            Text::from("No logs yet")
        } else {
            Text::from(
                self.logs
                    .iter()
                    .map(|line| styled_log_line(line))
                    .collect::<Vec<_>>(),
            )
        };

        let title = if self.log_scroll_from_bottom == 0 {
            format!("Agent Log ({}/{})", self.logs.len(), self.log_buffer_lines)
        } else {
            format!(
                "Agent Log ({}/{}, scrolled)",
                self.logs.len(),
                self.log_buffer_lines
            )
        };

        let log_view = Paragraph::new(content)
            .block(Block::bordered().title(title))
            .scroll((scroll_y, 0))
            .wrap(Wrap { trim: false });
        frame.render_widget(log_view, area);
        if highlight_edge {
            frame.render_widget(
                Block::default()
                    .borders(Borders::TOP)
                    .border_style(Style::default().fg(Color::LightCyan)),
                area,
            );
        }
        render_vertical_scrollbar(
            frame,
            area,
            self.logs.len(),
            viewport_lines,
            scroll_top,
            Color::Cyan,
        );
    }

    fn render_trends(&self, frame: &mut Frame, area: Rect) {
        if area.width < 3 || area.height < 2 {
            return;
        }

        let sections = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);

        let max_points = area.width.saturating_sub(2).max(1) as usize;
        let samples = self.last_traffic_samples(max_points);
        let mut outbound_data: Vec<u64> = samples.iter().map(|r| r.outbound_bytes).collect();
        let mut inbound_data: Vec<u64> = samples.iter().map(|r| r.inbound_bytes).collect();

        if outbound_data.is_empty() {
            outbound_data.push(0);
        }
        if inbound_data.is_empty() {
            inbound_data.push(0);
        }

        let outbound_max = outbound_data.iter().copied().max().unwrap_or(1).max(1);
        let inbound_max = inbound_data.iter().copied().max().unwrap_or(1).max(1);

        let outbound_graph = Sparkline::default()
            .block(Block::bordered().title("Outbound Trend"))
            .style(Style::default().fg(Color::Yellow))
            .data(&outbound_data)
            .max(outbound_max);
        frame.render_widget(outbound_graph, sections[0]);

        let inbound_graph = Sparkline::default()
            .block(Block::bordered().title("Inbound Trend"))
            .style(Style::default().fg(Color::Green))
            .data(&inbound_data)
            .max(inbound_max);
        frame.render_widget(inbound_graph, sections[1]);
    }

    fn render_traffic_table(&mut self, frame: &mut Frame, area: Rect, highlight_edge: bool) {
        let viewport_rows = traffic_table_viewport_rows(area);
        self.clamp_traffic_scroll(viewport_rows);

        let rows: Vec<Row> = if self.traffic.is_empty() {
            vec![Row::new(vec![
                Cell::from("-"),
                Cell::from("-"),
                Cell::from("No traffic yet"),
                Cell::from("-"),
                Cell::from("-"),
            ])]
        } else {
            self.traffic
                .iter()
                .rev()
                .skip(self.traffic_scroll_from_top)
                .take(viewport_rows.max(1))
                .map(|record| {
                    Row::new(vec![
                        Cell::from(format_hhmmss(record.timestamp_secs)),
                        Cell::from(record.protocol.clone()),
                        Cell::from(record.target.clone()),
                        Cell::from(format_bytes(record.outbound_bytes)),
                        Cell::from(format_bytes(record.inbound_bytes)),
                    ])
                })
                .collect()
        };

        let header = Row::new(vec!["Time", "Type", "Target", "Out", "In"]).style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );

        let title = if self.traffic_scroll_from_top == 0 {
            format!(
                "Recent Sessions ({}/{})",
                self.traffic.len(),
                MAX_TRAFFIC_ROWS
            )
        } else {
            format!(
                "Recent Sessions ({}/{}, scrolled)",
                self.traffic.len(),
                MAX_TRAFFIC_ROWS
            )
        };

        let table = Table::new(
            rows,
            [
                Constraint::Length(8),
                Constraint::Length(14),
                Constraint::Min(16),
                Constraint::Length(9),
                Constraint::Length(9),
            ],
        )
        .header(header)
        .block(Block::bordered().title(title))
        .column_spacing(1);

        frame.render_widget(table, area);
        if highlight_edge {
            frame.render_widget(
                Block::default()
                    .borders(Borders::LEFT)
                    .border_style(Style::default().fg(Color::LightCyan)),
                area,
            );
        }
        render_vertical_scrollbar(
            frame,
            area,
            self.traffic.len(),
            viewport_rows,
            self.traffic_scroll_from_top,
            Color::Yellow,
        );
    }

    fn last_traffic_samples(&self, max_points: usize) -> Vec<&TrafficRecord> {
        let point_count = max_points.max(1);
        let start = self.traffic.len().saturating_sub(point_count);
        self.traffic.iter().skip(start).collect()
    }

    fn render_help(&self, frame: &mut Frame, area: Rect) {
        let paragraph = Paragraph::new(Text::from(self.control_help_lines()))
            .block(Block::bordered().title("Controls"))
            .wrap(Wrap { trim: false });
        frame.render_widget(paragraph, area);
    }

    fn control_help_lines(&self) -> Vec<Line<'static>> {
        if self.active_tab == AppTab::TokioConsole {
            return vec![
                Line::from(vec![
                    "Views ".into(),
                    "<Tab/1/2/3>".cyan().bold(),
                    "  Quit ".into(),
                    "<Q>".red().bold(),
                ]),
                Line::from(vec![
                    "Agent ".into(),
                    "<S start>".green().bold(),
                    " ".into(),
                    "<X stop>".yellow().bold(),
                    "  Console ".into(),
                    "<K resume>".green().bold(),
                    " ".into(),
                    "<L pause>".yellow().bold(),
                    " ".into(),
                    "<Space toggle>".cyan().bold(),
                ]),
                Line::from(vec![
                    "Tasks ".into(),
                    "<Up/Down/Pg/Home/End>".cyan().bold(),
                    " / ".into(),
                    "<Wheel/Click>".cyan().bold(),
                    "  Ops ".into(),
                    "<R refresh>".blue().bold(),
                    " ".into(),
                    "<D details>".blue().bold(),
                    " ".into(),
                    "<H live>".blue().bold(),
                    " ".into(),
                    "<M sort>".blue().bold(),
                ]),
            ];
        }

        if self.active_tab == AppTab::Config {
            return vec![
                Line::from(vec![
                    "Views ".into(),
                    "<Tab/1/2/3>".cyan().bold(),
                    "  Quit ".into(),
                    "<Q>".red().bold(),
                ]),
                Line::from(vec![
                    "Select ".into(),
                    "<Up/Down/Pg/Home/End>".cyan().bold(),
                    " / ".into(),
                    "<Wheel/Click>".cyan().bold(),
                    "  Edit ".into(),
                    "<Enter/E>".green().bold(),
                    " ".into(),
                    "<Esc cancel>".yellow().bold(),
                ]),
                Line::from(vec![
                    "File ".into(),
                    "<W save>".blue().bold(),
                    " ".into(),
                    "<R reload>".blue().bold(),
                    "  Agent ".into(),
                    "<S start>".green().bold(),
                    " ".into(),
                    "<X stop>".yellow().bold(),
                ]),
            ];
        }

        vec![
            Line::from(vec![
                "Views ".into(),
                "<Tab/1/2/3>".cyan().bold(),
                "  Quit ".into(),
                "<Q>".red().bold(),
            ]),
            Line::from(vec![
                "Agent ".into(),
                "<S start>".green().bold(),
                " ".into(),
                "<X stop>".yellow().bold(),
                " ".into(),
                "<C clear-log>".blue().bold(),
                "  Console ".into(),
                "<K resume>".green().bold(),
                " ".into(),
                "<L pause>".yellow().bold(),
            ]),
            Line::from(vec![
                "Log ".into(),
                "<Up/Down/Pg/Home/End>".cyan().bold(),
                "  Sessions ".into(),
                "<Shift+Up/Down/Pg/Home/End>".cyan().bold(),
                "  Mouse ".into(),
                "<Drag split + Wheel scroll>".cyan().bold(),
            ]),
        ]
    }

    pub(super) fn render_config_tab(&mut self, frame: &mut Frame, area: Rect) {
        let layout = self.config_layout_from_body(area);
        let save_time = self
            .config_last_saved_secs
            .map(format_hhmmss)
            .unwrap_or_else(|| "-".to_string());
        let message_style = if self.config_message_is_error {
            Style::default().fg(Color::Red)
        } else {
            Style::default().fg(Color::Green)
        };
        let dirty_text = if self.config_dirty { "YES" } else { "NO" };
        let dirty_color = if self.config_dirty {
            Color::Yellow
        } else {
            Color::Green
        };

        let summary = Text::from(vec![
            Line::from(vec![
                Span::styled("File: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(self.config_path.clone()),
            ]),
            Line::from(vec![
                Span::styled("Unsaved: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::styled(dirty_text, Style::default().fg(dirty_color)),
                Span::raw(" | "),
                Span::styled("Last save: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(save_time),
                Span::raw(" | "),
                Span::styled("Mode: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(if self.config_is_editing {
                    "editing"
                } else {
                    "navigate"
                }),
            ]),
            Line::from(Span::styled(
                self.config_message
                    .clone()
                    .unwrap_or_else(|| "Select a field and press Enter to edit.".to_string()),
                message_style,
            )),
        ]);

        let summary_panel = Paragraph::new(summary)
            .block(Block::bordered().title("Configuration"))
            .wrap(Wrap { trim: false });
        frame.render_widget(summary_panel, layout.summary);

        let fields = Self::config_fields();
        let viewport_rows = config_table_viewport_rows(layout.fields_table);
        self.clamp_config_scroll(viewport_rows);
        self.keep_config_selection_visible(viewport_rows);

        let rows = fields
            .iter()
            .enumerate()
            .skip(self.config_scroll_from_top)
            .take(viewport_rows.max(1))
            .map(|(index, field)| {
                let mut row = Row::new(vec![
                    Cell::from(field.label()),
                    Cell::from(field.value(&self.config)),
                ]);
                if index == self.config_selected_index {
                    row = row.style(
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    );
                }
                row
            })
            .collect::<Vec<_>>();

        let header = Row::new(vec!["Key", "Value"]).style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );

        let table = Table::new(rows, [Constraint::Length(30), Constraint::Min(20)])
            .header(header)
            .block(Block::bordered().title("Fields"))
            .column_spacing(1);
        frame.render_widget(table, layout.fields_table);
        render_vertical_scrollbar(
            frame,
            layout.fields_table,
            fields.len(),
            viewport_rows,
            self.config_scroll_from_top,
            Color::Cyan,
        );

        let editor_text = if self.config_is_editing {
            let value_width = layout.editor.width.saturating_sub(12) as usize;
            let visible_value = tail_fit_text(&self.config_edit_buffer, value_width.max(1));
            Text::from(vec![
                Line::from(vec![
                    Span::styled("Value: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(visible_value),
                    Span::styled("█", Style::default().fg(Color::Cyan)),
                ]),
                Line::from(vec![
                    Span::styled("Editing ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(self.selected_config_field().label()),
                    Span::raw(" (Enter=apply, Esc=cancel)"),
                ]),
            ])
        } else {
            Text::from(vec![
                Line::from("Press Enter/E to edit selected field."),
                Line::from("Press W to save file, R to reload from disk."),
            ])
        };

        let editor_panel = Paragraph::new(editor_text)
            .block(Block::bordered().title("Editor"))
            .wrap(Wrap { trim: false });
        frame.render_widget(editor_panel, layout.editor);
    }

    pub(super) fn render_tokio_console_tab(&mut self, frame: &mut Frame, area: Rect) {
        let layout = self.tokio_console_layout_from_body(area);
        self.ensure_console_task_selection();

        let endpoint = self
            .config
            .console_port
            .map(|port| format!("127.0.0.1:{port}"))
            .unwrap_or_else(|| "Not configured".to_string());
        let temporality = self
            .console_temporality
            .as_deref()
            .unwrap_or("UNKNOWN")
            .to_string();
        let last_update = self
            .console_last_update_secs
            .map(format_hhmmss)
            .unwrap_or_else(|| "-".to_string());
        let error_line = self
            .console_last_error
            .as_deref()
            .map(|err| format!("Last error: {err}"))
            .unwrap_or_else(|| "Last error: -".to_string());
        let task_details_update = self
            .console_task_details_last_update_secs
            .map(format_hhmmss)
            .unwrap_or_else(|| "-".to_string());
        let selected = self
            .console_selected_task_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "-".to_string());

        let summary = Text::from(vec![
            Line::from(vec![
                Span::styled("Endpoint: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(endpoint),
            ]),
            Line::from(vec![
                Span::styled(
                    "Aggregator: ",
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw(temporality),
                Span::raw(" | "),
                Span::styled("Tasks: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(format!(
                    "{}/{} live",
                    self.console_live_tasks,
                    self.console_tasks.len()
                )),
                Span::raw(" | "),
                Span::styled(
                    "Dropped Events: ",
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw(self.console_dropped_task_events.to_string()),
                Span::raw(" | "),
                Span::styled("Sort: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(self.console_sort.as_str()),
                Span::raw(" | "),
                Span::styled("Filter: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(if self.console_only_live {
                    "live-only"
                } else {
                    "all"
                }),
            ]),
            Line::from(vec![
                Span::styled("Snapshot: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(last_update),
                Span::raw(" | "),
                Span::styled(
                    "Task details: ",
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw(task_details_update),
                Span::raw(" | "),
                Span::styled("Selected: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(selected),
            ]),
            Line::from(Span::styled(error_line, Style::default().fg(Color::Red))),
            Line::from(vec![
                Span::styled("Ops: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(
                    "K/L or Space pause-resume | R refresh | H live filter | M sort | D details",
                ),
            ]),
        ]);

        let summary_panel = Paragraph::new(summary)
            .block(Block::bordered().title("Tokio Console"))
            .wrap(Wrap { trim: false });
        frame.render_widget(summary_panel, layout.summary);

        let visible_tasks = self.console_visible_tasks();
        let viewport_rows = tokio_tasks_table_viewport_rows(layout.tasks_table);
        self.clamp_console_task_scroll(visible_tasks.len(), viewport_rows);
        self.keep_console_selection_visible_with_tasks(&visible_tasks, viewport_rows);

        let rows: Vec<Row> = if visible_tasks.is_empty() {
            let empty_message = if self.console_only_live {
                "No live task data yet"
            } else {
                "No task data yet"
            };
            vec![Row::new(vec![
                Cell::from("-"),
                Cell::from("-"),
                Cell::from(empty_message),
                Cell::from("-"),
                Cell::from("-"),
                Cell::from("-"),
                Cell::from("-"),
            ])]
        } else {
            visible_tasks
                .iter()
                .skip(self.console_task_scroll_from_top)
                .take(viewport_rows.max(1))
                .map(|task| {
                    let mut row = Row::new(vec![
                        Cell::from(task.id.to_string()),
                        Cell::from(task.kind.clone()),
                        Cell::from(task.name.clone()),
                        Cell::from(if task.is_live { "LIVE" } else { "DONE" }),
                        Cell::from(task.polls.to_string()),
                        Cell::from(task.wakes.to_string()),
                        Cell::from(task.self_wakes.to_string()),
                    ]);
                    if self.console_selected_task_id == Some(task.id) {
                        row = row.style(
                            Style::default()
                                .fg(Color::Black)
                                .bg(Color::Cyan)
                                .add_modifier(Modifier::BOLD),
                        );
                    }
                    row
                })
                .collect()
        };

        let header = Row::new(vec![
            "ID", "Kind", "Task", "State", "Polls", "Wakes", "Self",
        ])
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );

        let table_title = if self.console_task_scroll_from_top == 0 {
            format!(
                "Runtime Tasks ({}/{})",
                visible_tasks.len(),
                self.console_tasks.len()
            )
        } else {
            format!(
                "Runtime Tasks ({}/{}, scrolled)",
                visible_tasks.len(),
                self.console_tasks.len()
            )
        };

        let table = Table::new(
            rows,
            [
                Constraint::Length(8),
                Constraint::Length(9),
                Constraint::Min(18),
                Constraint::Length(7),
                Constraint::Length(8),
                Constraint::Length(8),
                Constraint::Length(8),
            ],
        )
        .header(header)
        .block(Block::bordered().title(table_title))
        .column_spacing(1);
        frame.render_widget(table, layout.tasks_table);
        render_vertical_scrollbar(
            frame,
            layout.tasks_table,
            visible_tasks.len(),
            viewport_rows,
            self.console_task_scroll_from_top,
            Color::Cyan,
        );

        let details_text = self.render_console_task_details_text();
        let details_panel = Paragraph::new(details_text)
            .block(Block::bordered().title("Task Details"))
            .wrap(Wrap { trim: false });
        frame.render_widget(details_panel, layout.task_details);
    }

    fn render_console_task_details_text(&self) -> Text<'static> {
        let Some(selected_id) = self.console_selected_task_id else {
            return Text::from(vec![
                Line::from("No task selected"),
                Line::from("Use Up/Down or mouse wheel in task table."),
            ]);
        };

        let selected_task = self
            .console_tasks
            .iter()
            .find(|task| task.id == selected_id)
            .cloned();
        let mut lines = vec![Line::from(vec![
            Span::styled("Task ID: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(selected_id.to_string()),
        ])];

        if let Some(task) = selected_task {
            lines.push(Line::from(vec![
                Span::styled("Task: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(task.name),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Kind: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(task.kind),
                Span::raw(" | "),
                Span::styled("State: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(if task.is_live { "LIVE" } else { "DONE" }),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Polls: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(task.polls.to_string()),
                Span::raw(" | "),
                Span::styled("Wakes: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(task.wakes.to_string()),
                Span::raw(" | "),
                Span::styled("Self: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(task.self_wakes.to_string()),
            ]));
        }

        match &self.console_task_details {
            Some(details) if details.task_id == selected_id => {
                let detail_ts = details
                    .updated_at_secs
                    .map(format_hhmmss)
                    .unwrap_or_else(|| "-".to_string());
                lines.push(Line::from(vec![
                    Span::styled(
                        "Details update: ",
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(detail_ts),
                ]));
                lines.push(Line::from(vec![
                    Span::styled(
                        "Poll histogram: ",
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format!(
                        "max={}, outliers={}, highest={}",
                        details
                            .poll_histogram_max_ns
                            .map(format_duration_ns)
                            .unwrap_or_else(|| "-".to_string()),
                        details.poll_histogram_high_outliers,
                        details
                            .poll_histogram_highest_outlier_ns
                            .map(format_duration_ns)
                            .unwrap_or_else(|| "-".to_string())
                    )),
                ]));
                lines.push(Line::from(vec![
                    Span::styled(
                        "Scheduled histogram: ",
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format!(
                        "max={}, outliers={}, highest={}",
                        details
                            .scheduled_histogram_max_ns
                            .map(format_duration_ns)
                            .unwrap_or_else(|| "-".to_string()),
                        details.scheduled_histogram_high_outliers,
                        details
                            .scheduled_histogram_highest_outlier_ns
                            .map(format_duration_ns)
                            .unwrap_or_else(|| "-".to_string())
                    )),
                ]));
            }
            _ => {
                lines.push(Line::from(
                    "Task details are loading. Press D to force refresh.",
                ));
            }
        }

        if let Some(err) = &self.console_task_details_error {
            lines.push(Line::from(Span::styled(
                format!("Details error: {err}"),
                Style::default().fg(Color::Red),
            )));
        }

        Text::from(lines)
    }
}
