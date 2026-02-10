use crate::config::AgentConfig;
use crate::server::AgentServer;
use crate::telemetry::{RuntimeStatus, TrafficRecord, UiEvent, emit_status};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    DefaultTerminal, Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, Cell, Paragraph, Row, Sparkline, Table, Wrap},
};
use std::collections::VecDeque;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

const MAX_LOG_LINES: usize = 600;
const MAX_TRAFFIC_ROWS: usize = 400;

pub async fn run(config: AgentConfig, mut events: UnboundedReceiver<UiEvent>) -> Result<()> {
    let mut terminal = ratatui::init();
    let run_result = run_app(&mut terminal, config, &mut events).await;
    ratatui::restore();
    run_result
}

async fn run_app(
    terminal: &mut DefaultTerminal,
    config: AgentConfig,
    events: &mut UnboundedReceiver<UiEvent>,
) -> Result<()> {
    let mut app = App::new(config);
    app.start_agent();

    loop {
        app.process_events(events);
        app.reap_server_task().await;

        terminal.draw(|frame| app.render(frame))?;

        if event::poll(Duration::from_millis(120))?
            && let Event::Key(key_event) = event::read()?
            && key_event.kind == KeyEventKind::Press
            && app.handle_key_event(key_event.code).await
        {
            break;
        }
    }

    app.shutdown_on_exit().await;
    Ok(())
}

struct App {
    config: AgentConfig,
    status: RuntimeStatus,
    logs: VecDeque<String>,
    traffic: VecDeque<TrafficRecord>,
    total_outbound: u64,
    total_inbound: u64,
    completed_sessions: u64,
    server_shutdown: Option<CancellationToken>,
    server_task: Option<JoinHandle<()>>,
}

impl App {
    fn new(config: AgentConfig) -> Self {
        Self {
            config,
            status: RuntimeStatus::Stopped,
            logs: VecDeque::new(),
            traffic: VecDeque::new(),
            total_outbound: 0,
            total_inbound: 0,
            completed_sessions: 0,
            server_shutdown: None,
            server_task: None,
        }
    }

    fn start_agent(&mut self) {
        if self.server_task.is_some() {
            return;
        }

        self.status = RuntimeStatus::Starting;
        emit_status(RuntimeStatus::Starting);

        let config = self.config.clone();
        let shutdown = CancellationToken::new();
        let server_shutdown = shutdown.child_token();

        let task = tokio::spawn(async move {
            info!("Starting PPAASS Agent");
            info!("Listen address: {}", config.listen_addr);
            info!("Proxy addresses: [{}]", config.proxy_addrs.join(", "));
            info!("Username: {}", config.username);
            info!("Log level: {}", config.log_level);
            info!(
                "Log directory: {}",
                config.log_dir.as_deref().unwrap_or("UI only")
            );
            if config.log_dir.is_some() {
                info!("Log file: {}", config.log_file);
            }
            if let Some(threads) = config.runtime_threads {
                info!("Runtime threads: {}", threads);
            } else {
                info!("Runtime threads: default (CPU cores)");
            }

            match AgentServer::new(config).await {
                Ok(server) => {
                    emit_status(RuntimeStatus::Running);
                    if let Err(err) = server.run(server_shutdown).await {
                        error!("Agent server stopped with error: {}", err);
                        emit_status(RuntimeStatus::Failed(err.to_string()));
                    } else {
                        info!("Agent server stopped");
                        emit_status(RuntimeStatus::Stopped);
                    }
                }
                Err(err) => {
                    error!("Failed to initialize agent server: {}", err);
                    emit_status(RuntimeStatus::Failed(err.to_string()));
                }
            }
        });

        self.server_shutdown = Some(shutdown);
        self.server_task = Some(task);
    }

    fn request_stop(&mut self) {
        if self.server_task.is_none() {
            return;
        }

        self.status = RuntimeStatus::Stopping;
        emit_status(RuntimeStatus::Stopping);

        if let Some(shutdown) = &self.server_shutdown {
            shutdown.cancel();
        }
    }

    async fn reap_server_task(&mut self) {
        let is_finished = self
            .server_task
            .as_ref()
            .is_some_and(|task| task.is_finished());
        if !is_finished {
            return;
        }

        if let Some(task) = self.server_task.take()
            && let Err(err) = task.await
        {
            self.push_log(format!("server task join error: {err}"));
            self.status = RuntimeStatus::Failed(err.to_string());
        }

        self.server_shutdown = None;
        if matches!(
            self.status,
            RuntimeStatus::Running | RuntimeStatus::Starting | RuntimeStatus::Stopping
        ) {
            self.status = RuntimeStatus::Stopped;
        }
    }

    async fn shutdown_on_exit(&mut self) {
        if let Some(shutdown) = &self.server_shutdown {
            shutdown.cancel();
        }

        if let Some(task) = self.server_task.take() {
            let _ = task.await;
        }

        self.server_shutdown = None;
        self.status = RuntimeStatus::Stopped;
    }

    fn process_events(&mut self, events: &mut UnboundedReceiver<UiEvent>) {
        while let Ok(event) = events.try_recv() {
            match event {
                UiEvent::Log(line) => self.push_log(line),
                UiEvent::Status(status) => self.status = status,
                UiEvent::Traffic(record) => self.push_traffic(record),
            }
        }
    }

    fn push_log(&mut self, line: String) {
        self.logs.push_back(line);
        if self.logs.len() > MAX_LOG_LINES {
            self.logs.pop_front();
        }
    }

    fn push_traffic(&mut self, record: TrafficRecord) {
        self.total_outbound = self.total_outbound.saturating_add(record.outbound_bytes);
        self.total_inbound = self.total_inbound.saturating_add(record.inbound_bytes);
        self.completed_sessions = self.completed_sessions.saturating_add(1);
        self.traffic.push_back(record);
        if self.traffic.len() > MAX_TRAFFIC_ROWS {
            self.traffic.pop_front();
        }
    }

    async fn handle_key_event(&mut self, code: KeyCode) -> bool {
        match code {
            KeyCode::Char('q') => true,
            KeyCode::Char('s') => {
                self.start_agent();
                false
            }
            KeyCode::Char('x') => {
                self.request_stop();
                false
            }
            KeyCode::Char('c') => {
                self.logs.clear();
                false
            }
            _ => false,
        }
    }

    fn render(&self, frame: &mut Frame) {
        let root = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(4),
                Constraint::Min(8),
                Constraint::Length(3),
            ])
            .split(frame.area());

        self.render_status(frame, root[0]);

        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
            .split(root[1]);

        self.render_logs(frame, body[0]);
        self.render_traffic(frame, body[1]);
        self.render_help(frame, root[2]);
    }

    fn render_status(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let (status_text, status_color) = match &self.status {
            RuntimeStatus::Starting => ("STARTING".to_string(), Color::Yellow),
            RuntimeStatus::Running => ("RUNNING".to_string(), Color::Green),
            RuntimeStatus::Stopping => ("STOPPING".to_string(), Color::Yellow),
            RuntimeStatus::Stopped => ("STOPPED".to_string(), Color::DarkGray),
            RuntimeStatus::Failed(message) => (format!("FAILED: {message}"), Color::Red),
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

    fn render_logs(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let content = if self.logs.is_empty() {
            Text::from("No logs yet")
        } else {
            Text::from(
                self.logs
                    .iter()
                    .rev()
                    .map(|line| styled_log_line(line))
                    .collect::<Vec<_>>(),
            )
        };

        let log_view = Paragraph::new(content)
            .block(Block::bordered().title("Agent Log"))
            .wrap(Wrap { trim: false });
        frame.render_widget(log_view, area);
    }

    fn render_traffic(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        if area.height < 9 {
            self.render_traffic_table(frame, area);
            return;
        }

        let sections = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(4),
                Constraint::Length(4),
                Constraint::Min(3),
            ])
            .split(area);

        let max_points = sections[0].width.saturating_sub(2).max(1) as usize;
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

        self.render_traffic_table(frame, sections[2]);
    }

    fn render_traffic_table(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
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
        .block(Block::bordered().title("Recent Sessions"))
        .column_spacing(1);

        frame.render_widget(table, area);
    }

    fn last_traffic_samples(&self, max_points: usize) -> Vec<&TrafficRecord> {
        let point_count = max_points.max(1);
        let start = self.traffic.len().saturating_sub(point_count);
        self.traffic.iter().skip(start).collect()
    }

    fn render_help(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let help = Line::from(vec![
            "Start ".into(),
            "<S>".green().bold(),
            "  Stop ".into(),
            "<X>".yellow().bold(),
            "  Clear Logs ".into(),
            "<C>".blue().bold(),
            "  Quit ".into(),
            "<Q>".red().bold(),
        ]);

        let paragraph = Paragraph::new(help)
            .block(Block::bordered().title("Controls"))
            .wrap(Wrap { trim: true });
        frame.render_widget(paragraph, area);
    }
}

fn format_hhmmss(timestamp_secs: u64) -> String {
    let day_secs = timestamp_secs % 86_400;
    let hours = day_secs / 3_600;
    let minutes = (day_secs % 3_600) / 60;
    let seconds = day_secs % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

fn format_bytes(bytes: u64) -> String {
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

fn styled_log_line(line: &str) -> Line<'static> {
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

fn detect_log_level(line: &str) -> Option<(usize, usize, Color)> {
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
