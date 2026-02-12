use crate::config::ProxyConfig;
use crate::server::ProxyServer;
use crate::telemetry::{RuntimeStatus, TrafficRecord, UiEvent, emit_status, reload_log_level};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::{
    DefaultTerminal, Frame,
    layout::{Constraint, Direction, Layout, Margin, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{
        Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState,
        Sparkline, Table, Tabs, Wrap,
    },
};
use std::collections::VecDeque;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

const MAX_TRAFFIC_ROWS: usize = 400;
const LOG_BUFFER_LINES: usize = 1_000;
const TABS_HEIGHT: u16 = 3;
const STATUS_HEIGHT: u16 = 4;
const FOOTER_HEIGHT: u16 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppTab {
    Proxy,
    Config,
}

impl AppTab {
    fn next(self) -> Self {
        match self {
            Self::Proxy => Self::Config,
            Self::Config => Self::Proxy,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ConfigFieldKey {
    ListenAddr,
    ApiAddr,
    EnableApi,
    LogLevel,
    LogDir,
    LogFile,
    RuntimeThreads,
    CompressionMode,
    ForwardMode,
    ConnectTimeoutSecs,
}

impl ConfigFieldKey {
    const ALL: [ConfigFieldKey; 10] = [
        ConfigFieldKey::ListenAddr,
        ConfigFieldKey::ApiAddr,
        ConfigFieldKey::EnableApi,
        ConfigFieldKey::LogLevel,
        ConfigFieldKey::LogDir,
        ConfigFieldKey::LogFile,
        ConfigFieldKey::RuntimeThreads,
        ConfigFieldKey::CompressionMode,
        ConfigFieldKey::ForwardMode,
        ConfigFieldKey::ConnectTimeoutSecs,
    ];

    fn label(self) -> &'static str {
        match self {
            ConfigFieldKey::ListenAddr => "listen_addr",
            ConfigFieldKey::ApiAddr => "api_addr",
            ConfigFieldKey::EnableApi => "enable_api",
            ConfigFieldKey::LogLevel => "log_level",
            ConfigFieldKey::LogDir => "log_dir",
            ConfigFieldKey::LogFile => "log_file",
            ConfigFieldKey::RuntimeThreads => "runtime_threads",
            ConfigFieldKey::CompressionMode => "compression_mode",
            ConfigFieldKey::ForwardMode => "forward_mode",
            ConfigFieldKey::ConnectTimeoutSecs => "connect_timeout_secs",
        }
    }

    fn value(self, config: &ProxyConfig) -> String {
        match self {
            ConfigFieldKey::ListenAddr => config.listen_addr.clone(),
            ConfigFieldKey::ApiAddr => config.api_addr.clone(),
            ConfigFieldKey::EnableApi => config.enable_api.to_string(),
            ConfigFieldKey::LogLevel => config.log_level.clone(),
            ConfigFieldKey::LogDir => config.log_dir.clone().unwrap_or_default(),
            ConfigFieldKey::LogFile => config.log_file.clone(),
            ConfigFieldKey::RuntimeThreads => config
                .runtime_threads
                .map(|threads| threads.to_string())
                .unwrap_or_default(),
            ConfigFieldKey::CompressionMode => config.compression_mode.clone(),
            ConfigFieldKey::ForwardMode => config.forward_mode.to_string(),
            ConfigFieldKey::ConnectTimeoutSecs => config.connect_timeout_secs.to_string(),
        }
    }

    fn apply(self, config: &mut ProxyConfig, input: &str) -> std::result::Result<(), String> {
        let value = input.trim();
        match self {
            ConfigFieldKey::ListenAddr => {
                if value.is_empty() {
                    return Err("listen_addr cannot be empty".to_string());
                }
                config.listen_addr = value.to_string();
            }
            ConfigFieldKey::ApiAddr => {
                if value.is_empty() {
                    return Err("api_addr cannot be empty".to_string());
                }
                config.api_addr = value.to_string();
            }
            ConfigFieldKey::EnableApi => {
                config.enable_api = parse_bool(value, "enable_api")?;
            }
            ConfigFieldKey::LogLevel => {
                if value.is_empty() {
                    return Err("log_level cannot be empty".to_string());
                }
                config.log_level = value.to_string();
            }
            ConfigFieldKey::LogDir => {
                if value.is_empty() || value.eq_ignore_ascii_case("none") {
                    config.log_dir = None;
                } else {
                    config.log_dir = Some(value.to_string());
                }
            }
            ConfigFieldKey::LogFile => {
                if value.is_empty() {
                    return Err("log_file cannot be empty".to_string());
                }
                config.log_file = value.to_string();
            }
            ConfigFieldKey::RuntimeThreads => {
                if value.is_empty() || value.eq_ignore_ascii_case("none") {
                    config.runtime_threads = None;
                } else {
                    let parsed = value
                        .parse::<usize>()
                        .map_err(|_| "runtime_threads must be a positive integer".to_string())?;
                    if parsed == 0 {
                        return Err("runtime_threads must be > 0".to_string());
                    }
                    config.runtime_threads = Some(parsed);
                }
            }
            ConfigFieldKey::CompressionMode => {
                if value.is_empty() {
                    return Err("compression_mode cannot be empty".to_string());
                }
                config.compression_mode = value.to_string();
            }
            ConfigFieldKey::ForwardMode => {
                config.forward_mode = parse_bool(value, "forward_mode")?;
            }
            ConfigFieldKey::ConnectTimeoutSecs => {
                let parsed = value
                    .parse::<u64>()
                    .map_err(|_| "connect_timeout_secs must be an integer".to_string())?;
                if parsed == 0 {
                    return Err("connect_timeout_secs must be > 0".to_string());
                }
                config.connect_timeout_secs = parsed;
            }
        }
        Ok(())
    }
}

fn parse_bool(value: &str, field_name: &str) -> std::result::Result<bool, String> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "y" | "on" => Ok(true),
        "false" | "0" | "no" | "n" | "off" => Ok(false),
        _ => Err(format!("{field_name} must be true/false")),
    }
}

pub async fn run(
    config: ProxyConfig,
    config_path: String,
    mut events: UnboundedReceiver<UiEvent>,
) -> Result<()> {
    let mut app = App::new(config, config_path);
    app.start_proxy();

    let mut terminal = ratatui::init();
    let run_result = run_app(&mut terminal, &mut app, &mut events).await;
    ratatui::restore();

    match run_result {
        Ok(AppExitAction::Shutdown) => {
            app.shutdown_on_exit().await;
            Ok(())
        }
        Ok(AppExitAction::DetachUi) => {
            if app.server_task.is_some() {
                println!("TUI closed. Proxy is still running. Press Ctrl+C to stop.");
                run_headless(&mut app, &mut events).await?;
            }
            Ok(())
        }
        Err(err) => {
            error!("TUI exited unexpectedly: {err}");
            if app.server_task.is_some() {
                eprintln!(
                    "TUI exited unexpectedly ({err}). Proxy is still running. Press Ctrl+C to stop."
                );
                run_headless(&mut app, &mut events).await?;
                Ok(())
            } else {
                Err(err)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppExitAction {
    DetachUi,
    Shutdown,
}

async fn run_app(
    terminal: &mut DefaultTerminal,
    app: &mut App,
    events: &mut UnboundedReceiver<UiEvent>,
) -> Result<AppExitAction> {
    loop {
        app.process_events(events);
        app.reap_server_task().await;
        terminal.draw(|frame| app.render(frame))?;

        if event::poll(Duration::from_millis(120))?
            && let Event::Key(key_event) = event::read()?
            && key_event.kind == KeyEventKind::Press
            && let Some(exit_action) = app.handle_key_event(key_event).await
        {
            return Ok(exit_action);
        }
    }
}

async fn run_headless(app: &mut App, events: &mut UnboundedReceiver<UiEvent>) -> Result<()> {
    loop {
        app.process_events(events);
        app.reap_server_task().await;

        if app.server_task.is_none() {
            return Ok(());
        }

        tokio::select! {
            signal_result = tokio::signal::ctrl_c() => {
                match signal_result {
                    Ok(()) => info!("Ctrl+C received, shutting down proxy"),
                    Err(err) => error!("Failed to receive Ctrl+C signal: {err}"),
                }
                app.shutdown_on_exit().await;
                return Ok(());
            }
            _ = tokio::time::sleep(Duration::from_millis(250)) => {}
        }
    }
}

struct App {
    config: ProxyConfig,
    config_path: String,
    status: RuntimeStatus,
    active_tab: AppTab,
    logs: VecDeque<String>,
    traffic: VecDeque<TrafficRecord>,
    total_outbound: u64,
    total_inbound: u64,
    completed_sessions: u64,
    log_scroll_from_bottom: usize,
    traffic_scroll_from_top: usize,
    config_selected_index: usize,
    config_scroll_from_top: usize,
    config_is_editing: bool,
    config_edit_buffer: String,
    config_dirty: bool,
    config_message: Option<String>,
    config_message_is_error: bool,
    server_shutdown: Option<CancellationToken>,
    server_task: Option<JoinHandle<()>>,
}

impl App {
    fn new(config: ProxyConfig, config_path: String) -> Self {
        Self {
            config,
            config_path,
            status: RuntimeStatus::Stopped,
            active_tab: AppTab::Proxy,
            logs: VecDeque::new(),
            traffic: VecDeque::new(),
            total_outbound: 0,
            total_inbound: 0,
            completed_sessions: 0,
            log_scroll_from_bottom: 0,
            traffic_scroll_from_top: 0,
            config_selected_index: 0,
            config_scroll_from_top: 0,
            config_is_editing: false,
            config_edit_buffer: String::new(),
            config_dirty: false,
            config_message: None,
            config_message_is_error: false,
            server_shutdown: None,
            server_task: None,
        }
    }

    fn start_proxy(&mut self) {
        if self.server_task.is_some() {
            return;
        }

        self.status = RuntimeStatus::Starting;
        emit_status(RuntimeStatus::Starting);

        let config = self.config.clone();
        let shutdown = CancellationToken::new();
        let server_shutdown = shutdown.child_token();

        let task = tokio::spawn(async move {
            info!("Starting PPAASS Proxy");
            info!("Listen address: {}", config.listen_addr);
            info!("API address: {}", config.api_addr);
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

            match ProxyServer::new(config).await {
                Ok(server) => {
                    emit_status(RuntimeStatus::Running);
                    if let Err(err) = server.run(server_shutdown.clone()).await {
                        if server_shutdown.is_cancelled() {
                            emit_status(RuntimeStatus::Stopped);
                        } else {
                            error!("Proxy server stopped with error: {}", err);
                            emit_status(RuntimeStatus::Failed(err.to_string()));
                        }
                    } else {
                        emit_status(RuntimeStatus::Stopped);
                    }
                }
                Err(err) => {
                    error!("Failed to initialize proxy server: {}", err);
                    emit_status(RuntimeStatus::Failed(err.to_string()));
                }
            }
        });

        self.server_shutdown = Some(shutdown);
        self.server_task = Some(task);
    }

    fn stop_proxy(&mut self) {
        if self.server_task.is_none() {
            self.status = RuntimeStatus::Stopped;
            return;
        }

        self.status = RuntimeStatus::Stopping;
        emit_status(RuntimeStatus::Stopping);
        if let Some(shutdown) = self.server_shutdown.take() {
            shutdown.cancel();
        }
    }

    async fn reap_server_task(&mut self) {
        if self
            .server_task
            .as_ref()
            .is_some_and(|server_task| server_task.is_finished())
        {
            let Some(server_task) = self.server_task.take() else {
                return;
            };
            if let Err(err) = server_task.await {
                self.push_log(format!("server task join error: {err}"));
                if !matches!(self.status, RuntimeStatus::Failed(_)) {
                    self.status = RuntimeStatus::Stopped;
                }
            }
            self.server_shutdown = None;
        }
    }

    async fn shutdown_on_exit(&mut self) {
        self.stop_proxy();

        let Some(mut server_task) = self.server_task.take() else {
            return;
        };

        let timer = tokio::time::sleep(Duration::from_secs(2));
        tokio::pin!(timer);

        tokio::select! {
            result = &mut server_task => {
                if let Err(err) = result {
                    self.push_log(format!("server task join error during shutdown: {err}"));
                }
            }
            _ = &mut timer => {
                server_task.abort();
                let _ = server_task.await;
                self.push_log("Server shutdown timed out; task was aborted".to_string());
            }
        }

        self.server_shutdown = None;
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
        while self.logs.len() > LOG_BUFFER_LINES {
            self.logs.pop_front();
        }
    }

    fn push_traffic(&mut self, record: TrafficRecord) {
        self.total_outbound = self.total_outbound.saturating_add(record.outbound_bytes);
        self.total_inbound = self.total_inbound.saturating_add(record.inbound_bytes);
        self.completed_sessions = self.completed_sessions.saturating_add(1);

        self.traffic.push_back(record);
        while self.traffic.len() > MAX_TRAFFIC_ROWS {
            self.traffic.pop_front();
        }
    }

    async fn handle_key_event(&mut self, key_event: KeyEvent) -> Option<AppExitAction> {
        match (key_event.code, key_event.modifiers) {
            (KeyCode::Char('q'), _) => return Some(AppExitAction::DetachUi),
            (KeyCode::Char('c'), modifiers) if modifiers.contains(KeyModifiers::CONTROL) => {
                return Some(AppExitAction::Shutdown);
            }
            (KeyCode::Tab, _) => {
                if !self.config_is_editing {
                    self.active_tab = self.active_tab.next();
                }
                return None;
            }
            _ => {}
        }

        match self.active_tab {
            AppTab::Proxy => self.handle_proxy_key_event(key_event),
            AppTab::Config => self.handle_config_key_event(key_event),
        }

        None
    }

    fn handle_proxy_key_event(&mut self, key_event: KeyEvent) {
        match key_event.code {
            KeyCode::Char('s') => {
                if self.server_task.is_some() {
                    self.stop_proxy();
                } else {
                    self.start_proxy();
                }
            }
            KeyCode::Char('r') => self.reload_config_from_file(),
            KeyCode::Char('c') => self.logs.clear(),
            KeyCode::Up => {
                self.traffic_scroll_from_top = self.traffic_scroll_from_top.saturating_add(1)
            }
            KeyCode::Down => {
                self.traffic_scroll_from_top = self.traffic_scroll_from_top.saturating_sub(1)
            }
            KeyCode::PageUp => {
                self.log_scroll_from_bottom = self.log_scroll_from_bottom.saturating_add(10)
            }
            KeyCode::PageDown => {
                self.log_scroll_from_bottom = self.log_scroll_from_bottom.saturating_sub(10)
            }
            KeyCode::End => {
                self.log_scroll_from_bottom = 0;
                self.traffic_scroll_from_top = 0;
            }
            _ => {}
        }
    }

    fn handle_config_key_event(&mut self, key_event: KeyEvent) {
        if self.config_is_editing {
            self.handle_config_edit_key_event(key_event);
            return;
        }

        match key_event.code {
            KeyCode::Up => {
                self.config_selected_index = self.config_selected_index.saturating_sub(1)
            }
            KeyCode::Down => {
                let max_index = ConfigFieldKey::ALL.len().saturating_sub(1);
                self.config_selected_index = (self.config_selected_index + 1).min(max_index);
            }
            KeyCode::Enter | KeyCode::Char('e') => self.begin_config_edit(),
            KeyCode::Char('s') => self.save_config_to_file(),
            KeyCode::Char('r') => self.reload_config_from_file(),
            _ => {}
        }
    }

    fn handle_config_edit_key_event(&mut self, key_event: KeyEvent) {
        match key_event.code {
            KeyCode::Esc => {
                self.config_is_editing = false;
                self.config_edit_buffer.clear();
                self.set_config_message("Edit cancelled".to_string(), false);
            }
            KeyCode::Enter => self.apply_config_edit(),
            KeyCode::Backspace => {
                self.config_edit_buffer.pop();
            }
            KeyCode::Char(ch)
                if !key_event.modifiers.contains(KeyModifiers::CONTROL)
                    && !key_event.modifiers.contains(KeyModifiers::ALT) =>
            {
                self.config_edit_buffer.push(ch);
            }
            _ => {}
        }
    }

    fn begin_config_edit(&mut self) {
        let field = self.current_config_field();
        self.config_edit_buffer = field.value(&self.config);
        self.config_is_editing = true;
        self.set_config_message(format!("Editing {}", field.label()), false);
    }

    fn apply_config_edit(&mut self) {
        let field = self.current_config_field();
        match field.apply(&mut self.config, &self.config_edit_buffer) {
            Ok(()) => {
                self.config_is_editing = false;
                self.config_edit_buffer.clear();
                self.config_dirty = true;
                self.set_config_message(format!("Updated {}", field.label()), false);
                if matches!(field, ConfigFieldKey::LogLevel)
                    && let Err(err) = reload_log_level(&self.config.log_level)
                {
                    self.set_config_message(
                        format!("Updated log_level, but live reload failed: {err}"),
                        true,
                    );
                }
            }
            Err(err) => self.set_config_message(err, true),
        }
    }

    fn save_config_to_file(&mut self) {
        match self.config.save(Path::new(&self.config_path)) {
            Ok(()) => {
                self.config_dirty = false;
                self.set_config_message(
                    format!("Saved configuration to {}", self.config_path),
                    false,
                );
            }
            Err(err) => self.set_config_message(format!("Failed to save config: {err}"), true),
        }
    }

    fn reload_config_from_file(&mut self) {
        match ProxyConfig::load(Path::new(&self.config_path)) {
            Ok(config) => {
                self.config = config;
                self.config_dirty = false;
                self.config_is_editing = false;
                self.config_edit_buffer.clear();
                self.set_config_message(
                    format!("Reloaded configuration from {}", self.config_path),
                    false,
                );
                if let Err(err) = reload_log_level(&self.config.log_level) {
                    self.set_config_message(
                        format!("Config reloaded, but log level reload failed: {err}"),
                        true,
                    );
                }
            }
            Err(err) => self.set_config_message(format!("Failed to reload config: {err}"), true),
        }
    }

    fn current_config_field(&self) -> ConfigFieldKey {
        ConfigFieldKey::ALL
            .get(self.config_selected_index)
            .copied()
            .unwrap_or(ConfigFieldKey::ListenAddr)
    }

    fn set_config_message(&mut self, message: String, is_error: bool) {
        self.config_message = Some(message);
        self.config_message_is_error = is_error;
    }

    fn render(&mut self, frame: &mut Frame) {
        let sections = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(TABS_HEIGHT),
                Constraint::Length(STATUS_HEIGHT),
                Constraint::Min(8),
                Constraint::Length(FOOTER_HEIGHT),
            ])
            .split(frame.area());

        self.render_tabs(frame, sections[0]);
        self.render_status(frame, sections[1]);

        match self.active_tab {
            AppTab::Proxy => self.render_proxy_tab(frame, sections[2]),
            AppTab::Config => self.render_config_tab(frame, sections[2]),
        }

        self.render_help(frame, sections[3]);
    }

    fn render_tabs(&self, frame: &mut Frame, area: Rect) {
        let titles = [" Proxy ", " Config "]
            .into_iter()
            .map(Line::from)
            .collect::<Vec<_>>();
        let selected = match self.active_tab {
            AppTab::Proxy => 0,
            AppTab::Config => 1,
        };
        let tabs = Tabs::new(titles)
            .select(selected)
            .style(Style::default().fg(Color::Gray))
            .highlight_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .divider("|")
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" PPAASS Proxy "),
            );
        frame.render_widget(tabs, area);
    }

    fn render_status(&self, frame: &mut Frame, area: Rect) {
        let (status_label, status_style) = match &self.status {
            RuntimeStatus::Starting => ("STARTING", Style::default().fg(Color::Yellow).bold()),
            RuntimeStatus::Running => ("RUNNING", Style::default().fg(Color::Green).bold()),
            RuntimeStatus::Stopping => ("STOPPING", Style::default().fg(Color::Yellow).bold()),
            RuntimeStatus::Stopped => ("STOPPED", Style::default().fg(Color::Gray).bold()),
            RuntimeStatus::Failed(_) => ("FAILED", Style::default().fg(Color::Red).bold()),
        };

        let mut lines = vec![Line::from(vec![
            Span::styled("Status: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(status_label, status_style),
            Span::raw("  "),
            Span::styled("Sessions: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(self.completed_sessions.to_string()),
            Span::raw("  "),
            Span::styled("Outbound: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format_bytes(self.total_outbound)),
            Span::raw("  "),
            Span::styled("Inbound: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format_bytes(self.total_inbound)),
        ])];

        if let RuntimeStatus::Failed(err) = &self.status {
            lines.push(Line::from(Span::styled(
                format!("Error: {err}"),
                Style::default().fg(Color::Red),
            )));
        }

        let panel = Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::ALL).title(" Runtime "));
        frame.render_widget(panel, area);
    }

    fn render_proxy_tab(&mut self, frame: &mut Frame, area: Rect) {
        let vertical = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
            .split(area);

        let top = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
            .split(vertical[0]);

        let samples = self.last_traffic_samples(top[0].width.saturating_sub(4).max(12) as usize);
        let outbound = samples
            .iter()
            .map(|record| record.outbound_bytes)
            .collect::<Vec<_>>();

        let summary = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(8), Constraint::Min(4)])
            .split(top[0]);

        let summary_lines = vec![
            Line::from(vec![
                Span::styled("Listen: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(self.config.listen_addr.clone()),
            ]),
            Line::from(vec![
                Span::styled("API: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(if self.config.enable_api {
                    format!("enabled ({})", self.config.api_addr)
                } else {
                    "disabled".to_string()
                }),
            ]),
            Line::from(vec![
                Span::styled("Mode: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(if self.config.forward_mode {
                    "forward"
                } else {
                    "direct"
                }),
                Span::raw("  "),
                Span::styled(
                    "Compression: ",
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw(self.config.compression_mode.clone()),
            ]),
            Line::from(vec![
                Span::styled("Config: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(self.config_path.clone()),
            ]),
        ];

        frame.render_widget(
            Paragraph::new(summary_lines)
                .wrap(Wrap { trim: true })
                .block(Block::default().borders(Borders::ALL).title(" Proxy ")),
            summary[0],
        );

        frame.render_widget(
            Sparkline::default()
                .data(&outbound)
                .style(Style::default().fg(Color::Cyan))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Outbound/session "),
                ),
            summary[1],
        );

        self.render_traffic_table(frame, top[1]);
        self.render_logs(frame, vertical[1]);
    }

    fn render_traffic_table(&mut self, frame: &mut Frame, area: Rect) {
        let viewport_rows = traffic_table_viewport_rows(area).max(1);
        let max_scroll = self.traffic.len().saturating_sub(viewport_rows);
        self.traffic_scroll_from_top = self.traffic_scroll_from_top.min(max_scroll);

        let rows = self
            .traffic
            .iter()
            .rev()
            .skip(self.traffic_scroll_from_top)
            .take(viewport_rows)
            .map(|record| {
                Row::new(vec![
                    Cell::from(format_hhmmss(record.timestamp_secs)),
                    Cell::from(tail_fit_text(&record.protocol, 12)),
                    Cell::from(tail_fit_text(&record.target, 40)),
                    Cell::from(format_bytes(record.outbound_bytes)),
                    Cell::from(format_bytes(record.inbound_bytes)),
                ])
            })
            .collect::<Vec<_>>();

        let table = Table::new(
            rows,
            [
                Constraint::Length(10),
                Constraint::Length(12),
                Constraint::Percentage(55),
                Constraint::Length(11),
                Constraint::Length(11),
            ],
        )
        .header(
            Row::new(vec!["Time", "Proto", "Target", "Out", "In"]).style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        )
        .block(Block::default().borders(Borders::ALL).title(" Sessions "));
        frame.render_widget(table, area);

        render_vertical_scrollbar(
            frame,
            area,
            self.traffic.len(),
            viewport_rows,
            self.traffic_scroll_from_top,
            Color::Cyan,
        );
    }

    fn render_logs(&mut self, frame: &mut Frame, area: Rect) {
        let viewport_rows = logs_viewport_rows(area).max(1);
        let total_logs = self.logs.len();
        let max_scroll = total_logs.saturating_sub(viewport_rows);
        self.log_scroll_from_bottom = self.log_scroll_from_bottom.min(max_scroll);

        let end = total_logs.saturating_sub(self.log_scroll_from_bottom);
        let start = end.saturating_sub(viewport_rows);
        let lines = self
            .logs
            .iter()
            .skip(start)
            .take(end.saturating_sub(start))
            .map(|line| styled_log_line(line))
            .collect::<Vec<_>>();

        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .block(Block::default().borders(Borders::ALL).title(" Logs ")),
            area,
        );

        let position = max_scroll.saturating_sub(self.log_scroll_from_bottom);
        render_vertical_scrollbar(
            frame,
            area,
            total_logs,
            viewport_rows,
            position,
            Color::Green,
        );
    }

    fn render_config_tab(&mut self, frame: &mut Frame, area: Rect) {
        let sections = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(8), Constraint::Length(8)])
            .split(area);

        let viewport_rows = config_table_viewport_rows(sections[0]).max(1);
        self.sync_config_scroll(viewport_rows);

        let rows = ConfigFieldKey::ALL
            .iter()
            .enumerate()
            .skip(self.config_scroll_from_top)
            .take(viewport_rows)
            .map(|(index, field)| {
                let row_style = if index == self.config_selected_index {
                    Style::default().bg(Color::DarkGray).fg(Color::White)
                } else {
                    Style::default()
                };
                Row::new(vec![
                    Cell::from(field.label()),
                    Cell::from(tail_fit_text(&field.value(&self.config), 90)),
                ])
                .style(row_style)
            })
            .collect::<Vec<_>>();

        let table = Table::new(rows, [Constraint::Length(28), Constraint::Min(20)])
            .header(
                Row::new(vec!["Field", "Value"]).style(
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
            )
            .block(Block::default().borders(Borders::ALL).title(" Config "));
        frame.render_widget(table, sections[0]);

        render_vertical_scrollbar(
            frame,
            sections[0],
            ConfigFieldKey::ALL.len(),
            viewport_rows,
            self.config_scroll_from_top,
            Color::Cyan,
        );

        let selected_field = self.current_config_field();
        let mut editor_lines = vec![Line::from(vec![
            Span::styled("Selected: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(selected_field.label()),
        ])];

        if self.config_is_editing {
            editor_lines.push(Line::from(vec![
                Span::styled("Input: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(self.config_edit_buffer.clone()),
            ]));
            editor_lines.push(Line::from("Enter=apply  Esc=cancel"));
        } else {
            editor_lines.push(Line::from("Up/Down=select  Enter/E=edit  S=save  R=reload"));
        }

        editor_lines.push(Line::from(vec![
            Span::styled("Unsaved: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(if self.config_dirty { "yes" } else { "no" }),
        ]));

        if let Some(message) = &self.config_message {
            editor_lines.push(Line::from(Span::styled(
                message.clone(),
                if self.config_message_is_error {
                    Style::default().fg(Color::Red)
                } else {
                    Style::default().fg(Color::Green)
                },
            )));
        }

        frame.render_widget(
            Paragraph::new(editor_lines)
                .wrap(Wrap { trim: false })
                .block(Block::default().borders(Borders::ALL).title(" Editor ")),
            sections[1],
        );
    }

    fn render_help(&self, frame: &mut Frame, area: Rect) {
        let lines = match self.active_tab {
            AppTab::Proxy => vec![
                Line::from(vec![
                    "  Q ".bold(),
                    "close tui".into(),
                    "  TAB ".bold().cyan(),
                    "switch tab".into(),
                    "  S ".bold().green(),
                    "start/stop".into(),
                    "  R ".bold().yellow(),
                    "reload config".into(),
                    "  C ".bold(),
                    "clear logs".into(),
                ]),
                Line::from(vec![
                    "  Up/Down ".bold(),
                    "scroll sessions".into(),
                    "  PgUp/PgDn ".bold(),
                    "scroll logs".into(),
                    "  End ".bold(),
                    "latest".into(),
                    "  Ctrl+C ".bold().red(),
                    "shutdown".into(),
                ]),
            ],
            AppTab::Config => vec![
                Line::from(vec![
                    "  TAB ".bold().cyan(),
                    "switch tab".into(),
                    "  Enter/E ".bold().green(),
                    "edit field".into(),
                    "  S ".bold().green(),
                    "save".into(),
                    "  R ".bold().yellow(),
                    "reload".into(),
                    "  Q ".bold(),
                    "close tui".into(),
                ]),
                Line::from(vec!["  Ctrl+C ".bold().red(), "shutdown".into()]),
            ],
        };

        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .block(Block::default().borders(Borders::ALL).title(" Help ")),
            area,
        );
    }

    fn sync_config_scroll(&mut self, viewport_rows: usize) {
        if self.config_selected_index < self.config_scroll_from_top {
            self.config_scroll_from_top = self.config_selected_index;
            return;
        }

        let end = self.config_scroll_from_top.saturating_add(viewport_rows);
        if self.config_selected_index >= end {
            self.config_scroll_from_top = self
                .config_selected_index
                .saturating_add(1)
                .saturating_sub(viewport_rows);
        }
    }

    fn last_traffic_samples(&self, max_points: usize) -> Vec<&TrafficRecord> {
        if max_points == 0 || self.traffic.is_empty() {
            return Vec::new();
        }
        let take_count = self.traffic.len().min(max_points);
        self.traffic
            .iter()
            .skip(self.traffic.len().saturating_sub(take_count))
            .collect()
    }
}

fn logs_viewport_rows(area: Rect) -> usize {
    area.height.saturating_sub(2) as usize
}

fn traffic_table_viewport_rows(area: Rect) -> usize {
    area.height.saturating_sub(3) as usize
}

fn config_table_viewport_rows(area: Rect) -> usize {
    area.height.saturating_sub(3) as usize
}

fn render_vertical_scrollbar(
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

    let mut state = ScrollbarState::new(content_length)
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
        &mut state,
    );
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

fn tail_fit_text(input: &str, max_chars: usize) -> String {
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

#[allow(dead_code)]
fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
