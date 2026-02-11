use crate::config::AgentConfig;
use crate::server::AgentServer;
use crate::telemetry::{RuntimeStatus, TrafficRecord, UiEvent, emit_status};
use anyhow::Result;
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
        KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
    },
    execute,
};
use ratatui::{
    DefaultTerminal, Frame,
    layout::{Constraint, Direction, Layout, Margin, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{
        Block, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Sparkline,
        Table, Tabs, Wrap,
    },
};
use std::cmp::Ordering;
#[cfg(feature = "console")]
use std::collections::HashMap;
use std::collections::VecDeque;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

const MAX_TRAFFIC_ROWS: usize = 400;
const TRENDS_LEFT_DEFAULT_PERCENT: u16 = 40;
const TRENDS_LEFT_MIN_PERCENT: u16 = 20;
const TRENDS_LEFT_MAX_PERCENT: u16 = 70;
const LOG_HEIGHT_DEFAULT_PERCENT: u16 = 30;
const LOG_HEIGHT_MIN_PERCENT: u16 = 15;
const LOG_HEIGHT_MAX_PERCENT: u16 = 70;
const TABS_HEIGHT: u16 = 3;
const STATUS_HEIGHT: u16 = 4;
const FOOTER_HEIGHT: u16 = 5;
const TOKIO_TASKS_WIDTH_PERCENT: u16 = 68;

#[derive(Debug, Clone, Copy)]
struct AgentLayoutRects {
    body: Rect,
    top: Rect,
    logs: Rect,
    trends: Rect,
    sessions: Rect,
    sessions_table: Rect,
}

#[derive(Debug, Clone, Copy)]
struct TokioConsoleLayoutRects {
    summary: Rect,
    tasks_table: Rect,
    task_details: Rect,
}

#[derive(Debug, Clone, Copy)]
struct ConfigLayoutRects {
    summary: Rect,
    fields_table: Rect,
    editor: Rect,
}

#[cfg_attr(not(feature = "console"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokioConsoleState {
    Disabled,
    Unsupported,
    Running,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppTab {
    Agent,
    TokioConsole,
    Config,
}

#[derive(Debug, Clone, Copy)]
enum ConfigFieldKey {
    ListenAddr,
    ProxyAddrs,
    Username,
    PrivateKeyPath,
    AsyncRuntimeStackSizeMb,
    PoolSize,
    ConnectTimeoutSecs,
    ConsolePort,
    LogLevel,
    LogDir,
    LogFile,
    LogBufferLines,
    RuntimeThreads,
}

impl ConfigFieldKey {
    const ALL: [ConfigFieldKey; 13] = [
        ConfigFieldKey::ListenAddr,
        ConfigFieldKey::ProxyAddrs,
        ConfigFieldKey::Username,
        ConfigFieldKey::PrivateKeyPath,
        ConfigFieldKey::AsyncRuntimeStackSizeMb,
        ConfigFieldKey::PoolSize,
        ConfigFieldKey::ConnectTimeoutSecs,
        ConfigFieldKey::ConsolePort,
        ConfigFieldKey::LogLevel,
        ConfigFieldKey::LogDir,
        ConfigFieldKey::LogFile,
        ConfigFieldKey::LogBufferLines,
        ConfigFieldKey::RuntimeThreads,
    ];

    fn label(self) -> &'static str {
        match self {
            ConfigFieldKey::ListenAddr => "listen_addr",
            ConfigFieldKey::ProxyAddrs => "proxy_addrs",
            ConfigFieldKey::Username => "username",
            ConfigFieldKey::PrivateKeyPath => "private_key_path",
            ConfigFieldKey::AsyncRuntimeStackSizeMb => "async_runtime_stack_size_mb",
            ConfigFieldKey::PoolSize => "pool_size",
            ConfigFieldKey::ConnectTimeoutSecs => "connect_timeout_secs",
            ConfigFieldKey::ConsolePort => "console_port",
            ConfigFieldKey::LogLevel => "log_level",
            ConfigFieldKey::LogDir => "log_dir",
            ConfigFieldKey::LogFile => "log_file",
            ConfigFieldKey::LogBufferLines => "log_buffer_lines",
            ConfigFieldKey::RuntimeThreads => "runtime_threads",
        }
    }

    fn value(self, config: &AgentConfig) -> String {
        match self {
            ConfigFieldKey::ListenAddr => config.listen_addr.clone(),
            ConfigFieldKey::ProxyAddrs => config.proxy_addrs.join(", "),
            ConfigFieldKey::Username => config.username.clone(),
            ConfigFieldKey::PrivateKeyPath => config.private_key_path.clone(),
            ConfigFieldKey::AsyncRuntimeStackSizeMb => {
                config.async_runtime_stack_size_mb.to_string()
            }
            ConfigFieldKey::PoolSize => config.pool_size.to_string(),
            ConfigFieldKey::ConnectTimeoutSecs => config.connect_timeout_secs.to_string(),
            ConfigFieldKey::ConsolePort => config
                .console_port
                .map(|port| port.to_string())
                .unwrap_or_default(),
            ConfigFieldKey::LogLevel => config.log_level.clone(),
            ConfigFieldKey::LogDir => config.log_dir.clone().unwrap_or_default(),
            ConfigFieldKey::LogFile => config.log_file.clone(),
            ConfigFieldKey::LogBufferLines => config.log_buffer_lines.to_string(),
            ConfigFieldKey::RuntimeThreads => config
                .runtime_threads
                .map(|threads| threads.to_string())
                .unwrap_or_default(),
        }
    }

    fn apply(self, config: &mut AgentConfig, input: &str) -> std::result::Result<(), String> {
        let value = input.trim();
        match self {
            ConfigFieldKey::ListenAddr => {
                if value.is_empty() {
                    return Err("listen_addr cannot be empty".to_string());
                }
                config.listen_addr = value.to_string();
            }
            ConfigFieldKey::ProxyAddrs => {
                let addrs = value
                    .split(',')
                    .map(|item| item.trim())
                    .filter(|item| !item.is_empty())
                    .map(ToString::to_string)
                    .collect::<Vec<_>>();
                if addrs.is_empty() {
                    return Err("proxy_addrs requires at least one address".to_string());
                }
                config.proxy_addrs = addrs;
            }
            ConfigFieldKey::Username => {
                if value.is_empty() {
                    return Err("username cannot be empty".to_string());
                }
                config.username = value.to_string();
            }
            ConfigFieldKey::PrivateKeyPath => {
                if value.is_empty() {
                    return Err("private_key_path cannot be empty".to_string());
                }
                config.private_key_path = value.to_string();
            }
            ConfigFieldKey::AsyncRuntimeStackSizeMb => {
                let parsed = value.parse::<usize>().map_err(|_| {
                    "async_runtime_stack_size_mb must be a positive integer".to_string()
                })?;
                if parsed == 0 {
                    return Err("async_runtime_stack_size_mb must be > 0".to_string());
                }
                config.async_runtime_stack_size_mb = parsed;
            }
            ConfigFieldKey::PoolSize => {
                let parsed = value
                    .parse::<usize>()
                    .map_err(|_| "pool_size must be a positive integer".to_string())?;
                if parsed == 0 {
                    return Err("pool_size must be > 0".to_string());
                }
                config.pool_size = parsed;
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
            ConfigFieldKey::ConsolePort => {
                if value.is_empty() || value.eq_ignore_ascii_case("none") {
                    config.console_port = None;
                } else {
                    let parsed = value.parse::<u16>().map_err(|_| {
                        "console_port must be a number between 1 and 65535".to_string()
                    })?;
                    if parsed == 0 {
                        return Err("console_port must be between 1 and 65535".to_string());
                    }
                    config.console_port = Some(parsed);
                }
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
            ConfigFieldKey::LogBufferLines => {
                let parsed = value
                    .parse::<usize>()
                    .map_err(|_| "log_buffer_lines must be a positive integer".to_string())?;
                if parsed == 0 {
                    return Err("log_buffer_lines must be > 0".to_string());
                }
                config.log_buffer_lines = parsed;
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
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConsoleTaskSort {
    Polls,
    Wakes,
    Name,
    Id,
}

impl ConsoleTaskSort {
    fn next(self) -> Self {
        match self {
            Self::Polls => Self::Wakes,
            Self::Wakes => Self::Name,
            Self::Name => Self::Id,
            Self::Id => Self::Polls,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Polls => "polls",
            Self::Wakes => "wakes",
            Self::Name => "name",
            Self::Id => "id",
        }
    }
}

#[derive(Debug, Clone, Default)]
struct ConsoleTaskView {
    id: u64,
    name: String,
    kind: String,
    #[cfg_attr(not(feature = "console"), allow(dead_code))]
    metadata_id: Option<u64>,
    wakes: u64,
    polls: u64,
    self_wakes: u64,
    is_live: bool,
}

#[cfg_attr(not(feature = "console"), allow(dead_code))]
#[derive(Debug, Clone, Default)]
struct ConsoleSnapshot {
    temporality: String,
    tasks: Vec<ConsoleTaskView>,
    live_tasks: usize,
    dropped_task_events: u64,
}

#[derive(Debug, Clone, Default)]
struct ConsoleTaskDetailsView {
    task_id: u64,
    updated_at_secs: Option<u64>,
    poll_histogram_max_ns: Option<u64>,
    poll_histogram_high_outliers: u64,
    poll_histogram_highest_outlier_ns: Option<u64>,
    scheduled_histogram_max_ns: Option<u64>,
    scheduled_histogram_high_outliers: u64,
    scheduled_histogram_highest_outlier_ns: Option<u64>,
}

pub async fn run(
    config: AgentConfig,
    config_path: String,
    mut events: UnboundedReceiver<UiEvent>,
) -> Result<()> {
    let mut terminal = ratatui::init();
    execute!(std::io::stdout(), EnableMouseCapture)?;
    let run_result = run_app(&mut terminal, config, config_path, &mut events).await;
    let _ = execute!(std::io::stdout(), DisableMouseCapture);
    ratatui::restore();
    run_result
}

async fn run_app(
    terminal: &mut DefaultTerminal,
    config: AgentConfig,
    config_path: String,
    events: &mut UnboundedReceiver<UiEvent>,
) -> Result<()> {
    let mut app = App::new(config, config_path);
    app.start_agent();

    loop {
        app.process_events(events);
        app.refresh_tokio_console_state().await;
        app.reap_server_task().await;

        terminal.draw(|frame| app.render(frame))?;

        if event::poll(Duration::from_millis(120))? {
            match event::read()? {
                Event::Key(key_event)
                    if key_event.kind == KeyEventKind::Press
                        && app.handle_key_event(key_event).await =>
                {
                    break;
                }
                Event::Mouse(mouse_event) => {
                    app.handle_mouse_event(mouse_event);
                }
                _ => {}
            }
        }
    }

    app.shutdown_on_exit().await;
    Ok(())
}

struct App {
    config: AgentConfig,
    config_path: String,
    status: RuntimeStatus,
    active_tab: AppTab,
    console_state: TokioConsoleState,
    console_temporality: Option<String>,
    console_last_error: Option<String>,
    console_last_update_secs: Option<u64>,
    #[cfg_attr(not(feature = "console"), allow(dead_code))]
    last_console_probe_secs: Option<u64>,
    console_tasks: Vec<ConsoleTaskView>,
    console_live_tasks: usize,
    console_dropped_task_events: u64,
    console_sort: ConsoleTaskSort,
    console_only_live: bool,
    console_selected_task_id: Option<u64>,
    console_task_scroll_from_top: usize,
    console_task_details: Option<ConsoleTaskDetailsView>,
    console_task_details_error: Option<String>,
    console_task_details_last_update_secs: Option<u64>,
    console_last_details_probe_secs: Option<u64>,
    log_buffer_lines: usize,
    trends_width_percent: u16,
    log_height_percent: u16,
    is_resizing_trends_split: bool,
    is_resizing_log_split: bool,
    log_scroll_from_bottom: usize,
    traffic_scroll_from_top: usize,
    config_selected_index: usize,
    config_scroll_from_top: usize,
    config_is_editing: bool,
    config_edit_buffer: String,
    config_dirty: bool,
    config_message: Option<String>,
    config_message_is_error: bool,
    config_last_saved_secs: Option<u64>,
    logs: VecDeque<String>,
    traffic: VecDeque<TrafficRecord>,
    total_outbound: u64,
    total_inbound: u64,
    completed_sessions: u64,
    server_shutdown: Option<CancellationToken>,
    server_task: Option<JoinHandle<()>>,
}

impl App {
    fn new(config: AgentConfig, config_path: String) -> Self {
        let log_buffer_lines = config.log_buffer_lines.max(1);
        let console_state = match config.console_port {
            Some(_) if cfg!(feature = "console") => TokioConsoleState::Running,
            Some(_) => TokioConsoleState::Unsupported,
            None => TokioConsoleState::Disabled,
        };

        Self {
            config,
            config_path,
            status: RuntimeStatus::Stopped,
            active_tab: AppTab::Agent,
            console_state,
            console_temporality: None,
            console_last_error: None,
            console_last_update_secs: None,
            last_console_probe_secs: None,
            console_tasks: Vec::new(),
            console_live_tasks: 0,
            console_dropped_task_events: 0,
            console_sort: ConsoleTaskSort::Polls,
            console_only_live: false,
            console_selected_task_id: None,
            console_task_scroll_from_top: 0,
            console_task_details: None,
            console_task_details_error: None,
            console_task_details_last_update_secs: None,
            console_last_details_probe_secs: None,
            log_buffer_lines,
            trends_width_percent: TRENDS_LEFT_DEFAULT_PERCENT,
            log_height_percent: LOG_HEIGHT_DEFAULT_PERCENT,
            is_resizing_trends_split: false,
            is_resizing_log_split: false,
            log_scroll_from_bottom: 0,
            traffic_scroll_from_top: 0,
            config_selected_index: 0,
            config_scroll_from_top: 0,
            config_is_editing: false,
            config_edit_buffer: String::new(),
            config_dirty: false,
            config_message: None,
            config_message_is_error: false,
            config_last_saved_secs: None,
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
        if !self.reload_config_from_file_internal(true) {
            return;
        }

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
            if let Some(console_port) = config.console_port {
                #[cfg(feature = "console")]
                info!(
                    "tokio-console enabled on 127.0.0.1:{} (connect with: tokio-console http://localhost:{})",
                    console_port, console_port
                );
                #[cfg(not(feature = "console"))]
                info!(
                    "console_port={} configured but build is missing --features console",
                    console_port
                );
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
        let _ = self.reload_config_from_file_internal(true);

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
        if self.log_scroll_from_bottom > 0 {
            self.log_scroll_from_bottom = self.log_scroll_from_bottom.saturating_add(1);
        }

        self.logs.push_back(line);
        while self.logs.len() > self.log_buffer_lines {
            self.logs.pop_front();
        }

        self.clamp_log_scroll(self.current_log_viewport_lines());
    }

    fn push_traffic(&mut self, record: TrafficRecord) {
        if self.traffic_scroll_from_top > 0 {
            self.traffic_scroll_from_top = self.traffic_scroll_from_top.saturating_add(1);
        }

        self.total_outbound = self.total_outbound.saturating_add(record.outbound_bytes);
        self.total_inbound = self.total_inbound.saturating_add(record.inbound_bytes);
        self.completed_sessions = self.completed_sessions.saturating_add(1);
        self.traffic.push_back(record);
        if self.traffic.len() > MAX_TRAFFIC_ROWS {
            self.traffic.pop_front();
        }
        self.clamp_traffic_scroll(self.current_traffic_viewport_lines());
    }

    async fn handle_key_event(&mut self, key_event: KeyEvent) -> bool {
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

    fn handle_mouse_event(&mut self, mouse_event: MouseEvent) {
        let left_release = matches!(mouse_event.kind, MouseEventKind::Up(MouseButton::Left));

        if self.active_tab == AppTab::TokioConsole {
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
            if left_release {
                self.is_resizing_trends_split = false;
                self.is_resizing_log_split = false;
            }
            return;
        };

        let body = layout.body;
        if body.width < 10 || body.height < 6 {
            if left_release {
                self.is_resizing_trends_split = false;
                self.is_resizing_log_split = false;
            }
            return;
        }

        let split_y = layout.logs.y;
        let split_x = layout.sessions.x;

        match mouse_event.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                let in_top_rows = mouse_event.row >= layout.top.y
                    && mouse_event.row < layout.top.y.saturating_add(layout.top.height);
                let near_vertical_split = mouse_event.column >= split_x.saturating_sub(1)
                    && mouse_event.column <= split_x.saturating_add(1);
                let in_body_cols = mouse_event.column >= body.x
                    && mouse_event.column < body.x.saturating_add(body.width);
                let near_horizontal_split = mouse_event.row >= split_y.saturating_sub(1)
                    && mouse_event.row <= split_y.saturating_add(1);
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

    fn current_content_body_rect(&self) -> Option<Rect> {
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

    fn agent_layout_from_body(&self, body: Rect) -> AgentLayoutRects {
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

    fn current_agent_layout_rects(&self) -> Option<AgentLayoutRects> {
        if self.active_tab != AppTab::Agent {
            return None;
        }

        let body = self.current_content_body_rect()?;
        Some(self.agent_layout_from_body(body))
    }

    fn tokio_console_layout_from_body(&self, body: Rect) -> TokioConsoleLayoutRects {
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

    fn current_tokio_console_layout_rects(&self) -> Option<TokioConsoleLayoutRects> {
        if self.active_tab != AppTab::TokioConsole {
            return None;
        }
        let body = self.current_content_body_rect()?;
        Some(self.tokio_console_layout_from_body(body))
    }

    fn config_layout_from_body(&self, body: Rect) -> ConfigLayoutRects {
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

    fn current_config_layout_rects(&self) -> Option<ConfigLayoutRects> {
        if self.active_tab != AppTab::Config {
            return None;
        }
        let body = self.current_content_body_rect()?;
        Some(self.config_layout_from_body(body))
    }

    fn config_fields() -> &'static [ConfigFieldKey] {
        &ConfigFieldKey::ALL
    }

    fn selected_config_field(&self) -> ConfigFieldKey {
        let fields = Self::config_fields();
        let index = self
            .config_selected_index
            .min(fields.len().saturating_sub(1));
        fields[index]
    }

    fn current_config_viewport_rows(&self) -> usize {
        self.current_config_layout_rects()
            .map(|layout| config_table_viewport_rows(layout.fields_table))
            .unwrap_or(1)
            .max(1)
    }

    fn max_config_scroll(&self, viewport_rows: usize) -> usize {
        Self::config_fields()
            .len()
            .saturating_sub(viewport_rows.max(1))
    }

    fn clamp_config_scroll(&mut self, viewport_rows: usize) {
        self.config_scroll_from_top = self
            .config_scroll_from_top
            .min(self.max_config_scroll(viewport_rows));
    }

    fn keep_config_selection_visible(&mut self, viewport_rows: usize) {
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

    fn move_config_selection(&mut self, delta: isize) {
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

    fn select_config_row_from_mouse(&mut self, table_area: Rect, mouse_row: u16) {
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

    fn current_log_viewport_lines(&self) -> usize {
        self.current_agent_layout_rects()
            .map(|layout| layout.logs.height.saturating_sub(2) as usize)
            .unwrap_or(1)
            .max(1)
    }

    fn current_traffic_viewport_lines(&self) -> usize {
        self.current_agent_layout_rects()
            .map(|layout| traffic_table_viewport_rows(layout.sessions_table))
            .unwrap_or(1)
            .max(1)
    }

    fn max_log_scroll(&self, viewport_lines: usize) -> usize {
        self.logs.len().saturating_sub(viewport_lines.max(1))
    }

    fn clamp_log_scroll(&mut self, viewport_lines: usize) {
        self.log_scroll_from_bottom = self
            .log_scroll_from_bottom
            .min(self.max_log_scroll(viewport_lines));
    }

    fn scroll_logs_older(&mut self, lines: usize) {
        let max_scroll = self.max_log_scroll(self.current_log_viewport_lines());
        self.log_scroll_from_bottom = self
            .log_scroll_from_bottom
            .saturating_add(lines)
            .min(max_scroll);
    }

    fn scroll_logs_newer(&mut self, lines: usize) {
        self.log_scroll_from_bottom = self.log_scroll_from_bottom.saturating_sub(lines);
    }

    fn scroll_logs_to_oldest(&mut self) {
        self.log_scroll_from_bottom = self.max_log_scroll(self.current_log_viewport_lines());
    }

    fn scroll_logs_to_latest(&mut self) {
        self.log_scroll_from_bottom = 0;
    }

    fn max_traffic_scroll(&self, viewport_rows: usize) -> usize {
        self.traffic.len().saturating_sub(viewport_rows.max(1))
    }

    fn clamp_traffic_scroll(&mut self, viewport_rows: usize) {
        self.traffic_scroll_from_top = self
            .traffic_scroll_from_top
            .min(self.max_traffic_scroll(viewport_rows));
    }

    fn scroll_traffic_older(&mut self, rows: usize) {
        let max_scroll = self.max_traffic_scroll(self.current_traffic_viewport_lines());
        self.traffic_scroll_from_top = self
            .traffic_scroll_from_top
            .saturating_add(rows)
            .min(max_scroll);
    }

    fn scroll_traffic_newer(&mut self, rows: usize) {
        self.traffic_scroll_from_top = self.traffic_scroll_from_top.saturating_sub(rows);
    }

    fn scroll_traffic_to_oldest(&mut self) {
        self.traffic_scroll_from_top =
            self.max_traffic_scroll(self.current_traffic_viewport_lines());
    }

    fn scroll_traffic_to_latest(&mut self) {
        self.traffic_scroll_from_top = 0;
    }

    fn compare_console_tasks(&self, left: &ConsoleTaskView, right: &ConsoleTaskView) -> Ordering {
        match self.console_sort {
            ConsoleTaskSort::Polls => right
                .polls
                .cmp(&left.polls)
                .then_with(|| right.wakes.cmp(&left.wakes))
                .then_with(|| left.id.cmp(&right.id)),
            ConsoleTaskSort::Wakes => right
                .wakes
                .cmp(&left.wakes)
                .then_with(|| right.polls.cmp(&left.polls))
                .then_with(|| left.id.cmp(&right.id)),
            ConsoleTaskSort::Name => left
                .name
                .cmp(&right.name)
                .then_with(|| left.id.cmp(&right.id)),
            ConsoleTaskSort::Id => left.id.cmp(&right.id),
        }
    }

    fn console_visible_tasks(&self) -> Vec<ConsoleTaskView> {
        let mut tasks: Vec<ConsoleTaskView> = self
            .console_tasks
            .iter()
            .filter(|task| !self.console_only_live || task.is_live)
            .cloned()
            .collect();
        tasks.sort_by(|left, right| self.compare_console_tasks(left, right));
        tasks
    }

    fn current_console_task_viewport_rows(&self) -> usize {
        self.current_tokio_console_layout_rects()
            .map(|layout| tokio_tasks_table_viewport_rows(layout.tasks_table))
            .unwrap_or(1)
            .max(1)
    }

    fn max_console_task_scroll(total_rows: usize, viewport_rows: usize) -> usize {
        total_rows.saturating_sub(viewport_rows.max(1))
    }

    fn clamp_console_task_scroll(&mut self, total_rows: usize, viewport_rows: usize) {
        self.console_task_scroll_from_top = self
            .console_task_scroll_from_top
            .min(Self::max_console_task_scroll(total_rows, viewport_rows));
    }

    fn ensure_console_task_selection(&mut self) {
        let visible = self.console_visible_tasks();
        let next_selected = self.console_selected_task_id.and_then(|selected_id| {
            visible
                .iter()
                .find(|task| task.id == selected_id)
                .map(|task| task.id)
        });

        if next_selected.is_none() {
            self.console_selected_task_id = visible.first().map(|task| task.id);
            self.console_last_details_probe_secs = None;
            self.console_task_details = None;
            self.console_task_details_error = None;
        }

        let viewport = self.current_console_task_viewport_rows();
        self.clamp_console_task_scroll(visible.len(), viewport);
        self.keep_console_selection_visible_with_tasks(&visible, viewport);
    }

    fn keep_console_selection_visible_with_tasks(
        &mut self,
        visible_tasks: &[ConsoleTaskView],
        viewport_rows: usize,
    ) {
        let Some(selected_id) = self.console_selected_task_id else {
            return;
        };
        let Some(selected_index) = visible_tasks.iter().position(|task| task.id == selected_id)
        else {
            return;
        };

        if selected_index < self.console_task_scroll_from_top {
            self.console_task_scroll_from_top = selected_index;
            return;
        }

        let viewport = viewport_rows.max(1);
        let viewport_end = self.console_task_scroll_from_top.saturating_add(viewport);
        if selected_index >= viewport_end {
            self.console_task_scroll_from_top =
                selected_index.saturating_add(1).saturating_sub(viewport);
        }
    }

    fn move_console_selection(&mut self, delta: isize) {
        let visible = self.console_visible_tasks();
        if visible.is_empty() {
            self.console_selected_task_id = None;
            self.console_task_scroll_from_top = 0;
            self.console_task_details = None;
            self.console_task_details_error = None;
            self.console_last_details_probe_secs = None;
            return;
        }

        let current_index = self
            .console_selected_task_id
            .and_then(|selected_id| visible.iter().position(|task| task.id == selected_id))
            .unwrap_or(0);

        let last_index = visible.len().saturating_sub(1);
        let next_index = if delta < 0 {
            current_index.saturating_sub(delta.unsigned_abs())
        } else {
            current_index.saturating_add(delta as usize).min(last_index)
        };

        let selected_id = visible[next_index].id;
        if self.console_selected_task_id != Some(selected_id) {
            self.console_selected_task_id = Some(selected_id);
            self.console_task_details = None;
            self.console_task_details_error = None;
            self.console_last_details_probe_secs = None;
        }

        let viewport = self.current_console_task_viewport_rows();
        self.clamp_console_task_scroll(visible.len(), viewport);
        self.keep_console_selection_visible_with_tasks(&visible, viewport);
    }

    fn select_first_console_task(&mut self) {
        let visible = self.console_visible_tasks();
        if let Some(first) = visible.first() {
            if self.console_selected_task_id != Some(first.id) {
                self.console_selected_task_id = Some(first.id);
                self.console_task_details = None;
                self.console_task_details_error = None;
                self.console_last_details_probe_secs = None;
            }
            self.console_task_scroll_from_top = 0;
        }
    }

    fn select_last_console_task(&mut self) {
        let visible = self.console_visible_tasks();
        if let Some(last) = visible.last() {
            if self.console_selected_task_id != Some(last.id) {
                self.console_selected_task_id = Some(last.id);
                self.console_task_details = None;
                self.console_task_details_error = None;
                self.console_last_details_probe_secs = None;
            }
            let viewport = self.current_console_task_viewport_rows();
            self.console_task_scroll_from_top =
                Self::max_console_task_scroll(visible.len(), viewport);
        }
    }

    fn select_console_task_from_row(&mut self, table_area: Rect, mouse_row: u16) {
        let row_start = table_area.y.saturating_add(2);
        if mouse_row < row_start {
            return;
        }

        let row_offset = mouse_row.saturating_sub(row_start) as usize;
        let viewport_rows = tokio_tasks_table_viewport_rows(table_area);
        if row_offset >= viewport_rows {
            return;
        }

        let visible = self.console_visible_tasks();
        let row_index = self.console_task_scroll_from_top.saturating_add(row_offset);
        let Some(task) = visible.get(row_index) else {
            return;
        };

        if self.console_selected_task_id != Some(task.id) {
            self.console_selected_task_id = Some(task.id);
            self.console_task_details = None;
            self.console_task_details_error = None;
            self.console_last_details_probe_secs = None;
        }

        self.clamp_console_task_scroll(visible.len(), viewport_rows);
        self.keep_console_selection_visible_with_tasks(&visible, viewport_rows);
    }

    async fn handle_tokio_console_key_event(&mut self, key_event: KeyEvent) -> bool {
        match key_event.code {
            KeyCode::Up => {
                self.move_console_selection(-1);
                false
            }
            KeyCode::Down => {
                self.move_console_selection(1);
                false
            }
            KeyCode::PageUp => {
                self.move_console_selection(-10);
                false
            }
            KeyCode::PageDown => {
                self.move_console_selection(10);
                false
            }
            KeyCode::Home => {
                self.select_first_console_task();
                false
            }
            KeyCode::End => {
                self.select_last_console_task();
                false
            }
            KeyCode::Char('h') | KeyCode::Char('H') => {
                self.console_only_live = !self.console_only_live;
                self.console_task_scroll_from_top = 0;
                self.ensure_console_task_selection();
                false
            }
            KeyCode::Char('m') | KeyCode::Char('M') => {
                self.console_sort = self.console_sort.next();
                self.ensure_console_task_selection();
                false
            }
            KeyCode::Char('r') | KeyCode::Char('R') => {
                self.last_console_probe_secs = None;
                self.console_last_details_probe_secs = None;
                self.refresh_tokio_console_state().await;
                false
            }
            KeyCode::Enter | KeyCode::Char('d') | KeyCode::Char('D') => {
                self.console_last_details_probe_secs = None;
                self.refresh_console_task_details(true).await;
                false
            }
            KeyCode::Char(' ') => {
                if self.console_state == TokioConsoleState::Running {
                    self.stop_tokio_console().await;
                } else {
                    self.start_tokio_console().await;
                }
                false
            }
            _ => false,
        }
    }

    fn handle_config_key_event(&mut self, key_event: KeyEvent) -> bool {
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

    fn handle_config_edit_input(&mut self, key_event: KeyEvent) {
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

    fn set_config_message<S: Into<String>>(&mut self, message: S, is_error: bool) {
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

    fn sync_ui_state_with_config(&mut self) {
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

    fn reload_config_from_file_internal(&mut self, for_agent_action: bool) -> bool {
        if self.config_is_editing {
            self.set_config_message("Finish editing first (Enter or Esc).", true);
            return false;
        }

        match AgentConfig::load(&self.config_path) {
            Ok(config) => {
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

    async fn refresh_console_task_details(&mut self, force: bool) {
        let Some(console_port) = self.config.console_port else {
            self.console_task_details = None;
            self.console_task_details_error = None;
            self.console_task_details_last_update_secs = None;
            return;
        };
        let Some(task_id) = self.console_selected_task_id else {
            self.console_task_details = None;
            self.console_task_details_error = None;
            self.console_task_details_last_update_secs = None;
            return;
        };

        #[cfg(feature = "console")]
        {
            let now = now_unix_secs();
            let min_interval_secs = if self.active_tab == AppTab::TokioConsole {
                1
            } else {
                3
            };
            if !force
                && self
                    .console_last_details_probe_secs
                    .is_some_and(|last| now.saturating_sub(last) < min_interval_secs)
            {
                return;
            }
            self.console_last_details_probe_secs = Some(now);

            match console_fetch_task_details(console_port, task_id).await {
                Ok(details) => {
                    self.console_task_details = Some(details);
                    self.console_task_details_error = None;
                    self.console_task_details_last_update_secs = Some(now);
                }
                Err(err) => {
                    self.console_task_details_error = Some(err);
                }
            }
        }

        #[cfg(not(feature = "console"))]
        {
            self.console_task_details = None;
            self.console_task_details_error =
                Some("tokio-console is unavailable in this build".to_string());
            self.console_task_details_last_update_secs = None;
            let _ = (console_port, task_id, force);
        }
    }

    async fn start_tokio_console(&mut self) {
        let Some(console_port) = self.config.console_port else {
            self.console_state = TokioConsoleState::Disabled;
            info!("tokio-console start ignored: console_port is not configured");
            return;
        };

        #[cfg(feature = "console")]
        {
            match console_resume(console_port).await {
                Ok(()) => {
                    self.console_state = TokioConsoleState::Running;
                    self.console_temporality = Some("LIVE".to_string());
                    self.console_last_error = None;
                    self.console_last_update_secs = Some(now_unix_secs());
                    self.last_console_probe_secs = None;
                    self.console_last_details_probe_secs = None;
                    info!(
                        "tokio-console resumed on 127.0.0.1:{} (connect with: tokio-console http://localhost:{})",
                        console_port, console_port
                    );
                }
                Err(err) => {
                    self.console_last_error = Some(err.clone());
                    info!(
                        "failed to resume tokio-console on port {}: {}",
                        console_port, err
                    );
                }
            }
        }

        #[cfg(not(feature = "console"))]
        {
            self.console_state = TokioConsoleState::Unsupported;
            info!(
                "tokio-console start ignored on port {}: build is missing --features console",
                console_port
            );
        }
    }

    async fn stop_tokio_console(&mut self) {
        let Some(console_port) = self.config.console_port else {
            self.console_state = TokioConsoleState::Disabled;
            info!("tokio-console stop ignored: console_port is not configured");
            return;
        };

        #[cfg(feature = "console")]
        {
            match console_pause(console_port).await {
                Ok(()) => {
                    self.console_state = TokioConsoleState::Stopped;
                    self.console_temporality = Some("PAUSED".to_string());
                    self.console_last_error = None;
                    self.console_last_update_secs = Some(now_unix_secs());
                    self.last_console_probe_secs = None;
                    info!("tokio-console paused on 127.0.0.1:{}", console_port);
                }
                Err(err) => {
                    self.console_last_error = Some(err.clone());
                    info!(
                        "failed to pause tokio-console on port {}: {}",
                        console_port, err
                    );
                }
            }
        }

        #[cfg(not(feature = "console"))]
        {
            self.console_state = TokioConsoleState::Unsupported;
            info!(
                "tokio-console stop ignored on port {}: build is missing --features console",
                console_port
            );
        }
    }

    async fn refresh_tokio_console_state(&mut self) {
        let Some(console_port) = self.config.console_port else {
            self.console_state = TokioConsoleState::Disabled;
            return;
        };

        #[cfg(feature = "console")]
        {
            let probe_interval_secs = match self.active_tab {
                AppTab::TokioConsole => 1,
                AppTab::Agent | AppTab::Config => 4,
            };
            let now = now_unix_secs();
            if self
                .last_console_probe_secs
                .is_some_and(|last| now.saturating_sub(last) < probe_interval_secs)
            {
                if self.active_tab == AppTab::TokioConsole {
                    self.refresh_console_task_details(false).await;
                }
                return;
            }
            self.last_console_probe_secs = Some(now);

            match console_fetch_snapshot(console_port).await {
                Ok(snapshot) => {
                    self.console_last_error = None;
                    self.console_last_update_secs = Some(now);
                    self.console_temporality = Some(snapshot.temporality.clone());
                    self.console_tasks = snapshot.tasks;
                    self.console_live_tasks = snapshot.live_tasks;
                    self.console_dropped_task_events = snapshot.dropped_task_events;
                    self.ensure_console_task_selection();
                    self.console_state = match snapshot.temporality.as_str() {
                        "PAUSED" => TokioConsoleState::Stopped,
                        _ => TokioConsoleState::Running,
                    };
                    self.refresh_console_task_details(false).await;
                }
                Err(err) => {
                    self.console_last_error = Some(err);
                }
            }
        }

        #[cfg(not(feature = "console"))]
        {
            self.console_state = TokioConsoleState::Unsupported;
            let _ = console_port;
        }
    }

    fn render(&mut self, frame: &mut Frame) {
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
                self.render_trends(frame, layout.trends);
                self.render_traffic_table(frame, layout.sessions_table);
                self.render_logs(frame, layout.logs);
            }
            AppTab::TokioConsole => self.render_tokio_console_tab(frame, root[2]),
            AppTab::Config => self.render_config_tab(frame, root[2]),
        }
        self.render_help(frame, root[3]);
    }

    fn render_tabs(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
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

    fn render_status(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
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

    fn render_logs(&mut self, frame: &mut Frame, area: ratatui::layout::Rect) {
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
        render_vertical_scrollbar(
            frame,
            area,
            self.logs.len(),
            viewport_lines,
            scroll_top,
            Color::Cyan,
        );
    }

    fn render_trends(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
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

    fn render_traffic_table(&mut self, frame: &mut Frame, area: ratatui::layout::Rect) {
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

    fn render_help(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
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

    fn render_config_tab(&mut self, frame: &mut Frame, area: ratatui::layout::Rect) {
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

    fn render_tokio_console_tab(&mut self, frame: &mut Frame, area: ratatui::layout::Rect) {
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

fn rect_contains(area: Rect, column: u16, row: u16) -> bool {
    column >= area.x
        && column < area.x.saturating_add(area.width)
        && row >= area.y
        && row < area.y.saturating_add(area.height)
}

fn traffic_table_viewport_rows(area: Rect) -> usize {
    area.height.saturating_sub(3) as usize
}

fn tokio_tasks_table_viewport_rows(area: Rect) -> usize {
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

fn format_duration_ns(nanos: u64) -> String {
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

#[cfg_attr(not(feature = "console"), allow(dead_code))]
fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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

#[cfg(feature = "console")]
async fn console_pause(port: u16) -> std::result::Result<(), String> {
    use console_api::instrument::{PauseRequest, instrument_client::InstrumentClient};
    use tonic::transport::Endpoint;

    let endpoint = Endpoint::from_shared(format!("http://127.0.0.1:{port}"))
        .map_err(|err| format!("invalid endpoint: {err}"))?
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(2));

    let channel = endpoint
        .connect()
        .await
        .map_err(|err| format!("connect failed: {err}"))?;
    let mut client = InstrumentClient::new(channel);
    client
        .pause(PauseRequest {})
        .await
        .map_err(|err| format!("pause request failed: {err}"))?;
    Ok(())
}

#[cfg(feature = "console")]
async fn console_resume(port: u16) -> std::result::Result<(), String> {
    use console_api::instrument::{ResumeRequest, instrument_client::InstrumentClient};
    use tonic::transport::Endpoint;

    let endpoint = Endpoint::from_shared(format!("http://127.0.0.1:{port}"))
        .map_err(|err| format!("invalid endpoint: {err}"))?
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(2));

    let channel = endpoint
        .connect()
        .await
        .map_err(|err| format!("connect failed: {err}"))?;
    let mut client = InstrumentClient::new(channel);
    client
        .resume(ResumeRequest {})
        .await
        .map_err(|err| format!("resume request failed: {err}"))?;
    Ok(())
}

#[cfg(feature = "console")]
async fn console_fetch_snapshot(port: u16) -> std::result::Result<ConsoleSnapshot, String> {
    use console_api::instrument::{
        InstrumentRequest, StateRequest, Temporality, instrument_client::InstrumentClient,
    };
    use tonic::transport::Endpoint;

    let endpoint = Endpoint::from_shared(format!("http://127.0.0.1:{port}"))
        .map_err(|err| format!("invalid endpoint: {err}"))?
        .connect_timeout(Duration::from_millis(900))
        .timeout(Duration::from_millis(900));

    let channel = endpoint
        .connect()
        .await
        .map_err(|err| format!("connect failed: {err}"))?;
    let mut client = InstrumentClient::new(channel);

    let state_response = client
        .watch_state(StateRequest {})
        .await
        .map_err(|err| format!("watch_state failed: {err}"))?;
    let mut state_stream = state_response.into_inner();
    let state_msg = tokio::time::timeout(Duration::from_millis(950), state_stream.message())
        .await
        .map_err(|_| "watch_state timed out".to_string())?
        .map_err(|err| format!("state stream failed: {err}"))?
        .ok_or_else(|| "state stream closed".to_string())?;

    let update_response = client
        .watch_updates(InstrumentRequest {})
        .await
        .map_err(|err| format!("watch_updates failed: {err}"))?;
    let mut update_stream = update_response.into_inner();
    let first_update = tokio::time::timeout(Duration::from_millis(1_800), update_stream.message())
        .await
        .map_err(|_| "watch_updates timed out".to_string())?
        .map_err(|err| format!("update stream failed: {err}"))?
        .ok_or_else(|| "update stream closed".to_string())?;
    let mut updates = vec![first_update];
    for _ in 0..10 {
        match tokio::time::timeout(Duration::from_millis(140), update_stream.message()).await {
            Ok(Ok(Some(update))) => updates.push(update),
            Ok(Ok(None)) => break,
            Ok(Err(err)) => return Err(format!("update stream failed: {err}")),
            Err(_) => break,
        }
    }

    let temporality = Temporality::try_from(state_msg.temporality)
        .unwrap_or(Temporality::Live)
        .as_str_name()
        .to_string();

    let mut meta_names = HashMap::<u64, String>::new();
    let mut tasks_by_id = HashMap::<u64, ConsoleTaskView>::new();
    let mut dropped_task_events = 0u64;

    for update in updates {
        apply_console_update(
            update,
            &mut meta_names,
            &mut tasks_by_id,
            &mut dropped_task_events,
        );
    }

    for task in tasks_by_id.values_mut() {
        if let Some(metadata_id) = task.metadata_id
            && let Some(metadata_name) = meta_names.get(&metadata_id)
        {
            task.name = metadata_name.clone();
        }
    }

    let mut tasks: Vec<ConsoleTaskView> = tasks_by_id.into_values().collect();

    tasks.sort_by(|a, b| {
        b.polls
            .cmp(&a.polls)
            .then_with(|| b.wakes.cmp(&a.wakes))
            .then_with(|| b.self_wakes.cmp(&a.self_wakes))
            .then_with(|| a.id.cmp(&b.id))
    });
    let live_tasks = tasks.iter().filter(|task| task.is_live).count();

    Ok(ConsoleSnapshot {
        temporality,
        tasks,
        live_tasks,
        dropped_task_events,
    })
}

#[cfg(feature = "console")]
fn apply_console_update(
    update: console_api::instrument::Update,
    meta_names: &mut HashMap<u64, String>,
    tasks_by_id: &mut HashMap<u64, ConsoleTaskView>,
    dropped_task_events: &mut u64,
) {
    use console_api::tasks::task::Kind;

    if let Some(new_metadata) = update.new_metadata {
        for item in new_metadata.metadata {
            if let (Some(id), Some(meta)) = (item.id, item.metadata) {
                meta_names.insert(id.id, meta.name);
            }
        }
    }

    let Some(task_update) = update.task_update else {
        return;
    };

    *dropped_task_events = dropped_task_events.saturating_add(task_update.dropped_events);
    for task in task_update.new_tasks {
        let task_id = task.id.map(|id| id.id).unwrap_or(0);
        let metadata_id = task.metadata.map(|meta| meta.id);
        let location_name = task.location.and_then(|loc| loc.module_path);
        let task_name = metadata_id
            .and_then(|id| meta_names.get(&id).cloned())
            .or(location_name)
            .unwrap_or_else(|| format!("task-{task_id}"));
        let kind = Kind::try_from(task.kind)
            .map(|k| k.as_str_name().to_string())
            .unwrap_or_else(|_| "UNKNOWN".to_string());

        let entry = tasks_by_id.entry(task_id).or_default();
        entry.id = task_id;
        entry.name = task_name;
        entry.kind = kind;
        entry.metadata_id = metadata_id;
        entry.is_live = true;
    }

    for (task_id, stats) in task_update.stats_update {
        let entry = tasks_by_id
            .entry(task_id)
            .or_insert_with(|| ConsoleTaskView {
                id: task_id,
                name: format!("task-{task_id}"),
                kind: "UNKNOWN".to_string(),
                metadata_id: None,
                wakes: 0,
                polls: 0,
                self_wakes: 0,
                is_live: true,
            });
        entry.wakes = stats.wakes;
        entry.polls = stats.poll_stats.as_ref().map(|p| p.polls).unwrap_or(0);
        entry.self_wakes = stats.self_wakes;
        entry.is_live = stats.dropped_at.is_none();
    }
}

#[cfg(feature = "console")]
async fn console_fetch_task_details(
    port: u16,
    task_id: u64,
) -> std::result::Result<ConsoleTaskDetailsView, String> {
    use console_api::Id;
    use console_api::instrument::{TaskDetailsRequest, instrument_client::InstrumentClient};
    use console_api::tasks::task_details::PollTimesHistogram;
    use tonic::transport::Endpoint;

    let endpoint = Endpoint::from_shared(format!("http://127.0.0.1:{port}"))
        .map_err(|err| format!("invalid endpoint: {err}"))?
        .connect_timeout(Duration::from_millis(900))
        .timeout(Duration::from_millis(900));

    let channel = endpoint
        .connect()
        .await
        .map_err(|err| format!("connect failed: {err}"))?;
    let mut client = InstrumentClient::new(channel);

    let details_response = client
        .watch_task_details(TaskDetailsRequest {
            id: Some(Id { id: task_id }),
        })
        .await
        .map_err(|err| format!("watch_task_details failed: {err}"))?;
    let mut details_stream = details_response.into_inner();
    let details = tokio::time::timeout(Duration::from_millis(1_500), details_stream.message())
        .await
        .map_err(|_| "watch_task_details timed out".to_string())?
        .map_err(|err| format!("task details stream failed: {err}"))?
        .ok_or_else(|| "task details stream closed".to_string())?;

    let updated_at_secs = details
        .now
        .and_then(|timestamp| u64::try_from(timestamp.seconds).ok());

    let (poll_histogram_max_ns, poll_histogram_high_outliers, poll_histogram_highest_outlier_ns) =
        match details.poll_times_histogram {
            Some(PollTimesHistogram::Histogram(histogram)) => (
                Some(histogram.max_value),
                histogram.high_outliers,
                histogram.highest_outlier,
            ),
            Some(PollTimesHistogram::LegacyHistogram(_)) => (None, 0, None),
            None => (None, 0, None),
        };

    let (
        scheduled_histogram_max_ns,
        scheduled_histogram_high_outliers,
        scheduled_histogram_highest_outlier_ns,
    ) = if let Some(histogram) = details.scheduled_times_histogram {
        (
            Some(histogram.max_value),
            histogram.high_outliers,
            histogram.highest_outlier,
        )
    } else {
        (None, 0, None)
    };

    Ok(ConsoleTaskDetailsView {
        task_id,
        updated_at_secs,
        poll_histogram_max_ns,
        poll_histogram_high_outliers,
        poll_histogram_highest_outlier_ns,
        scheduled_histogram_max_ns,
        scheduled_histogram_high_outliers,
        scheduled_histogram_highest_outlier_ns,
    })
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
