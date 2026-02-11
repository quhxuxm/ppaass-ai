use crate::config::AgentConfig;
use crate::server::AgentServer;
use crate::telemetry::{RuntimeStatus, TrafficRecord, UiEvent, emit_status};
use anyhow::Result;
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, MouseButton,
        MouseEvent, MouseEventKind,
    },
    execute,
};
use ratatui::{
    DefaultTerminal, Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, Cell, Paragraph, Row, Sparkline, Table, Tabs, Wrap},
};
use std::collections::VecDeque;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

const MAX_LOG_LINES: usize = 600;
const MAX_TRAFFIC_ROWS: usize = 400;

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
}

#[derive(Debug, Clone, Default)]
struct ConsoleTaskView {
    id: u64,
    name: String,
    kind: String,
    wakes: u64,
    polls: u64,
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

pub async fn run(config: AgentConfig, mut events: UnboundedReceiver<UiEvent>) -> Result<()> {
    let mut terminal = ratatui::init();
    execute!(std::io::stdout(), EnableMouseCapture)?;
    let run_result = run_app(&mut terminal, config, &mut events).await;
    let _ = execute!(std::io::stdout(), DisableMouseCapture);
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
        app.refresh_tokio_console_state().await;
        app.reap_server_task().await;

        terminal.draw(|frame| app.render(frame))?;

        if event::poll(Duration::from_millis(120))? {
            match event::read()? {
                Event::Key(key_event)
                    if key_event.kind == KeyEventKind::Press
                        && app.handle_key_event(key_event.code).await =>
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
    log_width_percent: u16,
    is_resizing_log_split: bool,
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
        let console_state = match config.console_port {
            Some(_) if cfg!(feature = "console") => TokioConsoleState::Running,
            Some(_) => TokioConsoleState::Unsupported,
            None => TokioConsoleState::Disabled,
        };

        Self {
            config,
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
            log_width_percent: 58,
            is_resizing_log_split: false,
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
            KeyCode::Tab => {
                self.switch_tab();
                false
            }
            KeyCode::Char('1') => {
                self.active_tab = AppTab::Agent;
                false
            }
            KeyCode::Char('2') => {
                self.active_tab = AppTab::TokioConsole;
                false
            }
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
            KeyCode::Char('k') => {
                self.start_tokio_console().await;
                false
            }
            KeyCode::Char('l') => {
                self.stop_tokio_console().await;
                false
            }
            _ => false,
        }
    }

    fn switch_tab(&mut self) {
        self.active_tab = match self.active_tab {
            AppTab::Agent => AppTab::TokioConsole,
            AppTab::TokioConsole => AppTab::Agent,
        };
    }

    fn handle_mouse_event(&mut self, mouse_event: MouseEvent) {
        if self.active_tab != AppTab::Agent {
            if matches!(mouse_event.kind, MouseEventKind::Up(MouseButton::Left)) {
                self.is_resizing_log_split = false;
            }
            return;
        }

        let Some(body) = self.current_agent_body_rect() else {
            return;
        };
        if body.width < 10 || body.height < 3 {
            return;
        }

        let split_x = body.x + ((body.width as u32 * self.log_width_percent as u32) / 100) as u16;

        match mouse_event.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                let in_body_rows = mouse_event.row >= body.y
                    && mouse_event.row < body.y.saturating_add(body.height);
                let near_split = mouse_event.column >= split_x.saturating_sub(1)
                    && mouse_event.column <= split_x.saturating_add(1);
                if in_body_rows && near_split {
                    self.is_resizing_log_split = true;
                    self.update_log_width_from_mouse(mouse_event.column, body);
                }
            }
            MouseEventKind::Drag(MouseButton::Left) => {
                if self.is_resizing_log_split {
                    self.update_log_width_from_mouse(mouse_event.column, body);
                }
            }
            MouseEventKind::Up(MouseButton::Left) => {
                if self.is_resizing_log_split {
                    self.update_log_width_from_mouse(mouse_event.column, body);
                    self.is_resizing_log_split = false;
                }
            }
            _ => {}
        }
    }

    fn update_log_width_from_mouse(&mut self, column: u16, body: Rect) {
        let relative_x = column.saturating_sub(body.x);
        let width = body.width.max(1);
        let percent = ((relative_x as u32 * 100) / width as u32) as u16;
        self.log_width_percent = percent.clamp(20, 80);
    }

    fn current_agent_body_rect(&self) -> Option<Rect> {
        let Ok((width, height)) = crossterm::terminal::size() else {
            return None;
        };
        if width == 0 || height <= 10 {
            return None;
        }

        // root layout: tabs(3) + status(4) + body(min) + controls(3)
        let body_y = 7;
        let controls_h = 3;
        if height <= body_y + controls_h {
            return None;
        }

        let body_h = height - body_y - controls_h;
        Some(Rect::new(0, body_y, width, body_h))
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
                    info!(
                        "tokio-console resumed on 127.0.0.1:{} (connect with: tokio-console http://localhost:{})",
                        console_port, console_port
                    );
                }
                Err(err) => {
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
                    info!("tokio-console paused on 127.0.0.1:{}", console_port);
                }
                Err(err) => {
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
                AppTab::Agent => 4,
            };
            let now = now_unix_secs();
            if self
                .last_console_probe_secs
                .is_some_and(|last| now.saturating_sub(last) < probe_interval_secs)
            {
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
                    self.console_state = match snapshot.temporality.as_str() {
                        "PAUSED" => TokioConsoleState::Stopped,
                        _ => TokioConsoleState::Running,
                    };
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
                Constraint::Length(3),
                Constraint::Length(4),
                Constraint::Min(8),
                Constraint::Length(3),
            ])
            .split(frame.area());

        self.render_tabs(frame, root[0]);
        self.render_status(frame, root[1]);
        match self.active_tab {
            AppTab::Agent => {
                let body = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([
                        Constraint::Percentage(self.log_width_percent),
                        Constraint::Percentage(100 - self.log_width_percent),
                    ])
                    .split(root[2]);
                self.render_logs(frame, body[0]);
                self.render_traffic(frame, body[1]);
            }
            AppTab::TokioConsole => self.render_tokio_console_tab(frame, root[2]),
        }
        self.render_help(frame, root[3]);
    }

    fn render_tabs(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let titles = vec!["Agent", "Tokio Console"];
        let selected = match self.active_tab {
            AppTab::Agent => 0,
            AppTab::TokioConsole => 1,
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
            "Switch Tab ".into(),
            "<Tab/1/2>".cyan().bold(),
            "  ".into(),
            "Resize Log ".into(),
            "<Drag Split>".cyan().bold(),
            "  ".into(),
            "Start ".into(),
            "<S>".green().bold(),
            "  Stop ".into(),
            "<X>".yellow().bold(),
            "  Start Console ".into(),
            "<K>".green().bold(),
            "  Stop Console ".into(),
            "<L>".yellow().bold(),
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

    fn render_tokio_console_tab(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
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
        let sections = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(7), Constraint::Min(4)])
            .split(area);

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
            ]),
            Line::from(vec![
                Span::styled(
                    "Last update: ",
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw(last_update),
                Span::raw(" | "),
                Span::styled("Controls: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw("K=start/resume, L=stop/pause"),
            ]),
            Line::from(Span::styled(error_line, Style::default().fg(Color::Red))),
        ]);

        let summary_panel = Paragraph::new(summary)
            .block(Block::bordered().title("Tokio Console"))
            .wrap(Wrap { trim: false });
        frame.render_widget(summary_panel, sections[0]);

        let rows: Vec<Row> = if self.console_tasks.is_empty() {
            vec![Row::new(vec![
                Cell::from("-"),
                Cell::from("-"),
                Cell::from("No task data yet"),
                Cell::from("-"),
                Cell::from("-"),
                Cell::from("-"),
            ])]
        } else {
            self.console_tasks
                .iter()
                .map(|task| {
                    Row::new(vec![
                        Cell::from(task.id.to_string()),
                        Cell::from(task.kind.clone()),
                        Cell::from(task.name.clone()),
                        Cell::from(if task.is_live { "LIVE" } else { "DONE" }),
                        Cell::from(task.polls.to_string()),
                        Cell::from(task.wakes.to_string()),
                    ])
                })
                .collect()
        };

        let header = Row::new(vec!["ID", "Kind", "Task", "State", "Polls", "Wakes"]).style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );

        let table = Table::new(
            rows,
            [
                Constraint::Length(8),
                Constraint::Length(9),
                Constraint::Min(22),
                Constraint::Length(7),
                Constraint::Length(8),
                Constraint::Length(8),
            ],
        )
        .header(header)
        .block(Block::bordered().title("Runtime Tasks"))
        .column_spacing(1);
        frame.render_widget(table, sections[1]);
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
    use console_api::tasks::task::Kind;
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
    let update_msg = tokio::time::timeout(Duration::from_millis(950), update_stream.message())
        .await
        .map_err(|_| "watch_updates timed out".to_string())?
        .map_err(|err| format!("update stream failed: {err}"))?
        .ok_or_else(|| "update stream closed".to_string())?;

    let temporality = Temporality::try_from(state_msg.temporality)
        .unwrap_or(Temporality::Live)
        .as_str_name()
        .to_string();

    let mut meta_names = std::collections::HashMap::<u64, String>::new();
    if let Some(new_metadata) = update_msg.new_metadata {
        for item in new_metadata.metadata {
            if let (Some(id), Some(meta)) = (item.id, item.metadata) {
                meta_names.insert(id.id, meta.name);
            }
        }
    }

    let mut tasks = Vec::<ConsoleTaskView>::new();
    let mut dropped_task_events = 0u64;

    if let Some(task_update) = update_msg.task_update {
        dropped_task_events = task_update.dropped_events;
        for task in task_update.new_tasks {
            let task_id = task.id.map(|id| id.id).unwrap_or(0);
            let metadata_id = task.metadata.map(|meta| meta.id);
            let task_name = metadata_id
                .and_then(|id| meta_names.get(&id).cloned())
                .or_else(|| task.location.and_then(|loc| loc.module_path))
                .unwrap_or_else(|| format!("task-{task_id}"));
            let kind = Kind::try_from(task.kind)
                .map(|k| k.as_str_name().to_string())
                .unwrap_or_else(|_| "UNKNOWN".to_string());
            let stats = task_update.stats_update.get(&task_id);
            let wakes = stats.map(|s| s.wakes).unwrap_or(0);
            let polls = stats
                .and_then(|s| s.poll_stats.as_ref().map(|p| p.polls))
                .unwrap_or(0);
            let is_live = stats.is_none_or(|s| s.dropped_at.is_none());

            tasks.push(ConsoleTaskView {
                id: task_id,
                name: task_name,
                kind,
                wakes,
                polls,
                is_live,
            });
        }
    }

    tasks.sort_by(|a, b| {
        b.polls
            .cmp(&a.polls)
            .then_with(|| b.wakes.cmp(&a.wakes))
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
