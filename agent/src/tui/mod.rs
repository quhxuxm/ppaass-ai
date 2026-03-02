mod config_tab;
mod console;
mod event_handler;
mod helpers;
mod layout;
mod render;
mod types;

use crate::config::AgentConfig;
use crate::server::AgentServer;
use crate::telemetry::{RuntimeStatus, TrafficRecord, UiEvent, emit_status};
use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyEventKind},
    execute,
};
use std::collections::VecDeque;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use types::*;

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
    terminal: &mut ratatui::DefaultTerminal,
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
    pub(crate) config: AgentConfig,
    pub(crate) config_path: String,
    pub(crate) status: RuntimeStatus,
    pub(crate) active_tab: AppTab,
    pub(crate) console_state: TokioConsoleState,
    pub(crate) console_temporality: Option<String>,
    pub(crate) console_last_error: Option<String>,
    pub(crate) console_last_update_secs: Option<u64>,
    #[cfg_attr(not(feature = "console"), allow(dead_code))]
    pub(crate) last_console_probe_secs: Option<u64>,
    pub(crate) console_tasks: Vec<ConsoleTaskView>,
    pub(crate) console_live_tasks: usize,
    pub(crate) console_dropped_task_events: u64,
    pub(crate) console_sort: ConsoleTaskSort,
    pub(crate) console_only_live: bool,
    pub(crate) console_selected_task_id: Option<u64>,
    pub(crate) console_task_scroll_from_top: usize,
    pub(crate) console_task_details: Option<ConsoleTaskDetailsView>,
    pub(crate) console_task_details_error: Option<String>,
    pub(crate) console_task_details_last_update_secs: Option<u64>,
    pub(crate) console_last_details_probe_secs: Option<u64>,
    pub(crate) log_buffer_lines: usize,
    pub(crate) trends_width_percent: u16,
    pub(crate) log_height_percent: u16,
    pub(crate) is_resizing_trends_split: bool,
    pub(crate) is_resizing_log_split: bool,
    pub(crate) is_hovering_trends_split: bool,
    pub(crate) is_hovering_log_split: bool,
    pub(crate) log_scroll_from_bottom: usize,
    pub(crate) traffic_scroll_from_top: usize,
    pub(crate) config_selected_index: usize,
    pub(crate) config_scroll_from_top: usize,
    pub(crate) config_is_editing: bool,
    pub(crate) config_edit_buffer: String,
    pub(crate) config_dirty: bool,
    pub(crate) config_message: Option<String>,
    pub(crate) config_message_is_error: bool,
    pub(crate) config_last_saved_secs: Option<u64>,
    pub(crate) logs: VecDeque<String>,
    pub(crate) traffic: VecDeque<TrafficRecord>,
    pub(crate) total_outbound: u64,
    pub(crate) total_inbound: u64,
    pub(crate) completed_sessions: u64,
    pub(crate) server_shutdown: Option<CancellationToken>,
    pub(crate) server_task: Option<JoinHandle<()>>,
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
            is_hovering_trends_split: false,
            is_hovering_log_split: false,
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
}
