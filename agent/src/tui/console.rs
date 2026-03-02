use super::App;
#[cfg(feature = "console")]
use super::helpers::now_unix_secs;
use super::helpers::tokio_tasks_table_viewport_rows;
use super::types::*;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use std::cmp::Ordering;
#[cfg(feature = "console")]
use std::collections::HashMap;
#[cfg(feature = "console")]
use std::time::Duration;
use tracing::info;

impl App {
    pub(super) fn compare_console_tasks(
        &self,
        left: &ConsoleTaskView,
        right: &ConsoleTaskView,
    ) -> Ordering {
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

    pub(super) fn console_visible_tasks(&self) -> Vec<ConsoleTaskView> {
        let mut tasks: Vec<ConsoleTaskView> = self
            .console_tasks
            .iter()
            .filter(|task| !self.console_only_live || task.is_live)
            .cloned()
            .collect();
        tasks.sort_by(|left, right| self.compare_console_tasks(left, right));
        tasks
    }

    pub(super) fn current_console_task_viewport_rows(&self) -> usize {
        self.current_tokio_console_layout_rects()
            .map(|layout| tokio_tasks_table_viewport_rows(layout.tasks_table))
            .unwrap_or(1)
            .max(1)
    }

    pub(super) fn max_console_task_scroll(total_rows: usize, viewport_rows: usize) -> usize {
        total_rows.saturating_sub(viewport_rows.max(1))
    }

    pub(super) fn clamp_console_task_scroll(&mut self, total_rows: usize, viewport_rows: usize) {
        self.console_task_scroll_from_top = self
            .console_task_scroll_from_top
            .min(Self::max_console_task_scroll(total_rows, viewport_rows));
    }

    pub(super) fn ensure_console_task_selection(&mut self) {
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

    pub(super) fn keep_console_selection_visible_with_tasks(
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

    pub(super) fn move_console_selection(&mut self, delta: isize) {
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

    pub(super) fn select_console_task_from_row(&mut self, table_area: Rect, mouse_row: u16) {
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

    pub(super) async fn handle_tokio_console_key_event(&mut self, key_event: KeyEvent) -> bool {
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

    pub(super) async fn refresh_console_task_details(&mut self, force: bool) {
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

    pub(super) async fn start_tokio_console(&mut self) {
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

    pub(super) async fn stop_tokio_console(&mut self) {
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

    pub(super) async fn refresh_tokio_console_state(&mut self) {
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
}

// ── Console gRPC free functions ─────────────────────────────────────────────

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
