use std::io::{self, Write};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::UnboundedSender;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::reload;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry, fmt};

#[derive(Debug, Clone)]
pub enum RuntimeStatus {
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct TrafficRecord {
    pub timestamp_secs: u64,
    pub protocol: String,
    pub target: String,
    pub outbound_bytes: u64,
    pub inbound_bytes: u64,
}

impl TrafficRecord {
    fn new(protocol: String, target: String, outbound_bytes: u64, inbound_bytes: u64) -> Self {
        Self {
            timestamp_secs: now_secs(),
            protocol,
            target,
            outbound_bytes,
            inbound_bytes,
        }
    }
}

#[derive(Debug, Clone)]
pub enum UiEvent {
    Log(String),
    Status(RuntimeStatus),
    Traffic(TrafficRecord),
}

static UI_EVENT_TX: OnceLock<UnboundedSender<UiEvent>> = OnceLock::new();
type FilterReloadHandle = reload::Handle<EnvFilter, Registry>;
static FILTER_RELOAD_HANDLE: OnceLock<FilterReloadHandle> = OnceLock::new();

pub fn install_event_sender(tx: UnboundedSender<UiEvent>) {
    let _ = UI_EVENT_TX.set(tx);
}

pub fn emit_status(status: RuntimeStatus) {
    emit(UiEvent::Status(status));
}

pub fn emit_traffic<S1: Into<String>, S2: Into<String>>(
    protocol: S1,
    target: S2,
    outbound_bytes: u64,
    inbound_bytes: u64,
) {
    emit(UiEvent::Traffic(TrafficRecord::new(
        protocol.into(),
        target.into(),
        outbound_bytes,
        inbound_bytes,
    )));
}

fn emit(event: UiEvent) {
    if let Some(tx) = UI_EVENT_TX.get() {
        let _ = tx.send(event);
    }
}

pub fn init_tracing(
    log_dir: Option<&str>,
    log_file: &str,
    log_level: &str,
    ui_tx: UnboundedSender<UiEvent>,
    console_port: Option<u16>,
) -> Option<WorkerGuard> {
    let ui_writer = UiLogMakeWriter::new(ui_tx);

    #[cfg(feature = "console")]
    let console_layer = console_port.map(|port| {
        console_subscriber::ConsoleLayer::builder()
            .server_addr((std::net::Ipv4Addr::LOCALHOST, port))
            .spawn()
    });

    #[cfg(not(feature = "console"))]
    if console_port.is_some() {
        eprintln!(
            "console_port is configured but proxy is not built with --features console; tokio-console is disabled"
        );
    }

    if let Some(log_dir) = log_dir {
        let file_appender = tracing_appender::rolling::daily(log_dir, log_file);
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        #[cfg(feature = "console")]
        if let Some(console_layer) = console_layer {
            let (filter_layer, filter_handle) = reload_filter_layer(log_level);
            let _ = FILTER_RELOAD_HANDLE.set(filter_handle);
            tracing_subscriber::registry()
                .with(filter_layer)
                .with(console_layer)
                .with(
                    fmt::layer()
                        .with_writer(non_blocking)
                        .with_target(true)
                        .with_thread_ids(true)
                        .with_line_number(true)
                        .with_ansi(false),
                )
                .with(
                    fmt::layer()
                        .with_writer(ui_writer)
                        .with_target(true)
                        .with_thread_ids(true)
                        .with_line_number(true)
                        .with_ansi(false),
                )
                .init();
            return Some(guard);
        }

        let (filter_layer, filter_handle) = reload_filter_layer(log_level);
        let _ = FILTER_RELOAD_HANDLE.set(filter_handle);
        tracing_subscriber::registry()
            .with(filter_layer)
            .with(
                fmt::layer()
                    .with_writer(non_blocking)
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_line_number(true)
                    .with_ansi(false),
            )
            .with(
                fmt::layer()
                    .with_writer(ui_writer)
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_line_number(true)
                    .with_ansi(false),
            )
            .init();
        Some(guard)
    } else {
        #[cfg(feature = "console")]
        if let Some(console_layer) = console_layer {
            let (filter_layer, filter_handle) = reload_filter_layer(log_level);
            let _ = FILTER_RELOAD_HANDLE.set(filter_handle);
            tracing_subscriber::registry()
                .with(filter_layer)
                .with(console_layer)
                .with(
                    fmt::layer()
                        .with_writer(ui_writer)
                        .with_target(true)
                        .with_thread_ids(true)
                        .with_line_number(true)
                        .with_ansi(false),
                )
                .init();
            return None;
        }

        let (filter_layer, filter_handle) = reload_filter_layer(log_level);
        let _ = FILTER_RELOAD_HANDLE.set(filter_handle);
        tracing_subscriber::registry()
            .with(filter_layer)
            .with(
                fmt::layer()
                    .with_writer(ui_writer)
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_line_number(true)
                    .with_ansi(false),
            )
            .init();
        None
    }
}

fn reload_filter_layer(
    log_level: &str,
) -> (reload::Layer<EnvFilter, Registry>, FilterReloadHandle) {
    let initial_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));
    reload::Layer::new(initial_filter)
}

pub fn reload_log_level(log_level: &str) -> std::result::Result<(), String> {
    let Some(handle) = FILTER_RELOAD_HANDLE.get() else {
        return Err("log filter reload handle is not initialized".to_string());
    };
    let filter = EnvFilter::try_new(log_level)
        .map_err(|err| format!("invalid log_level '{}': {err}", log_level))?;
    handle
        .reload(filter)
        .map_err(|err| format!("failed to reload log filter: {err}"))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Clone)]
struct UiLogMakeWriter {
    tx: UnboundedSender<UiEvent>,
}

impl UiLogMakeWriter {
    fn new(tx: UnboundedSender<UiEvent>) -> Self {
        Self { tx }
    }
}

impl<'a> MakeWriter<'a> for UiLogMakeWriter {
    type Writer = UiLogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        UiLogWriter {
            tx: self.tx.clone(),
            buffer: Vec::with_capacity(256),
        }
    }
}

struct UiLogWriter {
    tx: UnboundedSender<UiEvent>,
    buffer: Vec<u8>,
}

impl UiLogWriter {
    fn flush_buffer(&mut self) {
        if self.buffer.is_empty() {
            return;
        }

        let payload = String::from_utf8_lossy(&self.buffer).to_string();
        self.buffer.clear();

        for line in payload.lines() {
            let line = line.trim();
            if !line.is_empty() {
                let _ = self.tx.send(UiEvent::Log(line.to_string()));
            }
        }
    }
}

impl Write for UiLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_buffer();
        Ok(())
    }
}

impl Drop for UiLogWriter {
    fn drop(&mut self) {
        self.flush_buffer();
    }
}
