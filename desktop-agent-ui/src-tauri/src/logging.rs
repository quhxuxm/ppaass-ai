use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::Registry;
use tracing_subscriber::reload;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Clone)]
pub(crate) struct UiLogBuffer {
    lines: Arc<Mutex<VecDeque<String>>>,
    capacity: usize,
    filter: Arc<Mutex<Option<reload::Handle<EnvFilter, Registry>>>>,
    log_level: Arc<Mutex<&'static str>>,
}

impl UiLogBuffer {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            lines: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
            capacity,
            filter: Arc::new(Mutex::new(None)),
            log_level: Arc::new(Mutex::new("info")),
        }
    }

    pub(crate) fn push(&self, line: impl Into<String>) {
        let Ok(mut lines) = self.lines.lock() else {
            return;
        };
        while lines.len() >= self.capacity {
            lines.pop_front();
        }
        lines.push_back(line.into());
    }

    pub(crate) fn snapshot(&self) -> Vec<String> {
        self.lines
            .lock()
            .map(|lines| lines.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub(crate) fn install_tracing(&self) {
        let initial_level = self.log_level.lock().map(|level| *level).unwrap_or("info");
        let (filter, handle) = reload::Layer::new(log_filter(initial_level));
        let layer = fmt::layer()
            .with_writer(UiLogMakeWriter {
                buffer: self.clone(),
            })
            .with_ansi(false)
            .with_target(true)
            .with_thread_ids(true)
            .with_line_number(true);

        let result = tracing_subscriber::registry()
            .with(filter)
            .with(layer)
            .try_init();

        match result {
            Ok(()) => {
                if let Ok(mut slot) = self.filter.lock() {
                    *slot = Some(handle);
                }
                self.push("UI 日志通道已初始化");
            }
            Err(err) => self.push(format!("UI 日志通道初始化失败：{err}")),
        }
    }

    pub(crate) fn set_log_level(&self, log_level: &str) -> Result<(), String> {
        let normalized = normalize_log_level(log_level);
        let handle = self
            .filter
            .lock()
            .map_err(|_| "日志级别状态锁已损坏".to_string())?
            .clone();
        let mut current = self
            .log_level
            .lock()
            .map_err(|_| "日志级别状态锁已损坏".to_string())?;

        if *current == normalized {
            return Ok(());
        }

        if let Some(handle) = handle {
            handle
                .reload(log_filter(normalized))
                .map_err(|err| format!("更新 UI 日志级别失败：{err}"))?;
            self.push(format!("UI 日志级别已切换为：{normalized}"));
        }
        *current = normalized;
        Ok(())
    }
}

pub(crate) fn normalize_log_level(log_level: &str) -> &'static str {
    match log_level.trim().to_ascii_lowercase().as_str() {
        "trace" => "trace",
        "debug" => "debug",
        "warn" => "warn",
        "error" => "error",
        _ => "info",
    }
}

fn log_filter(log_level: &str) -> EnvFilter {
    EnvFilter::try_new(normalize_log_level(log_level)).unwrap_or_else(|_| EnvFilter::new("info"))
}

#[derive(Clone)]
struct UiLogMakeWriter {
    buffer: UiLogBuffer,
}

impl<'a> MakeWriter<'a> for UiLogMakeWriter {
    type Writer = UiLogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        UiLogWriter {
            buffer: self.buffer.clone(),
            bytes: Vec::new(),
        }
    }
}

struct UiLogWriter {
    buffer: UiLogBuffer,
    bytes: Vec<u8>,
}

impl Write for UiLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for UiLogWriter {
    fn drop(&mut self) {
        let text = String::from_utf8_lossy(&self.bytes);
        for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
            self.buffer.push(line.to_string());
        }
    }
}
