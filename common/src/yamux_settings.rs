use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const DEFAULT_YAMUX_SESSIONS: usize = 5;
pub const DEFAULT_YAMUX_MAX_STREAMS_PER_SESSION: usize = 256;
pub const DEFAULT_YAMUX_OPEN_STREAM_TIMEOUT_SECS: u64 = 10;
pub const DEFAULT_YAMUX_KEEPALIVE_INTERVAL_SECS: u64 = 30;
pub const DEFAULT_YAMUX_CONNECTION_WRITE_TIMEOUT_SECS: u64 = 10;
pub const MIN_YAMUX_STREAM_WINDOW_SIZE_KB: usize = 256;
pub const DEFAULT_YAMUX_STREAM_WINDOW_SIZE_KB: usize = 512;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TcpTransportMode {
    #[default]
    Auto,
    Yamux,
    Legacy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    #[serde(default)]
    pub tcp_mode: TcpTransportMode,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            tcp_mode: TcpTransportMode::Auto,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YamuxConfig {
    #[serde(default = "default_yamux_sessions")]
    pub sessions: usize,

    #[serde(default = "default_yamux_max_streams_per_session")]
    pub max_streams_per_session: usize,

    #[serde(default = "default_yamux_open_stream_timeout_secs")]
    pub open_stream_timeout_secs: u64,

    #[serde(default = "default_yamux_keepalive_interval_secs")]
    pub keepalive_interval_secs: u64,

    #[serde(default = "default_yamux_connection_write_timeout_secs")]
    pub connection_write_timeout_secs: u64,

    #[serde(default = "default_yamux_stream_window_size_kb")]
    pub stream_window_size_kb: usize,
}

impl Default for YamuxConfig {
    fn default() -> Self {
        Self {
            sessions: DEFAULT_YAMUX_SESSIONS,
            max_streams_per_session: DEFAULT_YAMUX_MAX_STREAMS_PER_SESSION,
            open_stream_timeout_secs: DEFAULT_YAMUX_OPEN_STREAM_TIMEOUT_SECS,
            keepalive_interval_secs: DEFAULT_YAMUX_KEEPALIVE_INTERVAL_SECS,
            connection_write_timeout_secs: DEFAULT_YAMUX_CONNECTION_WRITE_TIMEOUT_SECS,
            stream_window_size_kb: DEFAULT_YAMUX_STREAM_WINDOW_SIZE_KB,
        }
    }
}

impl YamuxConfig {
    pub fn session_count(&self) -> usize {
        self.sessions.max(1)
    }

    pub fn settings(&self) -> YamuxSettings {
        YamuxSettings {
            max_streams_per_session: self.max_streams_per_session.max(1),
            open_stream_timeout: Duration::from_secs(self.open_stream_timeout_secs.max(1)),
            keepalive_interval: if self.keepalive_interval_secs == 0 {
                None
            } else {
                Some(Duration::from_secs(self.keepalive_interval_secs))
            },
            connection_write_timeout: Duration::from_secs(
                self.connection_write_timeout_secs.max(1),
            ),
            stream_window_size_kb: self
                .stream_window_size_kb
                .max(MIN_YAMUX_STREAM_WINDOW_SIZE_KB),
        }
    }
}

#[derive(Debug, Clone)]
pub struct YamuxSettings {
    pub max_streams_per_session: usize,
    pub open_stream_timeout: Duration,
    pub keepalive_interval: Option<Duration>,
    pub connection_write_timeout: Duration,
    pub stream_window_size_kb: usize,
}

impl Default for YamuxSettings {
    fn default() -> Self {
        YamuxConfig::default().settings()
    }
}

impl YamuxSettings {
    pub fn to_tokio_config(&self) -> tokio_yamux::Config {
        let max_streams = self.max_streams_per_session.max(1);
        let stream_window_size = self
            .stream_window_size_kb
            .max(MIN_YAMUX_STREAM_WINDOW_SIZE_KB)
            .saturating_mul(1024)
            .min(u32::MAX as usize) as u32;

        tokio_yamux::Config {
            accept_backlog: max_streams,
            enable_keepalive: self.keepalive_interval.is_some(),
            keepalive_interval: self
                .keepalive_interval
                .unwrap_or_else(|| Duration::from_secs(DEFAULT_YAMUX_KEEPALIVE_INTERVAL_SECS)),
            connection_write_timeout: self.connection_write_timeout,
            max_stream_count: max_streams,
            max_stream_window_size: stream_window_size,
        }
    }
}

fn default_yamux_sessions() -> usize {
    DEFAULT_YAMUX_SESSIONS
}

fn default_yamux_max_streams_per_session() -> usize {
    DEFAULT_YAMUX_MAX_STREAMS_PER_SESSION
}

fn default_yamux_open_stream_timeout_secs() -> u64 {
    DEFAULT_YAMUX_OPEN_STREAM_TIMEOUT_SECS
}

fn default_yamux_keepalive_interval_secs() -> u64 {
    DEFAULT_YAMUX_KEEPALIVE_INTERVAL_SECS
}

fn default_yamux_connection_write_timeout_secs() -> u64 {
    DEFAULT_YAMUX_CONNECTION_WRITE_TIMEOUT_SECS
}

fn default_yamux_stream_window_size_kb() -> usize {
    DEFAULT_YAMUX_STREAM_WINDOW_SIZE_KB
}
