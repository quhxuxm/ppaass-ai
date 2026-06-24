use serde::{Deserialize, Serialize};
use std::time::Duration;

// TCP Yamux 会把浏览器/TUN 捕获到的多条 TCP 连接复用到少量外层 TCP 上。
// HLS 视频通常会同时拉取多个 HTTPS 分片；如果外层 session 太少，任一外层
// TCP 出现拥塞或丢包都会放大成多条子流的队头阻塞。因此 TCP 默认多开一些
// 外层连接，让子流分散到不同拥塞窗口，行为更接近常规通道连接池。
pub const DEFAULT_TCP_YAMUX_SESSIONS: usize = 16;
pub const DEFAULT_YAMUX_MAX_STREAMS_PER_SESSION: usize = 256;
pub const DEFAULT_YAMUX_OPEN_STREAM_TIMEOUT_SECS: u64 = 10;
pub const DEFAULT_YAMUX_KEEPALIVE_INTERVAL_SECS: u64 = 30;
pub const DEFAULT_YAMUX_CONNECTION_WRITE_TIMEOUT_SECS: u64 = 10;
pub const MIN_YAMUX_STREAM_WINDOW_SIZE_KB: usize = 256;
pub const DEFAULT_YAMUX_STREAM_WINDOW_SIZE_KB: usize = 8192;
pub const DEFAULT_YAMUX_SERVER_MAX_STREAMS_PER_SESSION: usize = 128;
pub const DEFAULT_YAMUX_SERVER_CONNECTION_WRITE_TIMEOUT_SECS: u64 = 10;
pub const DEFAULT_YAMUX_SERVER_STREAM_WINDOW_SIZE_KB: usize = 8192;

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

    #[serde(default)]
    pub udp_mode: TcpTransportMode,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            tcp_mode: TcpTransportMode::Auto,
            udp_mode: TcpTransportMode::Auto,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct YamuxConfig {
    #[serde(default)]
    pub tcp: YamuxTransportConfig,

    #[serde(default)]
    pub udp: YamuxTransportConfig,
}

impl YamuxConfig {
    pub fn tcp_session_count(&self) -> usize {
        self.tcp.session_count()
    }

    pub fn udp_session_count(&self) -> usize {
        self.udp.session_count()
    }

    pub fn tcp_settings(&self) -> YamuxSettings {
        self.tcp.settings()
    }

    pub fn udp_settings(&self) -> YamuxSettings {
        self.udp.settings()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct YamuxServerConfig {
    #[serde(default)]
    pub tcp: YamuxServerTransportConfig,

    #[serde(default)]
    pub udp: YamuxServerTransportConfig,
}

impl YamuxServerConfig {
    pub fn tcp_settings(&self) -> YamuxSettings {
        self.tcp.settings()
    }

    pub fn udp_settings(&self) -> YamuxSettings {
        self.udp.settings()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct YamuxTransportConfig {
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

impl Default for YamuxTransportConfig {
    fn default() -> Self {
        Self {
            sessions: DEFAULT_TCP_YAMUX_SESSIONS,
            max_streams_per_session: DEFAULT_YAMUX_MAX_STREAMS_PER_SESSION,
            open_stream_timeout_secs: DEFAULT_YAMUX_OPEN_STREAM_TIMEOUT_SECS,
            keepalive_interval_secs: DEFAULT_YAMUX_KEEPALIVE_INTERVAL_SECS,
            connection_write_timeout_secs: DEFAULT_YAMUX_CONNECTION_WRITE_TIMEOUT_SECS,
            stream_window_size_kb: DEFAULT_YAMUX_STREAM_WINDOW_SIZE_KB,
        }
    }
}

impl YamuxTransportConfig {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct YamuxServerTransportConfig {
    #[serde(default = "default_yamux_server_max_streams_per_session")]
    pub max_streams_per_session: usize,

    #[serde(default = "default_yamux_keepalive_interval_secs")]
    pub keepalive_interval_secs: u64,

    #[serde(default = "default_yamux_server_connection_write_timeout_secs")]
    pub connection_write_timeout_secs: u64,

    #[serde(default = "default_yamux_server_stream_window_size_kb")]
    pub stream_window_size_kb: usize,
}

impl Default for YamuxServerTransportConfig {
    fn default() -> Self {
        Self {
            max_streams_per_session: DEFAULT_YAMUX_SERVER_MAX_STREAMS_PER_SESSION,
            keepalive_interval_secs: DEFAULT_YAMUX_KEEPALIVE_INTERVAL_SECS,
            connection_write_timeout_secs: DEFAULT_YAMUX_SERVER_CONNECTION_WRITE_TIMEOUT_SECS,
            stream_window_size_kb: DEFAULT_YAMUX_SERVER_STREAM_WINDOW_SIZE_KB,
        }
    }
}

impl YamuxServerTransportConfig {
    pub fn settings(&self) -> YamuxSettings {
        YamuxSettings {
            max_streams_per_session: self.max_streams_per_session.max(1),
            open_stream_timeout: Duration::from_secs(DEFAULT_YAMUX_OPEN_STREAM_TIMEOUT_SECS),
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
        YamuxTransportConfig::default().settings()
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
    DEFAULT_TCP_YAMUX_SESSIONS
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

fn default_yamux_server_max_streams_per_session() -> usize {
    DEFAULT_YAMUX_SERVER_MAX_STREAMS_PER_SESSION
}

fn default_yamux_server_connection_write_timeout_secs() -> u64 {
    DEFAULT_YAMUX_SERVER_CONNECTION_WRITE_TIMEOUT_SECS
}

fn default_yamux_server_stream_window_size_kb() -> usize {
    DEFAULT_YAMUX_SERVER_STREAM_WINDOW_SIZE_KB
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_separate_tcp_udp_yamux_config() {
        let config: YamuxConfig = toml::from_str(
            r#"
[tcp]
sessions = 2
max_streams_per_session = 64
open_stream_timeout_secs = 7
keepalive_interval_secs = 11
connection_write_timeout_secs = 13
stream_window_size_kb = 768

[udp]
sessions = 3
max_streams_per_session = 32
open_stream_timeout_secs = 5
keepalive_interval_secs = 0
connection_write_timeout_secs = 9
stream_window_size_kb = 1024
"#,
        )
        .unwrap();

        assert_eq!(config.tcp_session_count(), 2);
        assert_eq!(config.udp_session_count(), 3);

        let tcp = config.tcp_settings();
        assert_eq!(tcp.max_streams_per_session, 64);
        assert_eq!(tcp.open_stream_timeout, Duration::from_secs(7));
        assert_eq!(tcp.keepalive_interval, Some(Duration::from_secs(11)));
        assert_eq!(tcp.connection_write_timeout, Duration::from_secs(13));
        assert_eq!(tcp.stream_window_size_kb, 768);

        let udp = config.udp_settings();
        assert_eq!(udp.max_streams_per_session, 32);
        assert_eq!(udp.open_stream_timeout, Duration::from_secs(5));
        assert_eq!(udp.keepalive_interval, None);
        assert_eq!(udp.connection_write_timeout, Duration::from_secs(9));
        assert_eq!(udp.stream_window_size_kb, 1024);
    }

    #[test]
    fn rejects_legacy_flat_yamux_config() {
        let err = toml::from_str::<YamuxConfig>(
            r#"
sessions = 5
max_streams_per_session = 256
"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn rejects_server_yamux_sessions_config() {
        let err = toml::from_str::<YamuxServerConfig>(
            r#"
[tcp]
sessions = 5
max_streams_per_session = 256
"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn rejects_server_yamux_open_stream_timeout_config() {
        let err = toml::from_str::<YamuxServerConfig>(
            r#"
[tcp]
open_stream_timeout_secs = 10
max_streams_per_session = 256
"#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn server_yamux_defaults_are_acceptor_friendly() {
        let config = YamuxServerConfig::default();
        let tcp = config.tcp_settings();
        let udp = config.udp_settings();

        assert_eq!(
            tcp.max_streams_per_session,
            DEFAULT_YAMUX_SERVER_MAX_STREAMS_PER_SESSION
        );
        assert_eq!(
            udp.max_streams_per_session,
            DEFAULT_YAMUX_SERVER_MAX_STREAMS_PER_SESSION
        );
        assert_eq!(
            tcp.connection_write_timeout,
            Duration::from_secs(DEFAULT_YAMUX_SERVER_CONNECTION_WRITE_TIMEOUT_SECS)
        );
        assert_eq!(
            udp.connection_write_timeout,
            Duration::from_secs(DEFAULT_YAMUX_SERVER_CONNECTION_WRITE_TIMEOUT_SECS)
        );
        assert_eq!(
            tcp.stream_window_size_kb,
            DEFAULT_YAMUX_SERVER_STREAM_WINDOW_SIZE_KB
        );
        assert_eq!(
            udp.stream_window_size_kb,
            DEFAULT_YAMUX_SERVER_STREAM_WINDOW_SIZE_KB
        );
    }
}
