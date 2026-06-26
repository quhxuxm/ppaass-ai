pub mod client_connection;
pub mod dns;
pub mod error;
pub mod quic;
pub mod task_guard;
pub mod tun_control;
pub mod yamux_settings;

pub use client_connection::{
    AuthenticatedConnection, BindInterface, ClientConnectionConfig, ClientStream,
    YAMUX_OPEN_STREAM_TIMEOUT_MESSAGE, YAMUX_SESSION_STREAM_CAPACITY_EXHAUSTED_MESSAGE,
    YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE, YamuxClientConnection, YamuxClientStream,
    bind_socket_to_interface,
};
pub use error::{CommonError, Result};
pub use quic::{QuicPolicy, QuicUdpStats, QuicUdpStatsSnapshot};
pub use task_guard::{install_known_smoltcp_panic_hook, panic_payload_message, spawn_guarded};
pub use yamux_settings::{
    YamuxConfig, YamuxServerConfig, YamuxServerTransportConfig, YamuxSettings, YamuxTransportConfig,
};

use std::time::{SystemTime, UNIX_EPOCH};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

pub fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub fn generate_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let timestamp = current_timestamp();
    let counter = COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("{}-{}", timestamp, counter)
}

/// 初始化全局 tracing。
///
/// 若 `log_dir` 不为空，日志只会按天滚动写入该目录下的文件，不再同时输出到控制台。
/// 开启文件日志时，返回的 guard 必须在程序整个生命周期内保持存活。
pub fn init_tracing(log_dir: Option<&str>, log_file: &str, log_level: &str) -> Option<WorkerGuard> {
    let filter = EnvFilter::new(log_level);

    if let Some(log_dir) = log_dir {
        let file_appender = tracing_appender::rolling::daily(log_dir, log_file);
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        let file_layer = fmt::layer()
            .with_writer(non_blocking)
            .with_target(true)
            .with_thread_ids(true)
            .with_line_number(true)
            .with_ansi(false);
        tracing_subscriber::registry()
            .with(filter)
            .with(file_layer)
            .init();
        Some(guard)
    } else {
        let stdout_layer = fmt::layer()
            .with_target(true)
            .with_thread_ids(true)
            .with_line_number(true)
            .with_ansi(true);
        tracing_subscriber::registry()
            .with(filter)
            .with(stdout_layer)
            .init();
        None
    }
}
