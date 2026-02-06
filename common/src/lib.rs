pub mod client_connection;
pub mod error;

pub use client_connection::{
    AuthenticatedConnection, ClientConnection, ClientConnectionConfig, ClientStream,
};
pub use error::{CommonError, Result};

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

pub fn init_tracing(log_dir: Option<&str>, log_file: &str, log_level: &str) -> Option<WorkerGuard> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    if let Some(log_dir) = log_dir {
        let file_appender = tracing_appender::rolling::daily(log_dir, log_file);
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        tracing_subscriber::registry()
            .with(filter)
            .with(
                fmt::layer()
                    .with_writer(non_blocking)
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_line_number(true)
                    .with_ansi(false),
            )
            .init();
        Some(guard)
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(
                fmt::layer()
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_line_number(true)
                    .with_ansi(true),
            )
            .init();
        None
    }
}
