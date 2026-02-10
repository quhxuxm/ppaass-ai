mod config;
mod connection_pool;
mod error;
mod http_handler;
mod server;
mod socks5_handler;
mod telemetry;
mod tui;

use crate::config::AgentConfig;
use crate::telemetry::UiEvent;
use anyhow::Result;
use clap::Parser;
use mimalloc::MiMalloc;
use tracing::info;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "config/agent.toml")]
    config: String,

    /// Override listen address
    #[arg(short, long)]
    listen: Option<String>,

    /// Override proxy server address
    #[arg(short, long)]
    proxy: Option<String>,

    /// Override username
    #[arg(short, long)]
    username: Option<String>,

    /// Override log level (trace, debug, info, warn, error)
    #[arg(long)]
    log_level: Option<String>,

    /// Override log directory
    #[arg(long)]
    log_dir: Option<String>,

    /// Override log file name
    #[arg(long)]
    log_file: Option<String>,

    /// Override number of runtime worker threads
    #[arg(long)]
    runtime_threads: Option<usize>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    // Load configuration first
    let mut config = AgentConfig::load(&args.config)?;

    // Override with command line arguments
    if let Some(listen) = args.listen {
        config.listen_addr = listen;
    }
    if let Some(proxy) = args.proxy {
        config.proxy_addrs = vec![proxy];
    }
    if let Some(username) = args.username {
        config.username = username;
    }
    if let Some(log_level) = args.log_level {
        config.log_level = log_level;
    }
    if let Some(log_dir) = args.log_dir {
        config.log_dir = Some(log_dir);
    }
    if let Some(log_file) = args.log_file {
        config.log_file = log_file;
    }
    if let Some(runtime_threads) = args.runtime_threads {
        config.runtime_threads = Some(runtime_threads);
    }
    // Create log directory if it doesn't exist
    if let Some(ref log_dir) = config.log_dir {
        std::fs::create_dir_all(log_dir)?;
    }
    let (ui_tx, ui_rx) = tokio::sync::mpsc::unbounded_channel::<UiEvent>();
    telemetry::install_event_sender(ui_tx.clone());
    let _guard = telemetry::init_tracing(
        config.log_dir.as_deref(),
        &config.log_file,
        &config.log_level,
        ui_tx,
    );

    // Build Tokio runtime with configurable thread count
    let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
    runtime_builder.thread_stack_size(config.async_runtime_stack_size_mb * 1024 * 1024);
    runtime_builder.enable_all();

    if let Some(threads) = config.runtime_threads {
        info!("Configuring Tokio runtime with {} worker threads", threads);
        runtime_builder.worker_threads(threads);
    }

    let runtime = runtime_builder.build()?;
    runtime.block_on(async { tui::run(config, ui_rx).await })
}
