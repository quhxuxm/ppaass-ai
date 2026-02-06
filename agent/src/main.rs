mod config;
mod connection_pool;
mod error;
mod http_handler;
mod server;
mod socks5_handler;

use crate::config::AgentConfig;
use crate::server::AgentServer;
use anyhow::Result;
use clap::Parser;
use common::init_tracing;
use tracing::info;

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
        config.proxy_addr = proxy;
    }
    if let Some(username) = args.username {
        config.username = username;
    }
    if let Some(log_level) = args.log_level {
        config.log_level = log_level;
    }
    if let Some(log_dir) = args.log_dir {
        config.log_dir = log_dir;
    }
    if let Some(runtime_threads) = args.runtime_threads {
        config.runtime_threads = Some(runtime_threads);
    }

    // Create log directory if it doesn't exist
    std::fs::create_dir_all(&config.log_dir)?;
    let _guard = init_tracing(&config.log_dir, "agent.log", &config.log_level);
    // Build Tokio runtime with configurable thread count
    let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
    runtime_builder.enable_all();

    if let Some(threads) = config.runtime_threads {
        info!("Configuring Tokio runtime with {} worker threads", threads);
        runtime_builder.worker_threads(threads);
    }

    let runtime = runtime_builder.build()?;

    runtime.block_on(async {
        info!("Starting PPAASS Agent");
        info!("Listen address: {}", config.listen_addr);
        info!("Proxy address: {}", config.proxy_addr);
        info!("Username: {}", config.username);
        info!("Log level: {}", config.log_level);
        info!("Log directory: {}", config.log_dir);
        if let Some(threads) = config.runtime_threads {
            info!("Runtime threads: {}", threads);
        } else {
            info!("Runtime threads: default (CPU cores)");
        }

        // Initialize tokio-console if configured
        #[cfg(feature = "console")]
        if let Some(console_port) = config.console_port {
            info!("Starting tokio-console on port {}", console_port);
            console_subscriber::init();
        }

        // Start agent server
        let server = AgentServer::new(config).await?;
        server.run().await?;
        Ok(())
    })
}
