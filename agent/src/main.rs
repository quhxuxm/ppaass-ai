mod config;
mod error;
mod http_handler;
mod pool;
mod proxy_connection;
mod socks5_handler;
mod server;

use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

use crate::config::AgentConfig;
use crate::server::AgentServer;

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
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Load configuration first to get log_level
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

    // Initialize tracing with log level from config or CLI
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    let subscriber = FmtSubscriber::builder()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting PPAASS Agent");
    info!("Listen address: {}", config.listen_addr);
    info!("Proxy address: {}", config.proxy_addr);
    info!("Username: {}", config.username);
    info!("Log level: {}", config.log_level);

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
}
