mod config;
mod connection_pool;
mod http_proxy;
mod socks5_proxy;
mod unified_proxy;

use anyhow::{Context, Result};
use clap::Parser;
use common::crypto;
use std::{net::SocketAddr, sync::Arc};
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(name = "ppaass-agent")]
#[command(about = "PPaass Agent - Client side proxy", long_about = None)]
struct Args {
    /// Config file path
    #[arg(short, long, default_value = "agent.toml")]
    config: String,

    /// Proxy listen address (auto-detects HTTP/SOCKS5)
    #[arg(long, env = "AGENT_LISTEN_ADDR")]
    listen_addr: Option<String>,

    /// Proxy server address
    #[arg(long, env = "AGENT_PROXY_ADDR")]
    proxy_addr: Option<String>,

    /// Username
    #[arg(long, env = "AGENT_USERNAME")]
    username: Option<String>,

    /// Password
    #[arg(long, env = "AGENT_PASSWORD")]
    password: Option<String>,

    /// Tokio console listen address (host:port)
    #[arg(long, env = "AGENT_CONSOLE_ADDR")]
    console_addr: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Load configuration
    let mut cfg = config::AgentConfig::load(&args.config)?;

    // Override with command line arguments
    if let Some(listen_addr) = args.listen_addr {
        cfg.listen_addr = listen_addr;
    }
    if let Some(proxy_addr) = args.proxy_addr {
        cfg.proxy_addr = proxy_addr;
    }
    if let Some(username) = args.username {
        cfg.user.username = username;
    }
    if let Some(password) = args.password {
        cfg.user.password = password;
    }
    if let Some(console_addr) = args.console_addr {
        cfg.tokio_console_addr = console_addr;
    }

    let console_addr: SocketAddr = cfg
        .tokio_console_addr
        .parse()
        .with_context(|| format!("Invalid tokio_console_addr: {}", cfg.tokio_console_addr))?;

    // Initialize tracing after configuration is ready
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "agent=info,common=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .with(
            console_subscriber::ConsoleLayer::builder()
                .with_default_env()
                .server_addr(console_addr)
                .spawn(),
        )
        .init();

    info!("Starting agent with configuration: {:?}", cfg);

    // Generate RSA keys if not present
    if cfg.user.rsa_public_key.is_empty() || cfg.user.rsa_private_key.is_empty() {
        info!("Generating RSA key pair...");
        let (public_key, private_key) = crypto::generate_rsa_keypair()?;
        cfg.user.rsa_public_key = public_key;
        cfg.user.rsa_private_key = private_key;
        cfg.save(&args.config)?;
        info!("RSA keys generated and saved to configuration file");
    }

    let cfg = Arc::new(cfg);

    // Create connection pool
    let pool = connection_pool::ConnectionPool::new(cfg.clone()).await?;
    let pool = Arc::new(pool);

    // Start unified proxy server (auto-detects HTTP/SOCKS5)
    let proxy_server = {
        let cfg = cfg.clone();
        let pool = pool.clone();
        tokio::spawn(async move {
            if let Err(e) = unified_proxy::start_server(cfg, pool).await {
                error!("Unified proxy server error: {}", e);
            }
        })
    };

    info!("Agent started successfully");
    info!(
        "Proxy listening on: {} (auto-detecting HTTP/SOCKS5)",
        cfg.listen_addr
    );

    // Wait for server or shutdown signal
    tokio::select! {
        _ = proxy_server => {
            error!("Proxy server stopped");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal");
        }
    }

    info!("Shutting down agent");
    Ok(())
}
