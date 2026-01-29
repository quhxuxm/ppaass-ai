mod api;
mod config;
mod relay;
mod session;
mod user_manager;

use anyhow::{Context, Result};
use clap::Parser;
use common::crypto;
use std::{net::SocketAddr, sync::Arc};
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(name = "ppaass-proxy")]
#[command(about = "PPaass Proxy - Server side proxy", long_about = None)]
struct Args {
    /// Config file path
    #[arg(short, long, default_value = "proxy.toml")]
    config: String,

    /// Proxy listen address
    #[arg(long, env = "PROXY_LISTEN_ADDR")]
    listen_addr: Option<String>,

    /// API listen address
    #[arg(long, env = "PROXY_API_ADDR")]
    api_addr: Option<String>,

    /// Tokio console listen address (host:port)
    #[arg(long, env = "PROXY_CONSOLE_ADDR")]
    console_addr: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Load configuration
    let mut cfg = config::ProxyConfig::load(&args.config)?;

    // Override with command line arguments
    if let Some(listen_addr) = args.listen_addr {
        cfg.listen_addr = listen_addr;
    }
    if let Some(api_addr) = args.api_addr {
        cfg.api_listen_addr = api_addr;
    }
    if let Some(console_addr) = args.console_addr {
        cfg.tokio_console_addr = console_addr;
    }

    let console_addr: SocketAddr = cfg
        .tokio_console_addr
        .parse()
        .with_context(|| format!("Invalid tokio_console_addr: {}", cfg.tokio_console_addr))?;

    // Initialize tracing once configuration is available
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "proxy=info,common=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .with(
            console_subscriber::ConsoleLayer::builder()
                .with_default_env()
                .server_addr(console_addr)
                .spawn(),
        )
        .init();

    info!("Starting proxy with configuration: {:?}", cfg);

    // Generate RSA keys if not present
    if cfg.rsa_public_key.is_empty() || cfg.rsa_private_key.is_empty() {
        info!("Generating RSA key pair...");
        let (public_key, private_key) = crypto::generate_rsa_keypair()?;
        cfg.rsa_public_key = public_key;
        cfg.rsa_private_key = private_key;
        cfg.save(&args.config)?;
        info!("RSA keys generated and saved to configuration file");
    }

    let cfg = Arc::new(cfg);

    // Initialize user manager
    let user_manager = user_manager::UserManager::new(cfg.clone());
    let user_manager = Arc::new(user_manager);

    // Initialize session manager
    let session_manager = session::SessionManager::new();
    let session_manager = Arc::new(session_manager);

    // Start relay server
    let relay_server = {
        let cfg = cfg.clone();
        let user_manager = user_manager.clone();
        let session_manager = session_manager.clone();
        tokio::spawn(async move {
            if let Err(e) = relay::start_server(cfg, user_manager, session_manager).await {
                error!("Relay server error: {}", e);
            }
        })
    };

    // Start API server
    let api_server = {
        let cfg = cfg.clone();
        let user_manager = user_manager.clone();
        let session_manager = session_manager.clone();
        tokio::spawn(async move {
            if let Err(e) = api::start_server(cfg, user_manager, session_manager).await {
                error!("API server error: {}", e);
            }
        })
    };

    info!("Proxy started successfully");
    info!("Relay server listening on: {}", cfg.listen_addr);
    info!("API server listening on: {}", cfg.api_listen_addr);

    // Wait for both servers
    tokio::select! {
        _ = relay_server => {
            error!("Relay server stopped");
        }
        _ = api_server => {
            error!("API server stopped");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal");
        }
    }

    info!("Shutting down proxy");
    Ok(())
}
