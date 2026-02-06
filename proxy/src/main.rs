mod api;
mod bandwidth;
mod config;
mod connection;
mod entity;
mod error;
mod server;
mod user_manager;

use crate::config::{ProxyConfig, UsersConfig};
use crate::server::ProxyServer;
use crate::user_manager::UserManager;
use anyhow::Result;
use clap::Parser;
use mimalloc::MiMalloc;
use common::init_tracing;
use tracing::info;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "proxy.toml")]
    config: String,

    /// Override listen address
    #[arg(short, long)]
    listen: Option<String>,

    /// Override API address
    #[arg(short, long)]
    api: Option<String>,

    /// Override log level (trace, debug, info, warn, error)
    #[arg(long)]
    log_level: Option<String>,

    /// Override log directory
    #[arg(long)]
    log_dir: Option<String>,

    /// Override number of runtime worker threads
    #[arg(long)]
    runtime_threads: Option<usize>,

    /// Migrate users from a TOML file to the SQLite database
    #[arg(long)]
    migrate_users: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Load configuration first
    let mut config = ProxyConfig::load(&args.config)?;

    // Override with command line arguments
    if let Some(listen) = args.listen {
        config.listen_addr = listen;
    }
    if let Some(api) = args.api {
        config.api_addr = api;
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
    let _guard = init_tracing(&config.log_dir, "proxy.log", &config.log_level);
    // Build Tokio runtime with configurable thread count
    let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
    runtime_builder.enable_all();

    if let Some(threads) = config.runtime_threads {
        info!("Configuring Tokio runtime with {} worker threads", threads);
        runtime_builder.worker_threads(threads);
    }

    let runtime = runtime_builder.build()?;

    runtime.block_on(async {
        info!("Starting PPAASS Proxy");
        info!("Listen address: {}", config.listen_addr);
        info!("API address: {}", config.api_addr);
        info!("Log level: {}", config.log_level);
        info!("Log directory: {}", config.log_dir);
        if let Some(threads) = config.runtime_threads {
            info!("Runtime threads: {}", threads);
        } else {
            info!("Runtime threads: default (CPU cores)");
        }

        // Handle user migration if requested
        if let Some(users_toml_path) = args.migrate_users {
            info!("Migrating users from {} to database", users_toml_path);
            migrate_users_from_toml(&config, &users_toml_path).await?;
            info!("User migration completed successfully");
            return Ok(());
        }

        // Initialize tokio-console if configured
        #[cfg(feature = "console")]
        if let Some(console_port) = config.console_port {
            info!("Starting tokio-console on port {}", console_port);
            console_subscriber::init();
        }

        // Start proxy server
        let server = ProxyServer::new(config).await?;
        server.run().await?;
        Ok(())
    })
}

async fn migrate_users_from_toml(config: &ProxyConfig, users_toml_path: &str) -> Result<()> {
    // Load users from TOML file
    let users_config = UsersConfig::load(users_toml_path)?;
    info!("Found {} users in TOML file", users_config.users.len());

    // Initialize user manager (this creates the database if needed)
    let user_manager = UserManager::new(&config.database_path, &config.keys_dir).await?;

    // Import each user
    for (username, user_config) in users_config.users {
        info!("Importing user: {}", username);

        // Check if user already exists
        if let Ok(Some(_)) = user_manager.get_user(&username).await {
            info!("User {} already exists, skipping", username);
            continue;
        }

        // Import user directly with their existing public key
        user_manager
            .import_user(
                username.clone(),
                user_config.public_key_pem.clone(),
                user_config.bandwidth_limit_mbps,
            )
            .await?;

        info!("User {} imported successfully", username);
    }

    Ok(())
}
