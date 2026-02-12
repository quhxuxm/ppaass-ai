mod api;
mod bandwidth;
mod config;
mod connection;
mod entity;
mod error;
mod server;
mod telemetry;
mod tui;
mod user_manager;

use crate::config::{ProxyConfig, UsersConfig};
use crate::telemetry::UiEvent;
use crate::user_manager::UserManager;
use anyhow::Result;
use clap::Parser;
use common::init_tracing;
use mimalloc::MiMalloc;
use tracing::{info, instrument};

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

    /// Override log file name
    #[arg(long)]
    log_file: Option<String>,

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

    if let Some(users_toml_path) = args.migrate_users {
        let _guard = init_tracing(
            config.log_dir.as_deref(),
            &config.log_file,
            &config.log_level,
        );
        let runtime = build_runtime(&config)?;
        runtime.block_on(async {
            info!("Migrating users from {} to database", users_toml_path);
            migrate_users_from_toml(&config, &users_toml_path).await?;
            info!("User migration completed successfully");
            Ok(())
        })
    } else {
        let (ui_tx, ui_rx) = tokio::sync::mpsc::unbounded_channel::<UiEvent>();
        telemetry::install_event_sender(ui_tx.clone());
        let _guard = telemetry::init_tracing(
            config.log_dir.as_deref(),
            &config.log_file,
            &config.log_level,
            ui_tx,
            config.console_port,
        );
        let runtime = build_runtime(&config)?;
        let config_path = args.config;
        runtime.block_on(async { tui::run(config, config_path, ui_rx).await })
    }
}

fn build_runtime(config: &ProxyConfig) -> Result<tokio::runtime::Runtime> {
    let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
    runtime_builder.thread_stack_size(config.async_runtime_stack_size_mb * 1024 * 1024);
    runtime_builder.enable_all();

    if let Some(threads) = config.runtime_threads {
        info!("Configuring Tokio runtime with {} worker threads", threads);
        runtime_builder.worker_threads(threads);
    }

    runtime_builder.build().map_err(Into::into)
}

#[instrument(skip(config))]
async fn migrate_users_from_toml(config: &ProxyConfig, users_toml_path: &str) -> Result<()> {
    // Load users from TOML file
    let users_config = UsersConfig::load(users_toml_path)?;
    info!("Found {} users in TOML file", users_config.users.len());

    // Initialize user manager (this creates the database if needed)
    let user_manager =
        UserManager::new(&config.database_path, &config.keys_dir, &config.db_pool).await?;

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
