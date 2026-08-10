//! CI-only headless Agent harness.

use anyhow::Result;
use clap::Parser;
use desktop_agent_be::config::AgentConfig;
#[cfg(feature = "mimalloc-allocator")]
use mimalloc::MiMalloc;
use tokio_util::sync::CancellationToken;

#[cfg(feature = "mimalloc-allocator")]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    config: String,
    #[arg(long)]
    managed_proxy_address: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config = AgentConfig::load(&args.config)?;
    let _log_guard = desktop_agent_be::telemetry::init_tracing(
        config.log_dir.as_deref(),
        &config.log_file,
        &config.log_level,
    );
    let shutdown = CancellationToken::new();
    let signal = shutdown.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal.cancel();
        }
    });
    desktop_agent_be::run_agent(config, vec![args.managed_proxy_address], shutdown).await
}
