//! Desktop Agent product executable.
//!
//! Normal Agent traffic must be started by the authenticated Desktop Agent UI,
//! which supplies server-managed Proxy addresses as runtime-only data. This
//! binary keeps only the hidden macOS helper service entry point.

use anyhow::Result;
use clap::Parser;
use desktop_agent_be::cli::CliArgs;
#[cfg(feature = "mimalloc-allocator")]
use mimalloc::MiMalloc;

#[cfg(feature = "mimalloc-allocator")]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn main() -> Result<()> {
    let args = CliArgs::parse();

    #[cfg(target_os = "macos")]
    if args.tun_helper_service {
        return desktop_agent_be::run_tun_helper_service(
            args.tun_helper_socket.as_deref(),
            args.tun_helper_allowed_uid,
            args.log_level.as_deref(),
        );
    }

    #[cfg(not(target_os = "macos"))]
    if args.tun_helper_service {
        anyhow::bail!("TUN helper service mode is only supported on macOS");
    }

    anyhow::bail!(
        "独立 desktop-agent 不再接受 Proxy 地址或启动代理流量；请使用 Desktop Agent UI 登录后启动"
    )
}
