pub mod config;
pub mod server;
pub mod telemetry;

mod direct_access;
mod error;
mod http_handler;
mod privilege;
mod socks5_handler;
mod tcp_relay;
mod tun_handler;
mod tun_helper_client;
mod yamux_session;

use crate::config::AgentConfig;
use crate::server::AgentServer;
use anyhow::Result;
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

pub use tun_handler::PacketCaptureController;

#[cfg(target_os = "macos")]
pub fn run_tun_helper_service(
    socket: Option<&str>,
    allowed_uid: Option<u32>,
    log_level: Option<&str>,
) -> anyhow::Result<()> {
    tun_handler::helper_service::run(socket, allowed_uid, log_level)
}

pub async fn run_agent(
    config: AgentConfig,
    proxy_addrs: Vec<String>,
    shutdown: CancellationToken,
) -> Result<()> {
    let packet_capture =
        PacketCaptureController::new(PathBuf::from(&config.tun.packet_capture.file));
    run_agent_with_packet_capture(config, proxy_addrs, shutdown, packet_capture).await
}

pub async fn run_agent_with_packet_capture(
    config: AgentConfig,
    proxy_addrs: Vec<String>,
    shutdown: CancellationToken,
    packet_capture: PacketCaptureController,
) -> Result<()> {
    if proxy_addrs.is_empty() {
        anyhow::bail!("未分配受管 Proxy 地址");
    }
    info!("PPAASS Desktop Agent 启动中");
    info!("监听地址：    {}", config.listen_addr);
    info!("已载入 {} 个受管 Proxy 节点", proxy_addrs.len());
    info!("用户名：      {}", config.username);
    info!("压缩模式：    {}", config.get_compression_mode());
    info!("日志级别：    {}", config.log_level);
    info!(
        "日志目录：    {}",
        config.log_dir.as_deref().unwrap_or("UI 内存日志")
    );
    if config.tun.enabled {
        info!(
            "TUN 模式已启用：设备={} ipv4={} mtu={}",
            config.tun.name, config.tun.ipv4, config.tun.mtu
        );
    }

    match AgentServer::new(config, proxy_addrs, packet_capture).await {
        Ok(server) => {
            if let Err(err) = server.run(shutdown).await {
                error!("Agent 服务器异常停止：{}", err);
                return Err(err.into());
            }
            info!("Agent 服务器已停止");
            Ok(())
        }
        Err(err) => {
            error!("Agent 服务器初始化失败：{}", err);
            Err(err.into())
        }
    }
}
