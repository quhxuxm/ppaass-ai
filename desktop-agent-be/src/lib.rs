pub mod config;
pub mod server;
pub mod telemetry;

mod cli;
mod connection_pool;
mod direct_access;
mod error;
mod http_handler;
mod privilege;
mod socks5_handler;
mod tun_handler;
mod tun_helper_client;

use crate::config::AgentConfig;
use crate::server::AgentServer;
use anyhow::Result;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

pub async fn run_agent(config: AgentConfig, shutdown: CancellationToken) -> Result<()> {
    info!("PPAASS Desktop Agent 启动中");
    info!("监听地址：    {}", config.listen_addr);
    info!("代理地址列表：[{}]", config.proxy_addrs.join(", "));
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

    match AgentServer::new(config).await {
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
