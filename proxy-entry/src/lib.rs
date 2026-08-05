//! Proxy Entry 数据面服务库。
//!
//! 可执行程序只负责 CLI 参数覆盖；日志、运行时和服务生命周期由这里统一管理。

pub mod access_log;
pub mod config;
pub mod connection;
pub mod control_plane;
pub mod error;
pub mod native_udp;
pub mod server;
pub mod user_manager;

use crate::config::ProxyConfig;
use crate::server::ProxyServer;
use anyhow::{Result, anyhow};
use common::{init_tracing, panic_payload_message};
use futures::FutureExt;
use std::collections::BTreeSet;
use std::panic::AssertUnwindSafe;
use std::time::Duration;
use tracing::{error, info, warn};

/// 启动 Proxy Entry 进程运行时并持续运行数据面服务。
pub fn run(config: ProxyConfig) -> Result<()> {
    if let Some(ref log_dir) = config.log_dir {
        std::fs::create_dir_all(log_dir)?;
    }
    let _guard = init_tracing(
        config.log_dir.as_deref(),
        &config.log_file,
        &config.log_level,
    );
    validate_outbound_interface(&config)?;

    let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
    runtime_builder.thread_stack_size(config.async_runtime_stack_size_mb * 1024 * 1024);
    runtime_builder.enable_all();
    if let Some(threads) = config.runtime_threads {
        info!("配置 Tokio 运行时工作线程数：{}", threads);
        runtime_builder.worker_threads(threads);
    }
    let runtime = runtime_builder.build()?;

    runtime.block_on(async {
        log_startup_configuration(&config);
        loop {
            let server = ProxyServer::new(config.clone()).await?;
            match AssertUnwindSafe(server.run()).catch_unwind().await {
                Ok(Ok(())) => break,
                Ok(Err(err)) => return Err(err.into()),
                Err(payload) => {
                    error!(
                        "proxy 主服务 panic，准备重启监听循环：{}",
                        panic_payload_message(payload.as_ref())
                    );
                    warn!("500ms 后重启 proxy 主服务");
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
        Ok(())
    })
}

fn log_startup_configuration(config: &ProxyConfig) {
    info!("PPAASS Proxy 启动中");
    info!("监听地址：{}", config.listen_addr);
    info!("日志级别：{}", config.log_level);
    info!(
        "日志目录：{}",
        config.log_dir.as_deref().unwrap_or("控制台")
    );
    if config.log_dir.is_some() {
        info!("日志文件：{}", config.log_file);
    }
    if let Some(threads) = config.runtime_threads {
        info!("运行时线程数：{}", threads);
    } else {
        info!("运行时线程数：默认（CPU 核心数）");
    }
    info!(
        "出站网络设备：{}",
        config
            .outbound_interface
            .as_deref()
            .filter(|name| !name.trim().is_empty())
            .unwrap_or("默认路由")
    );
    info!("Proxy Entry 实例：{}", config.entry_id);
    info!("Proxy Entry 公网地址：{}", config.advertised_address);
    info!("Registry 地址：{}", config.registry_url);
}

fn validate_outbound_interface(config: &ProxyConfig) -> Result<()> {
    let Some(interface) = config
        .outbound_interface
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
    else {
        return Ok(());
    };

    if interface.eq_ignore_ascii_case("auto") {
        info!("自动绑定出站网络设备：{}", interface);
        return Ok(());
    }
    let interfaces = if_addrs::get_if_addrs()
        .map_err(|e| anyhow!("读取本机网络设备列表失败：{e}"))?
        .into_iter()
        .map(|iface| iface.name)
        .collect::<BTreeSet<_>>();
    info!(
        "本机网络设备列表：{}",
        interfaces.iter().cloned().collect::<Vec<_>>().join(", ")
    );
    if interfaces.contains(interface) {
        return Ok(());
    }
    let available = if interfaces.is_empty() {
        "<未发现可用网络设备>".to_string()
    } else {
        interfaces.into_iter().collect::<Vec<_>>().join(", ")
    };

    Err(anyhow!(
        "配置的出站网络设备不存在：{interface}。请删除 outbound_interface 以使用系统默认路由，\
         改为当前机器上的设备名，或设置 outbound_interface = \"auto\" 自动绑定原始默认路由设备。\
         可用设备：{available}"
    ))
}
