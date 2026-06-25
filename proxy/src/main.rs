//! proxy 可执行入口。
//!
//! 这里负责把“进程级”的事情准备好：读取配置、覆盖命令行参数、初始化日志、
//! 校验出站网卡配置、构建 Tokio runtime，然后把真正的网络服务交给 `ProxyServer`。
//! 具体的认证、CONNECT 分流和数据中继都在 `server` 与 `connection` 模块中。

mod config;
mod connection;
mod error;
mod server;
mod user_manager;

use crate::config::ProxyConfig;
use crate::server::ProxyServer;
use anyhow::{Result, anyhow};
use clap::Parser;
use common::{init_tracing, panic_payload_message};
use futures::FutureExt;
#[cfg(feature = "mimalloc-allocator")]
use mimalloc::MiMalloc;
use std::collections::BTreeSet;
use std::panic::AssertUnwindSafe;
use std::time::Duration;
use tracing::{error, info, warn};

#[cfg(feature = "mimalloc-allocator")]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 配置文件路径
    #[arg(short, long, default_value = "proxy.toml")]
    config: String,

    /// 覆盖监听地址
    #[arg(short, long)]
    listen: Option<String>,

    /// 覆盖日志级别（trace、debug、info、warn、error）
    #[arg(long)]
    log_level: Option<String>,

    /// 覆盖日志目录
    #[arg(long)]
    log_dir: Option<String>,

    /// 覆盖日志文件名
    #[arg(long)]
    log_file: Option<String>,

    /// 覆盖运行时工作线程数
    #[arg(long)]
    runtime_threads: Option<usize>,

    /// 覆盖 proxy 连接目标服务器时使用的出站网络设备名
    #[arg(long)]
    outbound_interface: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // 先加载配置文件，再让命令行参数覆盖配置项。
    // 这样同一份 proxy.toml 可用于生产默认值，本地调试时只覆盖少量参数。
    let mut config = ProxyConfig::load(&args.config)?;

    // 使用命令行参数覆盖配置。
    if let Some(listen) = args.listen {
        config.listen_addr = listen;
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
    if let Some(outbound_interface) = args.outbound_interface {
        config.outbound_interface = Some(outbound_interface);
    }

    // 日志初始化要在大部分 info!/warn! 之前完成；配置了 log_dir 时提前创建目录。
    if let Some(ref log_dir) = config.log_dir {
        std::fs::create_dir_all(log_dir)?;
    }
    let _guard = init_tracing(
        config.log_dir.as_deref(),
        &config.log_file,
        &config.log_level,
    );
    validate_outbound_interface(&config)?;

    // 构建 Tokio 运行时，线程数可配置
    let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
    runtime_builder.thread_stack_size(config.async_runtime_stack_size_mb * 1024 * 1024);
    runtime_builder.enable_all();

    if let Some(threads) = config.runtime_threads {
        info!("配置 Tokio 运行时工作线程数：{}", threads);
        runtime_builder.worker_threads(threads);
    }

    let runtime = runtime_builder.build()?;

    runtime.block_on(async {
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
        info!("用户配置文件：{}", config.users_path);

        // 主监听循环外面包一层 panic 恢复：单次服务 run panic 后重新建 listener。
        // 普通错误仍返回给进程，避免配置/绑定等硬错误被无限重启掩盖。
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

fn validate_outbound_interface(config: &ProxyConfig) -> Result<()> {
    // 未配置出站设备时不做校验，运行时交给系统默认路由处理。
    let Some(interface) = config
        .outbound_interface
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
    else {
        return Ok(());
    };

    if interface.eq_ignore_ascii_case("auto") {
        // auto 是逻辑设备名，不需要出现在系统网卡列表中。
        info!("自动绑定出站网络设备：{}", interface);
        return Ok(());
    }
    // 显式设备名在启动时提前校验，避免连接到来后才报“设备不存在”。
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
    // 报错中列出本机设备名，便于用户在 Windows/macOS 上修正配置。
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
