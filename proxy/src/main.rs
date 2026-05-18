mod api;
mod bandwidth;
mod config;
mod connection;
mod error;
mod server;
mod user_manager;

use crate::config::ProxyConfig;
use crate::server::ProxyServer;
use anyhow::{Result, anyhow};
use clap::Parser;
use common::init_tracing;
use mimalloc::MiMalloc;
use std::collections::BTreeSet;
use tracing::info;

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

    /// 覆盖 API 地址
    #[arg(short, long)]
    api: Option<String>,

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

    // 先加载配置
    let mut config = ProxyConfig::load(&args.config)?;

    // 使用命令行参数覆盖配置
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
    if let Some(outbound_interface) = args.outbound_interface {
        config.outbound_interface = Some(outbound_interface);
    }

    // 如果日志目录不存在，则创建
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
        info!("API 地址：{}", config.api_addr);
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

        // 如果配置了 tokio-console，则初始化
        #[cfg(feature = "console")]
        if let Some(console_port) = config.console_port {
            info!("正在端口 {} 启动 tokio-console", console_port);
            console_subscriber::init();
        }

        // 启动代理服务器
        let server = ProxyServer::new(config).await?;
        server.run().await?;
        Ok(())
    })
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
        return Ok(());
    }

    let interfaces = if_addrs::get_if_addrs()
        .map_err(|e| anyhow!("读取本机网络设备列表失败：{e}"))?
        .into_iter()
        .map(|iface| iface.name)
        .collect::<BTreeSet<_>>();

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
