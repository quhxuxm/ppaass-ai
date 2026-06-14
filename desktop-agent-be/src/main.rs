//! Desktop Agent 可执行入口。
//!
//! 这里负责进程级初始化：读取 agent.toml、应用命令行覆盖、启动日志和 Tokio runtime，
//! 然后把真正的本地代理服务交给 `AgentServer`。如果启用 TUN 模式，`AgentServer`
//! 会同时保留本地 HTTP/SOCKS 监听和系统级 TUN 转发。

mod cli;
mod config;
mod connection_pool;
mod direct_access;
mod error;
mod http_handler;
mod privilege;
mod server;
mod socks5_handler;
mod telemetry;
mod tun_handler;
mod tun_helper_client;

use crate::cli::CliArgs;
use crate::config::AgentConfig;
use crate::server::AgentServer;
use anyhow::Result;
use clap::Parser;
#[cfg(feature = "mimalloc-allocator")]
use mimalloc::MiMalloc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

#[cfg(feature = "mimalloc-allocator")]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn main() -> Result<()> {
    let args = CliArgs::parse();

    // macOS 的 TUN helper 是同一个二进制的另一种运行模式：
    // 主进程通过本地 socket 请求 helper 做需要权限的 TUN/路由操作。
    #[cfg(target_os = "macos")]
    if args.tun_helper_service {
        return tun_handler::helper_service::run(
            args.tun_helper_socket.as_deref(),
            args.tun_helper_allowed_uid,
            args.log_level.as_deref(),
        );
    }

    #[cfg(not(target_os = "macos"))]
    if args.tun_helper_service {
        anyhow::bail!("TUN helper service mode is only supported on macOS");
    }

    // 加载配置文件，再用命令行参数覆盖少量运行时选项。
    // 这样本地调试可临时改 listen/proxy/TUN 参数，而不必修改配置文件。
    let mut config = AgentConfig::load(&args.config)?;

    // ── 基础参数覆盖 ──────────────────────────────────────────────────────────
    if let Some(listen) = args.listen {
        config.listen_addr = listen;
    }
    if let Some(proxy) = args.proxy {
        config.proxy_addrs = vec![proxy];
    }
    if let Some(username) = args.username {
        config.username = username;
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
    if let Some(compression_mode) = args.compression_mode {
        config.compression_mode = compression_mode;
    }
    if let Some(runtime_threads) = args.runtime_threads {
        config.runtime_threads = Some(runtime_threads);
    }

    // ── TUN 参数覆盖 ──────────────────────────────────────────────────────────
    if args.tun_enabled {
        config.tun.enabled = true;
    }
    if let Some(tun_name) = args.tun_name {
        config.tun.name = tun_name;
    }
    if let Some(tun_ipv4) = args.tun_ipv4 {
        config.tun.ipv4 = tun_ipv4;
    }
    if let Some(tun_ipv6) = args.tun_ipv6 {
        config.tun.ipv6 = Some(tun_ipv6);
    }
    if let Some(tun_mtu) = args.tun_mtu {
        config.tun.mtu = tun_mtu;
    }
    if let Some(tun_wintun_file) = args.tun_wintun_file {
        config.tun.wintun_file = Some(tun_wintun_file);
    }
    if args.tun_no_helper {
        config.tun.macos_helper_enabled = false;
    }
    if let Some(tun_helper_socket) = args.tun_helper_socket {
        config.tun.macos_helper_socket = tun_helper_socket;
    }
    if args.tun_helper_no_fallback {
        config.tun.macos_helper_fallback_to_privilege = false;
    }

    // 如有需要，创建日志目录
    if let Some(ref log_dir) = config.log_dir {
        std::fs::create_dir_all(log_dir)?;
    }

    let _log_guard = telemetry::init_tracing(
        config.log_dir.as_deref(),
        &config.log_file,
        &config.log_level,
    );

    // 构建 Tokio 运行时，线程数可配置
    let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
    // TUN/netstack 与大量中继任务会形成较深 async 栈，栈大小由配置控制。
    runtime_builder.thread_stack_size(config.async_runtime_stack_size_mb * 1024 * 1024);
    runtime_builder.enable_all();
    if let Some(threads) = config.runtime_threads {
        info!("配置 Tokio 运行时工作线程数：{}", threads);
        runtime_builder.worker_threads(threads);
    }
    let runtime = runtime_builder.build()?;

    runtime.block_on(async move {
        info!("PPAASS Desktop Agent 启动中");
        info!("监听地址：    {}", config.listen_addr);
        info!("代理地址列表：[{}]", config.proxy_addrs.join(", "));
        info!("用户名：      {}", config.username);
        info!("压缩模式：    {}", config.get_compression_mode());
        info!("日志级别：    {}", config.log_level);
        info!(
            "日志目录：    {}",
            config.log_dir.as_deref().unwrap_or("仅标准输出")
        );
        if config.tun.enabled {
            info!(
                "TUN 模式已启用：设备={} ipv4={} mtu={}",
                config.tun.name, config.tun.ipv4, config.tun.mtu
            );
        }

        let shutdown = CancellationToken::new();
        // 关闭信号只触发取消，真正的资源清理由各任务在收到 token 后完成。
        setup_shutdown_signals(&shutdown);

        match AgentServer::new(config).await {
            Ok(server) => {
                // AgentServer::run 会根据模式启动 SOCKS/HTTP 或 TUN 转发器。
                if let Err(err) = server.run(shutdown).await {
                    error!("Agent 服务器异常停止：{}", err);
                    return Err::<(), anyhow::Error>(err.into());
                }
                info!("Agent 服务器已停止");
                Ok(())
            }
            Err(err) => {
                error!("Agent 服务器初始化失败：{}", err);
                Err(err.into())
            }
        }
    })
}

fn setup_shutdown_signals(shutdown: &CancellationToken) {
    let shutdown_for_ctrl_c = shutdown.clone();
    tokio::spawn(async move {
        if let Err(err) = tokio::signal::ctrl_c().await {
            error!("安装 Ctrl-C 信号处理器失败：{err}");
            return;
        }
        info!("收到 Ctrl-C，正在请求关闭");
        shutdown_for_ctrl_c.cancel();
    });

    #[cfg(unix)]
    {
        setup_unix_shutdown_signal(
            shutdown,
            tokio::signal::unix::SignalKind::terminate(),
            "SIGTERM",
        );
        setup_unix_shutdown_signal(
            shutdown,
            tokio::signal::unix::SignalKind::hangup(),
            "SIGHUP",
        );
        setup_unix_shutdown_signal(shutdown, tokio::signal::unix::SignalKind::quit(), "SIGQUIT");
    }
}

#[cfg(unix)]
fn setup_unix_shutdown_signal(
    shutdown: &CancellationToken,
    kind: tokio::signal::unix::SignalKind,
    name: &'static str,
) {
    let mut signal = match tokio::signal::unix::signal(kind) {
        Ok(signal) => signal,
        Err(err) => {
            error!("安装 {name} 信号处理器失败：{err}");
            return;
        }
    };
    let shutdown = shutdown.clone();
    tokio::spawn(async move {
        signal.recv().await;
        info!("收到 {name}，正在请求关闭");
        shutdown.cancel();
    });
}
