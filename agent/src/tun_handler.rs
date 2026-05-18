//! TUN 模式转发器。
//!
//! 当 TUN 模式启用时，agent 会打开一个 TUN 设备，并使用
//! [`netstack-smoltcp`](https://crates.io/crates/netstack-smoltcp) 在其上构建
//! 用户空间 TCP/IP 协议栈。协议栈接受的每个 TCP/UDP 流都会通过现有的
//! [`ConnectionPool`] 转发到代理，复用 SOCKS5/HTTP 处理器所使用的相同协议。
//! 匹配 `direct_access` 规则的目标将直连，不经过代理。

mod network;
mod route;
mod tasks;
mod tcp;
mod udp;

use crate::config::TunConfig;
use crate::connection_pool::ConnectionPool;
use crate::direct_access::DirectAccessChecker;
use crate::error::{AgentError, Result};
use netstack_smoltcp::StackBuilder;
use network::{TunNetworks, parse_cidr_v4, parse_cidr_v6};
use route::{RouteGuard, detect_outbound_ip, resolve_proxy_ips};
#[cfg(windows)]
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tasks::{spawn_packet_bridge, spawn_tcp_listener, spawn_udp_sessions};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, instrument, warn};
use tun_rs::DeviceBuilder;

/// 公开入口：构建 TUN 设备，连接到 netstack，运行转发循环直到 `shutdown` 触发。
#[instrument(skip(pool, direct_checker, shutdown))]
pub async fn run_tun_mode(
    config: TunConfig,
    proxy_addrs: Vec<String>,
    pool: Arc<ConnectionPool>,
    direct_checker: Arc<DirectAccessChecker>,
    shutdown: CancellationToken,
) -> Result<()> {
    info!(
        "启动 TUN 模式转发器：设备={} ipv4={} ipv6={:?} mtu={}",
        config.name, config.ipv4, config.ipv6, config.mtu
    );
    let proxy_dns = config.proxy_dns;
    if proxy_dns {
        info!("TUN DNS 请求将交给 proxy 端默认 DNS 处理");
    }

    let (ipv4, ipv4_prefix) = parse_cidr_v4(&config.ipv4)?;
    let ipv6_config = config.ipv6.as_deref().map(parse_cidr_v6).transpose()?;
    let tun_networks = TunNetworks::new(ipv4, ipv4_prefix, ipv6_config);
    let device = create_tun_device(&config, ipv4, ipv4_prefix, ipv6_config)?;
    let tun_name = device
        .name()
        .map_err(|e| AgentError::Connection(format!("读取 TUN 设备名失败：{e}")))?;
    let tun_if_index = device
        .if_index()
        .map_err(|e| AgentError::Connection(format!("读取 TUN if_index 失败：{e}")))?;
    let device = Arc::new(device);
    info!(
        "TUN 设备已创建：名称={} if_index={}",
        tun_name, tun_if_index
    );

    configure_proxy_routing(&config, &proxy_addrs, &pool).await;
    let route_guard = install_route_guard(&config, ipv4, tun_if_index, &proxy_addrs);

    let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .enable_icmp(true)
        .mtu(config.mtu as usize)
        .build()
        .map_err(|e| AgentError::Connection(format!("构建 netstack 失败：{e}")))?;
    if let Some(runner) = runner {
        tokio::spawn(runner);
    }
    let tcp_listener =
        tcp_listener.ok_or_else(|| AgentError::Connection("netstack TCP 监听器不可用".into()))?;
    let udp_socket =
        udp_socket.ok_or_else(|| AgentError::Connection("netstack UDP 套接字不可用".into()))?;

    let (tun_to_stack, stack_to_tun) =
        spawn_packet_bridge(device.clone(), stack, config.mtu as usize, shutdown.clone());
    let tcp_task = spawn_tcp_listener(
        tcp_listener,
        pool.clone(),
        direct_checker.clone(),
        tun_networks,
        proxy_dns,
        shutdown.clone(),
    );
    let udp_task = spawn_udp_sessions(
        udp_socket,
        pool.clone(),
        direct_checker.clone(),
        tun_networks,
        proxy_dns,
        shutdown.clone(),
    );

    shutdown.cancelled().await;
    info!("收到 TUN 模式关闭请求");
    let _ = tokio::join!(tun_to_stack, stack_to_tun, tcp_task, udp_task);

    pool.set_proxy_bind_ip(None);
    drop(route_guard);

    info!("TUN 模式转发器已停止");
    Ok(())
}

fn create_tun_device(
    config: &TunConfig,
    ipv4: std::net::Ipv4Addr,
    ipv4_prefix: u8,
    ipv6_config: Option<(std::net::Ipv6Addr, u8)>,
) -> Result<tun_rs::AsyncDevice> {
    let mut builder = DeviceBuilder::new()
        .name(&config.name)
        .mtu(config.mtu)
        .ipv4(ipv4, ipv4_prefix, None);
    if let Some((ipv6, ipv6_prefix)) = ipv6_config {
        builder = builder.ipv6(ipv6, ipv6_prefix);
    }

    build_tun_device(builder, config)
}

#[cfg(windows)]
fn build_tun_device(builder: DeviceBuilder, config: &TunConfig) -> Result<tun_rs::AsyncDevice> {
    let wintun_file = resolve_wintun_file(config)?;
    ensure_windows_tun_privileges()?;
    info!("使用 Windows TUN 运行库：{}", wintun_file.display());
    builder
        .wintun_file(wintun_file.to_string_lossy().into_owned())
        .build_async()
        .map_err(|e| windows_tun_create_error(e, &wintun_file))
}

#[cfg(not(windows))]
fn build_tun_device(builder: DeviceBuilder, _config: &TunConfig) -> Result<tun_rs::AsyncDevice> {
    builder
        .build_async()
        .map_err(|e| AgentError::Connection(format!("创建 TUN 设备失败：{e}")))
}

#[cfg(windows)]
fn ensure_windows_tun_privileges() -> Result<()> {
    if unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() } != 0 {
        return Ok(());
    }

    Err(AgentError::Connection(
        "创建 TUN 设备失败：当前进程没有管理员权限。Windows TUN 模式需要以管理员身份运行，\
         才能创建/打开 Wintun 适配器并修改系统路由。请右键以管理员身份打开 PowerShell/终端后启动 agent，\
         或使用 start-agent.bat 触发 UAC 提权。"
            .to_string(),
    ))
}

#[cfg(windows)]
fn resolve_wintun_file(config: &TunConfig) -> Result<PathBuf> {
    if let Some(path) = config
        .wintun_file
        .as_deref()
        .map(str::trim)
        .filter(|path| !path.is_empty())
    {
        let path = absolute_wintun_path(Path::new(path));
        if path.is_file() {
            return Ok(path);
        }
        return Err(missing_wintun_error(&[path], true));
    }

    let candidates = default_wintun_candidates();
    if let Some(path) = candidates.iter().find(|path| path.is_file()) {
        return Ok(path.clone());
    }

    Err(missing_wintun_error(&candidates, false))
}

#[cfg(windows)]
fn absolute_wintun_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }

    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(path)
}

#[cfg(windows)]
fn default_wintun_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            push_wintun_candidate(&mut candidates, dir.join("wintun.dll"));
        }
    }

    if let Ok(cwd) = std::env::current_dir() {
        push_wintun_candidate(&mut candidates, cwd.join("wintun.dll"));
    }

    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            push_wintun_candidate(&mut candidates, dir.join("wintun.dll"));
        }
    }

    candidates
}

#[cfg(windows)]
fn push_wintun_candidate(candidates: &mut Vec<PathBuf>, path: PathBuf) {
    if !candidates.iter().any(|candidate| candidate == &path) {
        candidates.push(path);
    }
}

#[cfg(windows)]
fn missing_wintun_error(candidates: &[PathBuf], explicit: bool) -> AgentError {
    let checked = format_wintun_candidates(candidates);
    let reason = if explicit {
        "配置的 wintun_file 不存在"
    } else {
        "未找到 Windows TUN 运行库 wintun.dll"
    };

    AgentError::Connection(format!(
        "创建 TUN 设备失败：{reason}。TUN 模式需要与 agent.exe 同架构的 wintun.dll（当前进程架构：{}）。\
         请从 https://www.wintun.net/ 下载对应架构的 DLL，放到 agent.exe 同目录，或在 [tun] 中设置 wintun_file。\
         已检查：{}",
        windows_arch_label(),
        checked
    ))
}

#[cfg(windows)]
fn windows_tun_create_error(error: std::io::Error, wintun_file: &Path) -> AgentError {
    let hint = if error.raw_os_error() == Some(5) {
        "Windows 返回拒绝访问。请确认当前进程是 elevated 管理员令牌；如果已经提权，检查是否有同名 Wintun 适配器被其他进程占用，或安全策略拦截驱动安装/打开。"
    } else {
        "如果 DLL 存在但仍加载失败，请确认它与 agent.exe 架构一致，并以管理员身份运行。"
    };

    AgentError::Connection(format!(
        "创建 TUN 设备失败：{error}。已使用 wintun.dll：{}。\
         {hint}（当前进程架构：{}）",
        wintun_file.display(),
        windows_arch_label()
    ))
}

#[cfg(windows)]
fn format_wintun_candidates(candidates: &[PathBuf]) -> String {
    let mut checked: Vec<String> = candidates
        .iter()
        .take(8)
        .map(|path| path.display().to_string())
        .collect();

    if candidates.len() > checked.len() {
        checked.push(format!(
            "另有 {} 个 PATH 位置",
            candidates.len() - checked.len()
        ));
    }

    if checked.is_empty() {
        "<无可用搜索路径>".to_string()
    } else {
        checked.join("; ")
    }
}

#[cfg(windows)]
fn windows_arch_label() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x64/amd64",
        "x86" => "x86",
        "aarch64" => "ARM64",
        "arm" => "ARM",
        other => other,
    }
}

async fn configure_proxy_routing(
    config: &TunConfig,
    proxy_addrs: &[String],
    pool: &ConnectionPool,
) {
    let outbound_ip = detect_outbound_ip(proxy_addrs);
    if let Some(ip) = outbound_ip {
        info!("检测到物理出口 IP：{}；代理连接将绑定到该地址", ip);
        pool.set_proxy_bind_ip(Some(ip));
    } else {
        warn!(
            "无法检测物理出口 IP — 代理连接可能会回环进入 TUN。\
             请确保启动 TUN 模式前代理服务器可达。"
        );
    }

    // 必须在设置绑定 IP 后、劫持默认路由前预热连接池。
    pool.prewarm().await;

    debug!(
        "TUN 路由预配置完成：设备={} ipv4={} mtu={}",
        config.name, config.ipv4, config.mtu
    );
}

fn install_route_guard(
    config: &TunConfig,
    tun_ipv4: std::net::Ipv4Addr,
    tun_if_index: u32,
    proxy_addrs: &[String],
) -> Option<RouteGuard> {
    let proxy_ips = resolve_proxy_ips(proxy_addrs);
    match RouteGuard::install(tun_if_index, tun_ipv4, config.ipv6.as_deref(), &proxy_ips) {
        Ok(guard) => Some(guard),
        Err(e) => {
            warn!(
                "安装 TUN 路由失败（继续运行但不劫持路由）：{e}。\
                 可能需要手动配置路由或以提升权限运行。"
            );
            None
        }
    }
}
