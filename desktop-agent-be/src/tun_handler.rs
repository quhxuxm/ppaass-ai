//! TUN 模式转发器。
//!
//! 当 TUN 模式启用时，agent 会打开一个 TUN 设备，并使用
//! [`netstack-smoltcp`](https://crates.io/crates/netstack-smoltcp) 在其上构建
//! 用户空间 TCP/IP 协议栈。协议栈接受的 TCP/UDP 流会通过各自的
//! [`ConnectionPool`] 转发到代理，复用 SOCKS5/HTTP 处理器所使用的相同协议。
//! 匹配 `direct_access` 规则的目标将直连，不经过代理。

mod dns;
mod dns_proxy;
#[cfg(target_os = "macos")]
#[allow(dead_code)]
pub(crate) mod helper_service;
mod network;
mod route;
mod tasks;
mod tcp;
mod udp;
mod udp_relay;

use crate::config::TunConfig;
use crate::connection_pool::ConnectionPool;
use crate::direct_access::DirectAccessChecker;
use crate::error::{AgentError, Result};
use crate::privilege::ensure_tun_privileges_or_relaunch;
#[cfg(target_os = "macos")]
use crate::tun_helper_client::{HelperTunLease, start_tun as start_tun_via_helper};
use common::{install_known_smoltcp_panic_hook, panic_payload_message, spawn_guarded};
use dns::DnsGuard;
use futures::FutureExt;
use netstack_smoltcp::StackBuilder;
use network::{TunNetworks, parse_cidr_v4, parse_cidr_v6};
use route::{RouteGuard, cleanup_stale_routes, detect_proxy_route, resolve_proxy_ips};
use std::panic::AssertUnwindSafe;
#[cfg(windows)]
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tasks::{spawn_packet_bridge, spawn_tcp_listener, spawn_udp_sessions};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, instrument, warn};
use tun_rs::DeviceBuilder;

const PROXY_ROUTE_DETECT_MAX_WAIT: Duration = Duration::from_secs(60);
const PROXY_ROUTE_DETECT_RETRY_DELAY: Duration = Duration::from_secs(2);

#[derive(Clone)]
struct TunForwardContext {
    tcp_pool: Arc<ConnectionPool>,
    udp_pool: Arc<ConnectionPool>,
    direct_checker: Arc<DirectAccessChecker>,
    tun_networks: TunNetworks,
    proxy_dns: bool,
    direct_bind_interface: Option<common::BindInterface>,
}

/// 公开入口：构建 TUN 设备，连接到 netstack，运行转发循环直到 `shutdown` 触发。
#[instrument(skip(tcp_pool, udp_pool, direct_access_checker, shutdown))]
pub async fn run_tun_mode(
    config: TunConfig,
    proxy_addrs: Vec<String>,
    tcp_pool: Arc<ConnectionPool>,
    udp_pool: Arc<ConnectionPool>,
    direct_access_checker: Arc<DirectAccessChecker>,
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
    let block_quic = config.block_quic;
    if block_quic {
        info!("TUN UDP/443 QUIC 流量将被阻断，浏览器会回退到 TCP/TLS");
    }

    // 先解析 TUN 网段，后续会用它识别异常回环目标。
    let (ipv4, ipv4_prefix) = parse_cidr_v4(&config.ipv4)?;
    let ipv6_config = config.ipv6.as_deref().map(parse_cidr_v6).transpose()?;
    let tun_networks = TunNetworks::new(ipv4, ipv4_prefix, ipv6_config);

    // 在劫持默认路由前配置 proxy 连接绕行，否则 agent 到 proxy 也会进 TUN。
    let proxy_bind_interface =
        configure_proxy_routing(&config, &proxy_addrs, &tcp_pool, &udp_pool, &shutdown).await;

    // TUN 设备创建完成后才能拿到真实设备名和 if_index。
    let CreatedTunDevice {
        device,
        name: tun_name,
        if_index: tun_if_index,
        system_guard,
    } = create_tun_device(
        &config,
        ipv4,
        ipv4_prefix,
        ipv6_config,
        &proxy_addrs,
        proxy_bind_interface.as_ref(),
    )?;
    let helper_managed_network = system_guard.is_some();
    let device = Arc::new(device);
    info!(
        "TUN 设备已创建：名称={} if_index={} helper_managed={}",
        tun_name, tun_if_index, helper_managed_network
    );

    let forward_context = TunForwardContext {
        tcp_pool: tcp_pool.clone(),
        udp_pool: udp_pool.clone(),
        direct_checker: direct_access_checker.clone(),
        tun_networks,
        proxy_dns,
        direct_bind_interface: proxy_bind_interface.clone(),
    };
    let netstack_task = spawn_netstack_supervisor(
        device.clone(),
        config.mtu as usize,
        forward_context,
        block_quic,
        shutdown.clone(),
    )?;
    let route_guard = if helper_managed_network {
        None
    } else {
        install_route_guard(&config, ipv4, ipv4_prefix, tun_if_index, &proxy_addrs)
    };
    if !helper_managed_network {
        cleanup_stale_dns(config.dns_state_file.as_deref());
    }

    // 路由已就绪后再预热代理连接池。否则 VMware、旧 TUN 路由或 split-default
    // 已存在时，绑定到物理接口的 Yamux 连接可能在启动早期得到 No route to host。
    tcp_pool.prewarm().await;
    udp_pool.prewarm().await;

    shutdown.cancelled().await;
    info!("收到 TUN 模式关闭请求");

    // 先恢复系统网络状态，再等待内部任务退出。否则任一任务卡住都会延迟路由恢复。
    tcp_pool.set_proxy_bind_ip(None);
    tcp_pool.set_proxy_bind_interface(None);
    udp_pool.set_proxy_bind_ip(None);
    udp_pool.set_proxy_bind_interface(None);
    drop(route_guard);
    #[cfg(target_os = "macos")]
    drop(system_guard);
    #[cfg(not(target_os = "macos"))]
    let _ = system_guard;

    let _ = tokio::join!(wait_tun_task("netstack_supervisor", netstack_task),);

    info!("TUN 模式转发器已停止");
    Ok(())
}

fn cleanup_stale_dns(dns_state_file: Option<&str>) {
    // Current TUN mode never changes system DNS. This only restores DNS records
    // left behind by older builds that did temporarily rewrite system DNS.
    debug!("TUN 模式不会修改系统 DNS；仅检查并恢复旧版本遗留的 DNS 状态");
    let _ = DnsGuard::install(
        false,
        None,
        0,
        std::net::Ipv4Addr::UNSPECIFIED,
        dns_state_file,
    );
}

struct NetstackGeneration {
    id: u64,
    shutdown: CancellationToken,
    runner: JoinHandle<NetstackRunnerExit>,
    tun_to_stack: JoinHandle<()>,
    stack_to_tun: JoinHandle<()>,
    tcp_task: JoinHandle<()>,
    udp_task: JoinHandle<()>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum NetstackTaskKind {
    Runner,
    TunToStack,
    StackToTun,
    TcpListener,
    UdpSessions,
}

enum NetstackRunnerExit {
    Finished,
    Error(String),
    Panic(String),
}

fn spawn_netstack_supervisor(
    device: Arc<tun_rs::AsyncDevice>,
    mtu: usize,
    context: TunForwardContext,
    block_quic: bool,
    shutdown: CancellationToken,
) -> Result<JoinHandle<()>> {
    install_known_smoltcp_panic_hook();
    let initial = start_netstack_generation(
        0,
        device.clone(),
        mtu,
        context.clone(),
        block_quic,
        &shutdown,
    )?;

    Ok(spawn_guarded("desktop netstack supervisor", async move {
        run_netstack_supervisor(device, mtu, context, block_quic, shutdown, initial).await;
    }))
}

fn start_netstack_generation(
    id: u64,
    device: Arc<tun_rs::AsyncDevice>,
    mtu: usize,
    context: TunForwardContext,
    block_quic: bool,
    parent_shutdown: &CancellationToken,
) -> Result<NetstackGeneration> {
    let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .enable_icmp(true)
        .mtu(mtu)
        .build()
        .map_err(|e| AgentError::Connection(format!("构建 netstack 失败：{e}")))?;
    let runner = runner.ok_or_else(|| AgentError::Connection("netstack runner 不可用".into()))?;
    let tcp_listener =
        tcp_listener.ok_or_else(|| AgentError::Connection("netstack TCP 监听器不可用".into()))?;
    let udp_socket =
        udp_socket.ok_or_else(|| AgentError::Connection("netstack UDP 套接字不可用".into()))?;

    let generation_shutdown = parent_shutdown.child_token();
    let (tun_to_stack, stack_to_tun) =
        spawn_packet_bridge(device, stack, mtu, generation_shutdown.clone());
    let tcp_task = spawn_tcp_listener(tcp_listener, context.clone(), generation_shutdown.clone());
    let udp_task = spawn_udp_sessions(udp_socket, context, block_quic, generation_shutdown.clone());

    Ok(NetstackGeneration {
        id,
        shutdown: generation_shutdown,
        runner: spawn_netstack_runner(runner),
        tun_to_stack,
        stack_to_tun,
        tcp_task,
        udp_task,
    })
}

async fn run_netstack_supervisor(
    device: Arc<tun_rs::AsyncDevice>,
    mtu: usize,
    context: TunForwardContext,
    block_quic: bool,
    shutdown: CancellationToken,
    mut generation: NetstackGeneration,
) {
    let mut next_generation_id = generation.id + 1;
    let mut restart_delay = Duration::from_millis(200);

    loop {
        let stopped_task = tokio::select! {
            _ = shutdown.cancelled() => {
                None
            }
            result = &mut generation.runner => {
                match result {
                    Ok(NetstackRunnerExit::Finished) => warn!("netstack runner generation={} 已退出，准备重建 netstack", generation.id),
                    Ok(NetstackRunnerExit::Error(err)) => warn!("netstack runner generation={} 错误退出：{err}，准备重建 netstack", generation.id),
                    Ok(NetstackRunnerExit::Panic(message)) => warn!("netstack runner generation={} panic：{message}，准备重建 netstack", generation.id),
                    Err(err) => warn!("netstack runner generation={} join 错误：{err}，准备重建 netstack", generation.id),
                }
                Some(NetstackTaskKind::Runner)
            }
            result = &mut generation.tun_to_stack => {
                log_netstack_task_exit("tun_to_stack", generation.id, result);
                Some(NetstackTaskKind::TunToStack)
            }
            result = &mut generation.stack_to_tun => {
                log_netstack_task_exit("stack_to_tun", generation.id, result);
                Some(NetstackTaskKind::StackToTun)
            }
            result = &mut generation.tcp_task => {
                log_netstack_task_exit("tcp_task", generation.id, result);
                Some(NetstackTaskKind::TcpListener)
            }
            result = &mut generation.udp_task => {
                log_netstack_task_exit("udp_task", generation.id, result);
                Some(NetstackTaskKind::UdpSessions)
            }
        };

        let Some(stopped_task) = stopped_task else {
            stop_netstack_generation(generation, None).await;
            break;
        };

        stop_netstack_generation(generation, Some(stopped_task)).await;
        if shutdown.is_cancelled() {
            break;
        }

        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(restart_delay) => {}
        }
        if shutdown.is_cancelled() {
            break;
        }

        loop {
            match start_netstack_generation(
                next_generation_id,
                device.clone(),
                mtu,
                context.clone(),
                block_quic,
                &shutdown,
            ) {
                Ok(next) => {
                    info!("netstack 已重建：generation={}", next_generation_id);
                    generation = next;
                    next_generation_id += 1;
                    restart_delay = Duration::from_millis(200);
                    break;
                }
                Err(err) => {
                    warn!("重建 netstack 失败：{err}");
                    restart_delay = (restart_delay * 2).min(Duration::from_secs(5));
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = tokio::time::sleep(restart_delay) => {}
                    }
                }
            }
        }
    }

    debug!("netstack supervisor 退出");
}

fn spawn_netstack_runner(runner: netstack_smoltcp::Runner) -> JoinHandle<NetstackRunnerExit> {
    tokio::spawn(async move {
        match AssertUnwindSafe(runner).catch_unwind().await {
            Ok(Ok(())) => NetstackRunnerExit::Finished,
            Ok(Err(e)) => NetstackRunnerExit::Error(e.to_string()),
            Err(payload) => NetstackRunnerExit::Panic(panic_payload_message(payload.as_ref())),
        }
    })
}

fn log_netstack_task_exit(
    task_name: &'static str,
    generation: u64,
    result: std::result::Result<(), tokio::task::JoinError>,
) {
    match result {
        Ok(()) => warn!("netstack {task_name} generation={generation} 已退出，准备重建 netstack"),
        Err(err) => warn!(
            "netstack {task_name} generation={generation} join 错误：{err}，准备重建 netstack"
        ),
    }
}

async fn stop_netstack_generation(
    generation: NetstackGeneration,
    completed: Option<NetstackTaskKind>,
) {
    generation.shutdown.cancel();

    if completed != Some(NetstackTaskKind::Runner) {
        abort_generation_task("netstack_runner", generation.runner).await;
    }
    if completed != Some(NetstackTaskKind::TunToStack) {
        abort_generation_task("tun_to_stack", generation.tun_to_stack).await;
    }
    if completed != Some(NetstackTaskKind::StackToTun) {
        abort_generation_task("stack_to_tun", generation.stack_to_tun).await;
    }
    if completed != Some(NetstackTaskKind::TcpListener) {
        abort_generation_task("tcp_task", generation.tcp_task).await;
    }
    if completed != Some(NetstackTaskKind::UdpSessions) {
        abort_generation_task("udp_task", generation.udp_task).await;
    }
}

async fn abort_generation_task<T>(name: &'static str, handle: JoinHandle<T>)
where
    T: Send + 'static,
{
    handle.abort();
    match handle.await {
        Ok(_) => {}
        Err(err) if err.is_cancelled() => {}
        Err(err) => warn!("中止 netstack generation 任务 {name} 时出现 join 错误：{err}"),
    }
}

async fn wait_tun_task(name: &'static str, mut handle: JoinHandle<()>) {
    tokio::select! {
        result = &mut handle => {
            if let Err(e) = result {
                warn!("TUN 任务 {name} 异常结束：{e}");
            }
        }
        _ = tokio::time::sleep(Duration::from_secs(3)) => {
            warn!("TUN 任务 {name} 未及时退出，正在中止任务");
            handle.abort();
            let _ = handle.await;
        }
    }
}

fn tun_ipv4_peer(ipv4: std::net::Ipv4Addr, ipv4_prefix: u8) -> Option<std::net::Ipv4Addr> {
    // Host stacks treat the TUN adapter address itself as local, so DNS queries sent
    // to that IP can be consumed by the host instead of entering the TUN device.
    // Pick another usable address in the same TUN subnet so packets reach netstack.
    if ipv4_prefix >= 31 {
        return None;
    }

    let mask = if ipv4_prefix == 0 {
        0
    } else {
        u32::MAX << (32 - ipv4_prefix)
    };
    let network = u32::from(ipv4) & mask;
    let broadcast = network | !mask;
    let local = u32::from(ipv4);

    let candidates = [
        network.saturating_add(1),
        network.saturating_add(2),
        network.saturating_add(3),
    ];
    for candidate in candidates {
        if candidate != network && candidate != broadcast && candidate != local {
            return Some(std::net::Ipv4Addr::from(candidate));
        }
    }

    None
}

#[cfg(target_os = "macos")]
fn tun_ipv4_destination(ipv4: std::net::Ipv4Addr, ipv4_prefix: u8) -> Option<std::net::Ipv4Addr> {
    tun_ipv4_peer(ipv4, ipv4_prefix)
}

#[cfg(not(target_os = "macos"))]
fn tun_ipv4_destination(_ipv4: std::net::Ipv4Addr, _ipv4_prefix: u8) -> Option<std::net::Ipv4Addr> {
    None
}

#[cfg(target_os = "macos")]
fn tun_ipv4_interface_prefix(_configured_prefix: u8) -> u8 {
    // macOS utun is point-to-point. Keep the configured CIDR for routing policy
    // and virtual peer selection, but install the interface address as a host
    // route so packets are delivered through the utun control socket.
    32
}

#[cfg(not(target_os = "macos"))]
fn tun_ipv4_interface_prefix(configured_prefix: u8) -> u8 {
    configured_prefix
}

struct CreatedTunDevice {
    device: tun_rs::AsyncDevice,
    name: String,
    if_index: u32,
    system_guard: Option<TunSystemGuard>,
}

enum TunSystemGuard {
    #[cfg(target_os = "macos")]
    #[allow(dead_code)]
    Helper(HelperTunLease),
}

fn create_tun_device(
    config: &TunConfig,
    ipv4: std::net::Ipv4Addr,
    ipv4_prefix: u8,
    ipv6_config: Option<(std::net::Ipv6Addr, u8)>,
    _proxy_addrs: &[String],
    _proxy_bind_interface: Option<&common::BindInterface>,
) -> Result<CreatedTunDevice> {
    #[cfg(target_os = "macos")]
    if config.macos_helper_enabled {
        match start_tun_via_helper(config, _proxy_addrs, _proxy_bind_interface) {
            Ok(helper_device) => {
                info!(
                    "已通过 TUN helper 创建设备：name={} if_index={}",
                    helper_device.name, helper_device.if_index
                );
                return Ok(CreatedTunDevice {
                    device: helper_device.device,
                    name: helper_device.name,
                    if_index: helper_device.if_index,
                    system_guard: Some(TunSystemGuard::Helper(helper_device.lease)),
                });
            }
            Err(err) if config.macos_helper_fallback_to_privilege => {
                warn!("TUN helper 不可用，将回退到旧的整进程提权路径：{}", err);
            }
            Err(err) => return Err(err),
        }
    }

    create_tun_device_legacy(config, ipv4, ipv4_prefix, ipv6_config)
}

fn create_tun_device_legacy(
    config: &TunConfig,
    ipv4: std::net::Ipv4Addr,
    ipv4_prefix: u8,
    ipv6_config: Option<(std::net::Ipv6Addr, u8)>,
) -> Result<CreatedTunDevice> {
    cleanup_stale_routes(config.route_state_file.as_deref());
    ensure_tun_privileges_or_relaunch()?;

    // DeviceBuilder 负责设置地址、MTU 和平台相关参数。
    let mut builder = DeviceBuilder::new()
        .name(&config.name)
        .mtu(config.mtu)
        .ipv4(
            ipv4,
            tun_ipv4_interface_prefix(ipv4_prefix),
            tun_ipv4_destination(ipv4, ipv4_prefix),
        );
    #[cfg(target_os = "macos")]
    {
        // We manage split-default and proxy bypass routes ourselves. tun-rs' macOS
        // associated route points the TUN subnet at the adapter address, which can
        // steal packets for the virtual peer/DNS address before they reach utun.
        builder = builder.associate_route(false);
    }
    if let Some((ipv6, ipv6_prefix)) = ipv6_config {
        builder = builder.ipv6(ipv6, ipv6_prefix);
    }

    let device = build_tun_device(builder, config)?;
    let name = device
        .name()
        .map_err(|e| AgentError::Connection(format!("读取 TUN 设备名失败：{e}")))?;
    let if_index = device
        .if_index()
        .map_err(|e| AgentError::Connection(format!("读取 TUN if_index 失败：{e}")))?;

    Ok(CreatedTunDevice {
        device,
        name,
        if_index,
        system_guard: None,
    })
}

#[cfg(windows)]
fn build_tun_device(builder: DeviceBuilder, config: &TunConfig) -> Result<tun_rs::AsyncDevice> {
    // Windows 必须显式找到 wintun.dll。
    let wintun_file = resolve_wintun_file(config)?;
    info!("使用 Windows TUN 运行库：{}", wintun_file.display());
    builder
        .wintun_file(wintun_file.to_string_lossy().into_owned())
        .build_async()
        .map_err(|e| windows_tun_create_error(e, &wintun_file))
}

#[cfg(not(windows))]
fn build_tun_device(builder: DeviceBuilder, _config: &TunConfig) -> Result<tun_rs::AsyncDevice> {
    // 非 Windows 平台由 tun-rs 直接创建系统 TUN 设备。
    builder
        .build_async()
        .map_err(|e| AgentError::Connection(format!("创建 TUN 设备失败：{e}")))
}

#[cfg(windows)]
fn resolve_wintun_file(config: &TunConfig) -> Result<PathBuf> {
    // 用户显式配置时只接受该路径，避免误用 PATH 中的其他 DLL。
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

    // 未配置时按 desktop-agent.exe 目录、当前目录、PATH 顺序搜索。
    let candidates = default_wintun_candidates();
    if let Some(path) = candidates.iter().find(|path| path.is_file()) {
        return Ok(path.clone());
    }

    Err(missing_wintun_error(&candidates, false))
}

#[cfg(windows)]
fn absolute_wintun_path(path: &Path) -> PathBuf {
    // 相对路径按当前工作目录解析，便于配置文件本地部署。
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

    // desktop-agent.exe 同目录优先，最符合随二进制打包的部署方式。
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        push_wintun_candidate(&mut candidates, dir.join("wintun.dll"));
    }

    if let Ok(cwd) = std::env::current_dir() {
        push_wintun_candidate(&mut candidates, cwd.join("wintun.dll"));
    }

    // 最后才遍历 PATH，避免意外加载其他软件携带的 wintun.dll。
    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            push_wintun_candidate(&mut candidates, dir.join("wintun.dll"));
        }
    }

    candidates
}

#[cfg(windows)]
fn push_wintun_candidate(candidates: &mut Vec<PathBuf>, path: PathBuf) {
    // 搜索路径可能重复，去重后错误信息更清楚。
    if !candidates.iter().any(|candidate| candidate == &path) {
        candidates.push(path);
    }
}

#[cfg(windows)]
fn missing_wintun_error(candidates: &[PathBuf], explicit: bool) -> AgentError {
    // 错误信息保留已检查路径和进程架构，方便用户定位 DLL 放置/架构问题。
    let checked = format_wintun_candidates(candidates);
    let reason = if explicit {
        "配置的 wintun_file 不存在"
    } else {
        "未找到 Windows TUN 运行库 wintun.dll"
    };

    AgentError::Connection(format!(
        "创建 TUN 设备失败：{reason}。TUN 模式需要与 desktop-agent.exe 同架构的 wintun.dll（当前进程架构：{}）。\
         请从 https://www.wintun.net/ 下载对应架构的 DLL，放到 desktop-agent.exe 同目录，或在 [tun] 中设置 wintun_file。\
         已检查：{}",
        windows_arch_label(),
        checked
    ))
}

#[cfg(windows)]
fn windows_tun_create_error(error: std::io::Error, wintun_file: &Path) -> AgentError {
    // os error 5 单独提示管理员权限和适配器占用，这是 Windows 下最常见失败。
    let hint = if error.raw_os_error() == Some(5) {
        "Windows 返回拒绝访问。请确认当前进程是 elevated 管理员令牌；如果已经提权，检查是否有同名 Wintun 适配器被其他进程占用，或安全策略拦截驱动安装/打开。"
    } else {
        "如果 DLL 存在但仍加载失败，请确认它与 desktop-agent.exe 架构一致，并以管理员身份运行。"
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
    // PATH 可能很长，错误信息只展示前几个候选并汇总剩余数量。
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
    tcp_pool: &ConnectionPool,
    udp_pool: &ConnectionPool,
    shutdown: &CancellationToken,
) -> Option<common::BindInterface> {
    // 通过 OS 路由决策探测物理出口 IP/接口，用于后续 proxy 连接 bind。
    // macOS 登录项开机自启时，默认路由和网络服务常常晚于进程启动才可用。
    let started = Instant::now();
    let mut attempts = 0usize;
    let mut last_partial_route = None;
    let proxy_route = loop {
        attempts += 1;
        match detect_proxy_route(proxy_addrs) {
            Some(route) if proxy_route_has_interface(&route) => break Some(route),
            Some(route) => {
                debug!(
                    "已检测到物理出口 IP={}，但出口接口尚不可用；等待系统网络就绪",
                    route.local_ip
                );
                last_partial_route = Some(route);
            }
            None => {
                debug!("尚未检测到物理出口；等待系统网络就绪");
            }
        }

        let elapsed = started.elapsed();
        if elapsed >= PROXY_ROUTE_DETECT_MAX_WAIT {
            if let Some(route) = last_partial_route {
                warn!(
                    "等待物理出口接口超时（尝试 {} 次，用时 {:?}）；退化为仅绑定出口 IP={}，\
                     代理连接仍可能受当前系统路由影响",
                    attempts, elapsed, route.local_ip
                );
                break Some(route);
            }
            break None;
        }

        let delay = PROXY_ROUTE_DETECT_RETRY_DELAY.min(PROXY_ROUTE_DETECT_MAX_WAIT - elapsed);
        tokio::select! {
            _ = shutdown.cancelled() => break None,
            _ = tokio::time::sleep(delay) => {}
        }
    };

    let mut bind_interface = None;
    if let Some(route) = proxy_route {
        bind_interface = route.bind_interface.clone();
        info!(
            "检测到物理出口：ip={} interface={:?}；代理连接将绑定到该出口（尝试 {} 次，用时 {:?}）",
            route.local_ip,
            route.bind_interface,
            attempts,
            started.elapsed()
        );
        tcp_pool.set_proxy_bind_ip(Some(route.local_ip));
        tcp_pool.set_proxy_bind_interface(route.bind_interface.clone());
        udp_pool.set_proxy_bind_ip(Some(route.local_ip));
        udp_pool.set_proxy_bind_interface(route.bind_interface);
    } else {
        warn!(
            "无法检测物理出口 IP — 代理连接可能会回环进入 TUN。\
             请确保启动 TUN 模式前代理服务器可达。"
        );
        tcp_pool.set_proxy_bind_ip(None);
        tcp_pool.set_proxy_bind_interface(None);
        udp_pool.set_proxy_bind_ip(None);
        udp_pool.set_proxy_bind_interface(None);
    }

    debug!(
        "TUN 路由预配置完成：设备={} ipv4={} mtu={}",
        config.name, config.ipv4, config.mtu
    );

    bind_interface
}

fn proxy_route_has_interface(route: &route::ProxyRoute) -> bool {
    route
        .bind_interface
        .as_ref()
        .is_some_and(bind_interface_is_usable)
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "fuchsia"))]
fn bind_interface_is_usable(interface: &common::BindInterface) -> bool {
    interface.name.is_some()
}

#[cfg(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
    windows,
))]
fn bind_interface_is_usable(interface: &common::BindInterface) -> bool {
    interface.index.is_some()
}

#[cfg(not(any(
    target_os = "android",
    target_os = "fuchsia",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
    windows,
)))]
fn bind_interface_is_usable(interface: &common::BindInterface) -> bool {
    interface.name.is_some() || interface.index.is_some()
}

fn install_route_guard(
    config: &TunConfig,
    tun_ipv4: std::net::Ipv4Addr,
    tun_ipv4_prefix: u8,
    tun_if_index: u32,
    proxy_addrs: &[String],
) -> Option<RouteGuard> {
    // 解析 proxy IP 后安装旁路和 split-default 路由；失败时继续运行但不接管全局路由。
    let proxy_ips = resolve_proxy_ips(proxy_addrs);
    let dns_capture_target = tun_ipv4_peer(tun_ipv4, tun_ipv4_prefix).unwrap_or(tun_ipv4);
    match RouteGuard::install(
        tun_if_index,
        tun_ipv4,
        dns_capture_target,
        config.ipv6.as_deref(),
        config.route_state_file.as_deref(),
        &proxy_ips,
        config.proxy_dns,
    ) {
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

#[cfg(test)]
mod tests {
    #[cfg(target_os = "macos")]
    use super::tun_ipv4_destination;
    #[cfg(target_os = "macos")]
    use super::tun_ipv4_interface_prefix;
    use std::net::Ipv4Addr;

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_tun_destination_uses_virtual_peer() {
        assert_eq!(
            tun_ipv4_destination(Ipv4Addr::new(10, 10, 10, 1), 24),
            Some(Ipv4Addr::new(10, 10, 10, 2))
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_tun_interface_uses_host_prefix() {
        assert_eq!(tun_ipv4_interface_prefix(24), 32);
    }
}
