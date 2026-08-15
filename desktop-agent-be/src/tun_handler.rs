//! TUN 模式转发器。
//!
//! 当 TUN 模式启用时，agent 会打开一个 TUN 设备，并使用
//! [`netstack-smoltcp`](https://crates.io/crates/netstack-smoltcp) 在其上构建
//! 用户空间 TCP/IP 协议栈。协议栈接受的 TCP/UDP 流会按配置选择
//! agent 本地直连，或通过 [`YamuxSessionManager`] 转发到 proxy。
//! `direct_access` 规则与 TUN UDP 的 `proxy_udp` 开关共同决定具体路径。

pub mod device;
pub mod direct_domain_cache;
pub mod direct_egress;
pub mod dns;
pub mod dns_proxy;
#[cfg(target_os = "macos")]
#[allow(dead_code)]
pub mod helper_service;
mod netstack;
pub mod network;
pub mod packet_capture;
pub(crate) use packet_capture::CapturedTcpStream;
pub use packet_capture::PacketCaptureController;
pub mod proxy_routing;
pub mod route;
pub mod tasks;
mod tcp;
pub use tcp::{proxy_target_address, tls_client_hello_server_name};
mod udp;
pub mod udp_relay;
mod udp_writer;

use crate::config::TunConfig;
use crate::direct_access::DirectAccessChecker;
use crate::error::{AgentError, Result};
use crate::privilege::ensure_tun_privileges_or_relaunch;
#[cfg(target_os = "macos")]
use crate::tun_helper_client::{HelperTunLease, start_tun as start_tun_via_helper};
use crate::yamux_session::YamuxSessionManager;
use common::{
    TransportMode, install_known_smoltcp_panic_hook, panic_payload_message, spawn_guarded,
};
use device::{CreatedTunDevice, create_tun_device};
use direct_domain_cache::DirectDomainCache;
use direct_egress::TunDirectEgress;
use dns::warn_legacy_dns_state;
use futures::FutureExt;
use netstack::{spawn_netstack_supervisor, wait_tun_task};
use netstack_smoltcp::StackBuilder;
use network::{TunNetworks, parse_cidr_v4, parse_cidr_v6};
use proxy_routing::{ProxySessionBindGuard, configure_proxy_routing, install_route_guard};
use route::{RouteGuard, cleanup_stale_routes, detect_proxy_route};
use std::panic::AssertUnwindSafe;
#[cfg(windows)]
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tasks::{spawn_packet_bridge, spawn_tcp_listener, spawn_udp_sessions};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, instrument, warn};
use tun_rs::DeviceBuilder;

const PROXY_ROUTE_DETECT_MAX_WAIT: Duration = Duration::from_secs(60);
const PROXY_ROUTE_DETECT_RETRY_DELAY: Duration = Duration::from_secs(2);
const DIRECT_EGRESS_REFRESH_COOLDOWN: Duration = Duration::from_secs(2);

pub(crate) struct TunModeResources {
    pub(crate) tcp_sessions: Arc<YamuxSessionManager>,
    pub(crate) udp_sessions: Arc<YamuxSessionManager>,
    pub(crate) direct_access_checker: Arc<DirectAccessChecker>,
    pub(crate) packet_capture: PacketCaptureController,
}

#[derive(Clone)]
struct TunForwardContext {
    // TCP/UDP 两类 proxy Yamux session 管理器分开，避免 UDP 高并发挤占 TCP session。
    tcp_sessions: Arc<YamuxSessionManager>,
    udp_sessions: Arc<YamuxSessionManager>,
    // TUN TCP/UDP 都会复用同一套直连规则。
    direct_checker: Arc<DirectAccessChecker>,
    // DNS proxy 会记录域名解析结果，TCP/UDP 后续可用 IP -> 域名映射命中直连规则。
    direct_domain_cache: Arc<DirectDomainCache>,
    tun_networks: TunNetworks,
    // true 时，系统 DNS 请求会被映射成 proxy 端 DNS 虚拟目标。
    proxy_dns: bool,
    // true 保持普通 UDP 原有路由语义；false 时除代理 DNS 与 QUIC 外均从 agent 直连。
    // UDP/443 QUIC 由 quic_policy 与 direct_access 独立决定。
    proxy_udp: bool,
    // 直连路径的物理出口绑定信息，可在失败后刷新。
    direct_egress: Arc<TunDirectEgress>,
}

/// 公开入口：构建 TUN 设备，连接到 netstack，运行转发循环直到 `shutdown` 触发。
#[instrument(skip(config, proxy_addrs, resources, shutdown))]
pub(crate) async fn run_tun_mode(
    config: TunConfig,
    transport_mode: TransportMode,
    proxy_addrs: Vec<String>,
    resources: TunModeResources,
    shutdown: CancellationToken,
) -> Result<()> {
    let TunModeResources {
        tcp_sessions,
        udp_sessions,
        direct_access_checker,
        packet_capture,
    } = resources;
    let native_udp = transport_mode.uses_native_udp_for(protocol::TransportProtocol::Udp);
    info!(
        "启动 TUN 模式转发器：设备={} ipv4={} ipv6={:?} mtu={}",
        config.name, config.ipv4, config.ipv6, config.mtu
    );
    let proxy_dns = config.proxy_dns;
    if proxy_dns {
        info!("TUN DNS 请求将交给 proxy 端默认 DNS 处理");
    }
    let proxy_udp = config.proxy_udp;
    info!(
        "TUN 普通 UDP（不含代理 DNS/UDP443）转发：{}",
        if proxy_udp {
            "保持原有 proxy/direct_access 路由"
        } else {
            "agent 端直连目标"
        }
    );
    let quic_policy = config.effective_quic_policy();
    info!("TUN UDP/443 QUIC 策略：{}", quic_policy.description_zh());
    if !quic_policy.should_block_udp443() {
        info!(
            "TUN UDP/443 已允许：直连规则命中时直连，否则通过 proxy 转发（UDP 传输={}）",
            if native_udp {
                "原生加密 UDP"
            } else {
                "TCP/Yamux"
            }
        );
    }

    // 先解析 TUN 网段，后续会用它识别异常回环目标。
    let (ipv4, ipv4_prefix) = parse_cidr_v4(&config.ipv4)?;
    let ipv6_config = config.ipv6.as_deref().map(parse_cidr_v6).transpose()?;
    let tun_networks = TunNetworks::new(ipv4, ipv4_prefix, ipv6_config);
    warn_legacy_dns_state(config.dns_state_file.as_deref());

    // 在劫持默认路由前配置 proxy 连接绕行，否则 agent 到 proxy 也会进 TUN。
    // 这个顺序非常关键：先固定控制连接出口，再安装 TUN/split-default 路由。
    // guard 必须先于配置绑定创建：从这里开始的取消、设备/路由/netstack
    // 初始化错误或任务 abort 都会自动恢复共享 HTTP/SOCKS manager 的普通路由。
    let proxy_session_bind_guard =
        ProxySessionBindGuard::new(tcp_sessions.clone(), udp_sessions.clone());
    // DNS 捕获规则安装后，运行期再解析 proxy 域名会形成循环依赖：proxy
    // 重连等待 DNS，而 DNS proxy 又等待 proxy 会话。必须先固定 IP endpoint。
    let resolved_proxy_addrs = route::resolve_proxy_endpoints_checked(&proxy_addrs)?;
    let (proxy_bind_interface, pinned_proxy_addrs) = configure_proxy_routing(
        &config,
        &resolved_proxy_addrs,
        &tcp_sessions,
        &udp_sessions,
        &shutdown,
    )
    .await;
    if shutdown.is_cancelled() {
        info!("TUN 模式启动过程中收到关闭请求，跳过 TUN 设备创建");
        return Ok(());
    }

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
        &pinned_proxy_addrs,
        proxy_bind_interface.as_ref(),
    )?;
    let helper_managed_network = system_guard.is_some();
    info!(
        "TUN 设备已创建：名称={} if_index={} helper_managed={}",
        tun_name, tun_if_index, helper_managed_network
    );
    info!(
        "明文抓包运行时控制已就绪：默认关闭，文件={}",
        packet_capture.file().display()
    );

    // 必要路由必须在 netstack 任务启动前安装成功。否则 TUN 设备虽然显示已启动，
    // 实际流量却没有进入 TUN，或 proxy 控制连接被 split-default 回环劫持。
    let route_guard = if helper_managed_network {
        None
    } else {
        Some(install_route_guard(
            &config,
            ipv4,
            ipv4_prefix,
            tun_if_index,
            &pinned_proxy_addrs,
        )?)
    };
    let device = Arc::new(device);
    let direct_egress = Arc::new(TunDirectEgress::new(
        pinned_proxy_addrs,
        proxy_bind_interface.clone(),
        #[cfg(target_os = "macos")]
        helper_managed_network.then(|| config.macos_helper_socket.clone()),
    ));
    let forward_context = TunForwardContext {
        tcp_sessions: tcp_sessions.clone(),
        udp_sessions: udp_sessions.clone(),
        direct_checker: direct_access_checker.clone(),
        direct_domain_cache: Arc::new(DirectDomainCache::new(Duration::from_secs(300))),
        tun_networks,
        proxy_dns,
        proxy_udp,
        direct_egress,
    };
    let netstack_task = spawn_netstack_supervisor(
        device.clone(),
        config.mtu as usize,
        forward_context,
        quic_policy,
        packet_capture,
        shutdown.clone(),
    )?;
    shutdown.cancelled().await;
    info!("收到 TUN 模式关闭请求");

    // 先恢复系统网络状态，再等待内部任务退出。否则任一任务卡住都会延迟路由恢复。
    proxy_session_bind_guard.clear();
    drop(route_guard);
    #[cfg(target_os = "macos")]
    drop(system_guard);
    #[cfg(not(target_os = "macos"))]
    let _ = system_guard;

    let _ = tokio::join!(wait_tun_task("netstack_supervisor", netstack_task),);

    info!("TUN 模式转发器已停止");
    Ok(())
}
