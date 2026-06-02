//! TUN 模式转发器。
//!
//! 当 TUN 模式启用时，agent 会打开一个 TUN 设备，并使用
//! [`netstack-smoltcp`](https://crates.io/crates/netstack-smoltcp) 在其上构建
//! 用户空间 TCP/IP 协议栈。协议栈接受的 TCP/UDP 流会通过各自的
//! [`ConnectionPool`] 转发到代理，复用 SOCKS5/HTTP 处理器所使用的相同协议。
//! 匹配 `direct_access` 规则的目标将直连，不经过代理。

mod device;
mod direct_domain_cache;
mod dns;
mod dns_proxy;
mod domain_sniff;
#[cfg(target_os = "macos")]
#[allow(dead_code)]
pub(crate) mod helper_service;
mod netstack;
mod network;
mod proxy_routing;
mod route;
mod system_dns;
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
use device::{CreatedTunDevice, create_tun_device};
use direct_domain_cache::DirectDomainCache;
use dns::DnsGuard;
use futures::FutureExt;
use netstack::{spawn_netstack_supervisor, wait_tun_task};
use netstack_smoltcp::StackBuilder;
use network::{TunNetworks, parse_cidr_v4, parse_cidr_v6};
use proxy_routing::{configure_proxy_routing, install_route_guard};
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
    direct_domain_cache: Arc<DirectDomainCache>,
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
        direct_domain_cache: Arc::new(DirectDomainCache::new(Duration::from_secs(300))),
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
