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
use crate::tun_helper_client::{
    HelperTunLease,
    refresh_macos_scoped_default_bypass as refresh_macos_scoped_default_bypass_via_helper,
    start_tun as start_tun_via_helper,
};
use common::{install_known_smoltcp_panic_hook, panic_payload_message, spawn_guarded};
use device::{CreatedTunDevice, create_tun_device};
use direct_domain_cache::DirectDomainCache;
use dns::DnsGuard;
use futures::FutureExt;
use netstack::{spawn_netstack_supervisor, wait_tun_task};
use netstack_smoltcp::StackBuilder;
use network::{TunNetworks, parse_cidr_v4, parse_cidr_v6};
use proxy_routing::{configure_proxy_routing, install_route_guard};
use route::{
    RouteGuard, cleanup_stale_routes, detect_default_route_interface, detect_proxy_route,
    refresh_macos_scoped_default_bypass as refresh_macos_scoped_default_bypass_local,
    resolve_proxy_ips,
};
use std::net::IpAddr;
use std::panic::AssertUnwindSafe;
#[cfg(windows)]
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tasks::{spawn_packet_bridge, spawn_tcp_listener, spawn_udp_sessions};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, instrument, warn};
use tun_rs::DeviceBuilder;

const PROXY_ROUTE_DETECT_MAX_WAIT: Duration = Duration::from_secs(60);
const PROXY_ROUTE_DETECT_RETRY_DELAY: Duration = Duration::from_secs(2);
const DIRECT_EGRESS_REFRESH_COOLDOWN: Duration = Duration::from_secs(2);

#[derive(Clone)]
struct TunForwardContext {
    // TCP/UDP 两类 proxy 连接池分开，避免 UDP 高并发挤占 TCP 预热连接。
    tcp_pool: Arc<ConnectionPool>,
    udp_pool: Arc<ConnectionPool>,
    // TUN TCP/UDP 都会复用同一套直连规则。
    direct_checker: Arc<DirectAccessChecker>,
    // DNS proxy 会记录域名解析结果，TCP/UDP 后续可用 IP -> 域名映射命中直连规则。
    direct_domain_cache: Arc<DirectDomainCache>,
    tun_networks: TunNetworks,
    // true 时，系统 DNS 请求会被映射成 proxy 端 DNS 虚拟目标。
    proxy_dns: bool,
    // 直连路径的物理出口绑定信息，可在失败后刷新。
    direct_egress: Arc<TunDirectEgress>,
}

struct TunDirectEgress {
    // 用 proxy 地址探测当前物理出口，防止 TUN 默认路由生效后误选到 TUN。
    proxy_addrs: Arc<Vec<String>>,
    // proxy IP 绝不能再通过 proxy 连接池转发，否则当系统路由短暂捕获
    // agent->proxy 控制连接时会形成递归。
    proxy_ips: Arc<Vec<IpAddr>>,
    // 直连 socket 使用的物理接口绑定；macOS/Windows 常靠 if_index，Linux 可用 name。
    bind_interface: RwLock<Option<common::BindInterface>>,
    #[cfg(target_os = "macos")]
    helper_socket: Option<String>,
    refresh_lock: tokio::sync::Mutex<()>,
    last_refresh: RwLock<Option<Instant>>,
}

impl TunDirectEgress {
    fn new(
        proxy_addrs: Vec<String>,
        bind_interface: Option<common::BindInterface>,
        #[cfg(target_os = "macos")] helper_socket: Option<String>,
    ) -> Self {
        let proxy_ips = resolve_proxy_ips(&proxy_addrs);
        Self {
            proxy_addrs: Arc::new(proxy_addrs),
            proxy_ips: Arc::new(proxy_ips),
            bind_interface: RwLock::new(bind_interface),
            #[cfg(target_os = "macos")]
            helper_socket,
            refresh_lock: tokio::sync::Mutex::new(()),
            last_refresh: RwLock::new(None),
        }
    }

    fn bind_interface(&self) -> Option<common::BindInterface> {
        let guard = self.bind_interface.read().ok()?;
        guard.clone()
    }

    fn is_proxy_ip(&self, ip: IpAddr) -> bool {
        self.proxy_ips.contains(&ip)
    }

    async fn refresh_after_direct_failure(
        &self,
        target_ip: IpAddr,
        tcp_pool: &ConnectionPool,
        udp_pool: &ConnectionPool,
        tun_networks: TunNetworks,
    ) -> Option<common::BindInterface> {
        // 直连失败后刷新物理出口，但用冷却时间避免大量连接同时触发路由探测。
        if self.refresh_recently() {
            return self.bind_interface();
        }

        let _guard = self.refresh_lock.lock().await;
        if self.refresh_recently() {
            return self.bind_interface();
        }

        let refreshed = self
            .refresh_after_direct_failure_locked(target_ip, tcp_pool, udp_pool, tun_networks)
            .await;
        self.mark_refreshed();
        refreshed
    }

    async fn refresh_after_direct_failure_locked(
        &self,
        target_ip: IpAddr,
        tcp_pool: &ConnectionPool,
        udp_pool: &ConnectionPool,
        tun_networks: TunNetworks,
    ) -> Option<common::BindInterface> {
        let Some(route) = detect_proxy_route(self.proxy_addrs.as_slice()).await else {
            warn!("刷新 direct access 物理出口失败：无法探测当前 proxy 出口路由");
            self.refresh_macos_scoped_default_bypass();
            return self.refresh_default_route_interface(target_ip);
        };

        if tun_networks.contains_ip(route.local_ip) {
            warn!(
                "刷新 direct access 物理出口时探测到 TUN 地址 {}，尝试使用系统默认物理接口兜底",
                route.local_ip,
            );
            self.refresh_macos_scoped_default_bypass();
            return self.refresh_default_route_interface(target_ip);
        }

        self.refresh_macos_scoped_default_bypass();
        let bind_interface = route.bind_interface.clone();
        self.update_bind_interface(bind_interface.clone());
        tcp_pool.set_proxy_bind_ip(Some(route.local_ip));
        tcp_pool.set_proxy_bind_interface(bind_interface.clone());
        udp_pool.set_proxy_bind_ip(Some(route.local_ip));
        udp_pool.set_proxy_bind_interface(bind_interface.clone());
        info!(
            "已刷新 direct access 物理出口：ip={} interface={:?}",
            route.local_ip, bind_interface
        );
        bind_interface
    }

    fn refresh_macos_scoped_default_bypass(&self) {
        #[cfg(target_os = "macos")]
        {
            if let Some(socket_path) = &self.helper_socket {
                match refresh_macos_scoped_default_bypass_via_helper(socket_path) {
                    Ok(()) => return,
                    Err(err) => warn!("通过 TUN helper 刷新 macOS scoped default 失败：{err}"),
                }
            }
        }

        refresh_macos_scoped_default_bypass_local();
    }

    fn refresh_default_route_interface(&self, target_ip: IpAddr) -> Option<common::BindInterface> {
        let bind_interface = detect_default_route_interface(target_ip.is_ipv6());
        if bind_interface.is_some() {
            self.update_bind_interface(bind_interface.clone());
            info!(
                "已用系统默认路由刷新 direct access 物理接口：target_ip={} interface={:?}",
                target_ip, bind_interface
            );
            bind_interface
        } else {
            warn!(
                "无法从系统默认路由刷新 direct access 物理接口，保留旧接口绑定 {:?}",
                self.bind_interface()
            );
            self.bind_interface()
        }
    }

    fn update_bind_interface(&self, bind_interface: Option<common::BindInterface>) {
        if let Ok(mut guard) = self.bind_interface.write() {
            *guard = bind_interface.clone();
        }
    }

    fn refresh_recently(&self) -> bool {
        self.last_refresh_time()
            .is_some_and(|last_refresh| last_refresh.elapsed() < DIRECT_EGRESS_REFRESH_COOLDOWN)
    }

    fn last_refresh_time(&self) -> Option<Instant> {
        let guard = self.last_refresh.read().ok()?;
        *guard
    }

    fn mark_refreshed(&self) {
        if let Ok(mut guard) = self.last_refresh.write() {
            *guard = Some(Instant::now());
        }
    }
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
    // 这个顺序非常关键：先固定控制连接出口，再安装 TUN/split-default 路由。
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

    let direct_egress = Arc::new(TunDirectEgress::new(
        proxy_addrs.clone(),
        proxy_bind_interface.clone(),
        #[cfg(target_os = "macos")]
        helper_managed_network.then(|| config.macos_helper_socket.clone()),
    ));
    let forward_context = TunForwardContext {
        tcp_pool: tcp_pool.clone(),
        udp_pool: udp_pool.clone(),
        direct_checker: direct_access_checker.clone(),
        direct_domain_cache: Arc::new(DirectDomainCache::new(Duration::from_secs(300))),
        tun_networks,
        proxy_dns,
        direct_egress,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn tun_direct_egress_records_proxy_ips() {
        let egress = TunDirectEgress::new(
            vec!["140.82.30.214:80".to_string(), "127.0.0.1:8080".to_string()],
            None,
            #[cfg(target_os = "macos")]
            None,
        );

        assert!(egress.is_proxy_ip(IpAddr::V4(Ipv4Addr::new(140, 82, 30, 214))));
        assert!(!egress.is_proxy_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(!egress.is_proxy_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }
}
