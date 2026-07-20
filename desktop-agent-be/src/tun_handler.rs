//! TUN 模式转发器。
//!
//! 当 TUN 模式启用时，agent 会打开一个 TUN 设备，并使用
//! [`netstack-smoltcp`](https://crates.io/crates/netstack-smoltcp) 在其上构建
//! 用户空间 TCP/IP 协议栈。协议栈接受的 TCP/UDP 流会按配置选择
//! agent 本地直连，或通过 [`YamuxSessionManager`] 转发到 proxy。
//! `direct_access` 规则与 TUN UDP 的 `proxy_udp` 开关共同决定具体路径。

mod device;
mod direct_domain_cache;
mod dns;
mod dns_proxy;
#[cfg(target_os = "macos")]
#[allow(dead_code)]
pub(crate) mod helper_service;
mod netstack;
mod network;
mod proxy_routing;
mod route;
mod tasks;
mod tcp;
mod udp;
mod udp_relay;

use crate::config::TunConfig;
use crate::direct_access::DirectAccessChecker;
use crate::error::{AgentError, Result};
use crate::privilege::ensure_tun_privileges_or_relaunch;
#[cfg(target_os = "macos")]
use crate::tun_helper_client::{
    HelperTunLease,
    refresh_macos_scoped_default_bypass as refresh_macos_scoped_default_bypass_via_helper,
    start_tun as start_tun_via_helper,
};
use crate::yamux_session::YamuxSessionManager;
use common::{
    TransportMode, install_known_smoltcp_panic_hook, panic_payload_message, spawn_guarded,
};
#[cfg(windows)]
use device::tun_ipv4_peer;
use device::{CreatedTunDevice, create_tun_device};
use direct_domain_cache::DirectDomainCache;
use dns::DnsGuard;
use futures::FutureExt;
use netstack::{spawn_netstack_supervisor, wait_tun_task};
use netstack_smoltcp::StackBuilder;
use network::{TunNetworks, parse_cidr_v4, parse_cidr_v6};
use proxy_routing::{bind_interface_is_usable, configure_proxy_routing, install_route_guard};
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

struct TunDirectEgress {
    // 用 proxy 地址探测当前物理出口，防止 TUN 默认路由生效后误选到 TUN。
    proxy_addrs: Arc<Vec<String>>,
    // IPv4/IPv6 可能使用不同物理出口，必须按目标地址族选择绑定。
    bind_interfaces: RwLock<TunDirectBindInterfaces>,
    #[cfg(target_os = "macos")]
    helper_socket: Option<String>,
    refresh_lock: tokio::sync::Mutex<()>,
    last_refresh: RwLock<TunDirectRefreshTimes>,
}

#[derive(Default)]
struct TunDirectBindInterfaces {
    ipv4: Option<common::BindInterface>,
    ipv6: Option<common::BindInterface>,
}

#[derive(Default)]
struct TunDirectRefreshTimes {
    ipv4: Option<Instant>,
    ipv6: Option<Instant>,
}

impl TunDirectEgress {
    fn new(
        proxy_addrs: Vec<String>,
        bind_interface: Option<common::BindInterface>,
        #[cfg(target_os = "macos")] helper_socket: Option<String>,
    ) -> Self {
        let fallback = bind_interface.filter(bind_interface_is_usable);
        let ipv4 = detect_default_route_interface(false)
            .filter(bind_interface_is_usable)
            .or_else(|| fallback.clone());
        let ipv6 = detect_default_route_interface(true)
            .filter(bind_interface_is_usable)
            .or_else(|| fallback.clone());
        Self {
            proxy_addrs: Arc::new(proxy_addrs),
            bind_interfaces: RwLock::new(TunDirectBindInterfaces { ipv4, ipv6 }),
            #[cfg(target_os = "macos")]
            helper_socket,
            refresh_lock: tokio::sync::Mutex::new(()),
            last_refresh: RwLock::new(TunDirectRefreshTimes::default()),
        }
    }

    fn bind_interface(&self, target_ip: IpAddr) -> Option<common::BindInterface> {
        let guard = self.bind_interfaces.read().ok()?;
        if target_ip.is_ipv6() {
            guard.ipv6.clone()
        } else {
            guard.ipv4.clone()
        }
    }

    async fn refresh_after_direct_failure(
        &self,
        target_ip: IpAddr,
        tcp_sessions: &YamuxSessionManager,
        udp_sessions: &YamuxSessionManager,
        tun_networks: TunNetworks,
    ) -> Option<common::BindInterface> {
        // 直连失败后刷新物理出口，但用冷却时间避免大量连接同时触发路由探测。
        if self.refresh_recently(target_ip) {
            return self.bind_interface(target_ip);
        }

        let _guard = self.refresh_lock.lock().await;
        if self.refresh_recently(target_ip) {
            return self.bind_interface(target_ip);
        }

        let refreshed = self
            .refresh_after_direct_failure_locked(
                target_ip,
                tcp_sessions,
                udp_sessions,
                tun_networks,
            )
            .await;
        self.mark_refreshed(target_ip);
        refreshed
    }

    async fn refresh_after_direct_failure_locked(
        &self,
        target_ip: IpAddr,
        tcp_sessions: &YamuxSessionManager,
        udp_sessions: &YamuxSessionManager,
        tun_networks: TunNetworks,
    ) -> Option<common::BindInterface> {
        // helper 管理的 macOS 路由可能在待机/切网后需要先刷新。
        // 优先重新探测 proxy 出口，这样可以同步刷新两类 proxy session manager；
        // 若探测结果属于 TUN、地址族不匹配或没有可用接口，再按目标地址族取系统默认接口。
        self.refresh_macos_scoped_default_bypass();
        let Some(route) = detect_proxy_route(self.proxy_addrs.as_slice()).await else {
            warn!("刷新 direct access 物理出口失败：无法探测当前 proxy 出口路由");
            return self.refresh_default_route_interface(target_ip);
        };

        if tun_networks.contains_ip(route.local_ip) {
            warn!(
                "刷新 direct access 物理出口时探测到 TUN 路由：\
                 route_ip={} target_ip={}，尝试使用对应地址族的系统默认接口兜底",
                route.local_ip, target_ip
            );
            return self.refresh_default_route_interface(target_ip);
        }

        let bind_interface = route.bind_interface.filter(bind_interface_is_usable);
        let Some(bind_interface) = bind_interface else {
            warn!(
                "刷新 direct access 物理出口时未得到可用接口：\
                 route_ip={} target_ip={}",
                route.local_ip, target_ip
            );
            return self.refresh_default_route_interface(target_ip);
        };
        // proxy 出口刷新与 direct 目标的地址族选择分开：
        // 即使当前 direct 目标是 IPv4、proxy 走 IPv6（或反之），
        // 后续 proxy session 也应该立即拿到新出口。
        tcp_sessions.set_proxy_bind_ip(Some(route.local_ip));
        tcp_sessions.set_proxy_bind_interface(Some(bind_interface.clone()));
        udp_sessions.set_proxy_bind_ip(Some(route.local_ip));
        udp_sessions.set_proxy_bind_interface(Some(bind_interface.clone()));

        if route.local_ip.is_ipv6() != target_ip.is_ipv6() {
            info!(
                "已刷新 proxy 物理出口，但地址族与 direct 目标不同：\
                 route_ip={} target_ip={}，direct 改用对应地址族的系统默认接口",
                route.local_ip, target_ip
            );
            return self.refresh_default_route_interface(target_ip);
        }

        self.update_bind_interface(target_ip, Some(bind_interface.clone()));
        info!(
            "已刷新 direct access 物理出口：ip={} interface={:?}",
            route.local_ip, bind_interface
        );
        Some(bind_interface)
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
        let bind_interface = bind_interface.filter(bind_interface_is_usable);
        if bind_interface.is_some() {
            self.update_bind_interface(target_ip, bind_interface.clone());
            info!(
                "已用系统默认路由刷新 direct access 物理接口：target_ip={} interface={:?}",
                target_ip, bind_interface
            );
            bind_interface
        } else {
            warn!(
                "无法从系统默认路由刷新 direct access 物理接口，保留旧接口绑定 {:?}",
                self.bind_interface(target_ip)
            );
            self.bind_interface(target_ip)
        }
    }

    fn update_bind_interface(
        &self,
        target_ip: IpAddr,
        bind_interface: Option<common::BindInterface>,
    ) {
        if let Ok(mut guard) = self.bind_interfaces.write() {
            if target_ip.is_ipv6() {
                guard.ipv6 = bind_interface;
            } else {
                guard.ipv4 = bind_interface;
            }
        }
    }

    fn refresh_recently(&self, target_ip: IpAddr) -> bool {
        self.last_refresh_time(target_ip)
            .is_some_and(|last_refresh| last_refresh.elapsed() < DIRECT_EGRESS_REFRESH_COOLDOWN)
    }

    fn last_refresh_time(&self, target_ip: IpAddr) -> Option<Instant> {
        let guard = self.last_refresh.read().ok()?;
        if target_ip.is_ipv6() {
            guard.ipv6
        } else {
            guard.ipv4
        }
    }

    fn mark_refreshed(&self, target_ip: IpAddr) {
        if let Ok(mut guard) = self.last_refresh.write() {
            if target_ip.is_ipv6() {
                guard.ipv6 = Some(Instant::now());
            } else {
                guard.ipv4 = Some(Instant::now());
            }
        }
    }
}

/// 公开入口：构建 TUN 设备，连接到 netstack，运行转发循环直到 `shutdown` 触发。
#[instrument(skip(tcp_sessions, udp_sessions, direct_access_checker, shutdown))]
pub async fn run_tun_mode(
    config: TunConfig,
    transport_mode: TransportMode,
    proxy_addrs: Vec<String>,
    tcp_sessions: Arc<YamuxSessionManager>,
    udp_sessions: Arc<YamuxSessionManager>,
    direct_access_checker: Arc<DirectAccessChecker>,
    shutdown: CancellationToken,
) -> Result<()> {
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

    // 在劫持默认路由前配置 proxy 连接绕行，否则 agent 到 proxy 也会进 TUN。
    // 这个顺序非常关键：先固定控制连接出口，再安装 TUN/split-default 路由。
    let proxy_bind_interface = configure_proxy_routing(
        &config,
        &proxy_addrs,
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
        shutdown.clone(),
    )?;
    let route_guard = if helper_managed_network {
        None
    } else {
        install_route_guard(&config, ipv4, ipv4_prefix, tun_if_index, &proxy_addrs)
    };
    #[cfg(windows)]
    let dns_guard = if helper_managed_network {
        None
    } else {
        install_windows_dns_guard(
            proxy_dns,
            proxy_bind_interface.as_ref(),
            tun_if_index,
            ipv4,
            ipv4_prefix,
            config.dns_state_file.as_deref(),
        )
    };
    #[cfg(not(windows))]
    if !helper_managed_network {
        cleanup_stale_dns(config.dns_state_file.as_deref());
    }

    shutdown.cancelled().await;
    info!("收到 TUN 模式关闭请求");

    // 先恢复系统网络状态，再等待内部任务退出。否则任一任务卡住都会延迟路由恢复。
    tcp_sessions.set_proxy_bind_ip(None);
    tcp_sessions.set_proxy_bind_interface(None);
    udp_sessions.set_proxy_bind_ip(None);
    udp_sessions.set_proxy_bind_interface(None);
    // Windows DNS Client 会按接口发送查询，仅安装 DNS 服务器的 /32 TUN
    // 路由无法可靠捕获这类流量。先恢复接口 DNS，再撤销 TUN 路由，避免
    // 退出窗口内系统查询仍指向已经不可达的虚拟 DNS 地址。
    #[cfg(windows)]
    drop(dns_guard);
    drop(route_guard);
    #[cfg(target_os = "macos")]
    drop(system_guard);
    #[cfg(not(target_os = "macos"))]
    let _ = system_guard;

    let _ = tokio::join!(wait_tun_task("netstack_supervisor", netstack_task),);

    info!("TUN 模式转发器已停止");
    Ok(())
}

#[cfg(windows)]
fn install_windows_dns_guard(
    proxy_dns: bool,
    proxy_bind_interface: Option<&common::BindInterface>,
    tun_if_index: u32,
    tun_ipv4: std::net::Ipv4Addr,
    tun_ipv4_prefix: u8,
    dns_state_file: Option<&str>,
) -> Option<DnsGuard> {
    let Some(tun_dns) = tun_ipv4_peer(tun_ipv4, tun_ipv4_prefix) else {
        // install(false, ...) still restores a lease left by an interrupted older run.
        cleanup_stale_dns(dns_state_file);
        if proxy_dns {
            warn!(
                "TUN proxy_dns 已启用，但 {} 无可用虚拟 peer 地址；跳过 Windows 系统 DNS 接管",
                format_args!("{tun_ipv4}/{tun_ipv4_prefix}")
            );
        }
        return None;
    };

    if proxy_dns {
        info!(
            "Windows TUN proxy_dns 使用虚拟 DNS 地址：{tun_dns} (TUN={tun_ipv4}/{tun_ipv4_prefix})"
        );
    }
    DnsGuard::install(
        proxy_dns,
        proxy_bind_interface,
        tun_if_index,
        tun_dns,
        dns_state_file,
    )
}

fn cleanup_stale_dns(dns_state_file: Option<&str>) {
    // Windows 正常生命周期由 install_windows_dns_guard 持有 guard；本函数用于
    // proxy_dns 关闭、无可用虚拟 peer，以及其他平台清理异常退出遗留的状态。
    debug!("检查并恢复旧版本或异常退出遗留的 DNS 状态");
    let _ = DnsGuard::install(
        false,
        None,
        0,
        std::net::Ipv4Addr::UNSPECIFIED,
        dns_state_file,
    );
}
