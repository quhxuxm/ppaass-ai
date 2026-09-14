use arc_swap::ArcSwap;
use socket2::{SockAddr, Socket};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use tracing::{info, warn};

use crate::yamux_session::YamuxSessionManager;

use super::DIRECT_EGRESS_REFRESH_COOLDOWN;
use super::network::TunNetworks;
use super::proxy_routing::bind_interface_is_usable;
use super::route::{
    detect_default_route_interface, detect_proxy_route,
    refresh_macos_scoped_default_bypass as refresh_macos_scoped_default_bypass_local,
};
#[cfg(target_os = "macos")]
use crate::tun_helper_client::refresh_macos_scoped_default_bypass as refresh_macos_scoped_default_bypass_via_helper;

pub(super) struct TunDirectEgress {
    // 用 proxy 地址探测当前物理出口，防止 TUN 默认路由生效后误选到 TUN。
    proxy_addrs: Arc<Vec<String>>,
    // IPv4/IPv6 可能使用不同物理出口，必须按目标地址族选择绑定。
    bind_interfaces: ArcSwap<TunDirectBindInterfaces>,
    #[cfg(windows)]
    direct_source_ip: Option<IpAddr>,
    #[cfg(target_os = "macos")]
    helper_socket: Option<String>,
    refresh_lock: tokio::sync::Mutex<()>,
    refresh_epoch: Instant,
    last_refresh: TunDirectRefreshTimes,
}

#[derive(Clone, Default)]
struct TunDirectBindInterfaces {
    ipv4: Option<common::BindInterface>,
    ipv6: Option<common::BindInterface>,
}

struct TunDirectRefreshTimes {
    ipv4_millis: AtomicU64,
    ipv6_millis: AtomicU64,
}

impl Default for TunDirectRefreshTimes {
    fn default() -> Self {
        Self {
            ipv4_millis: AtomicU64::new(0),
            ipv6_millis: AtomicU64::new(0),
        }
    }
}

/// 选择 TUN 内直连 socket 的初始物理出口。
///
/// Windows 在 split-default 路由已安装后查询默认路由，会稳定得到 Wintun
/// 接口；因此必须优先使用 TUN 启动前为 proxy 捕获的物理接口，否则直连
/// socket 会被 `IP_UNICAST_IF` 再次送回 TUN。
pub fn select_initial_direct_bind_interface(
    captured_physical: Option<common::BindInterface>,
    detected_default: Option<common::BindInterface>,
) -> Option<common::BindInterface> {
    #[cfg(windows)]
    {
        captured_physical.or(detected_default)
    }

    #[cfg(not(windows))]
    {
        detected_default.or(captured_physical)
    }
}

pub fn select_direct_source_ip(
    captured_physical_ip: Option<IpAddr>,
    target_ip: IpAddr,
) -> Option<IpAddr> {
    captured_physical_ip.filter(|source_ip| source_ip.is_ipv6() == target_ip.is_ipv6())
}

pub(super) fn bind_direct_socket_source(
    socket: &Socket,
    source_ip: Option<IpAddr>,
    target: SocketAddr,
) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        let source_ip = source_ip.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!("TUN 直连缺少 {target} 的物理源地址"),
            )
        })?;
        socket.bind(&SockAddr::from(SocketAddr::new(source_ip, 0)))?;
    }

    #[cfg(not(windows))]
    let _ = (socket, source_ip, target);

    Ok(())
}

impl TunDirectEgress {
    pub(super) fn new(
        proxy_addrs: Vec<String>,
        proxy_bind_ip: Option<IpAddr>,
        bind_interface: Option<common::BindInterface>,
        #[cfg(target_os = "macos")] helper_socket: Option<String>,
    ) -> Self {
        let fallback = bind_interface.filter(bind_interface_is_usable);
        let ipv4 = select_initial_direct_bind_interface(
            fallback.clone(),
            detect_default_route_interface(false).filter(bind_interface_is_usable),
        );
        let ipv6 = select_initial_direct_bind_interface(
            fallback.clone(),
            detect_default_route_interface(true).filter(bind_interface_is_usable),
        );
        Self {
            proxy_addrs: Arc::new(proxy_addrs),
            bind_interfaces: ArcSwap::from_pointee(TunDirectBindInterfaces { ipv4, ipv6 }),
            #[cfg(windows)]
            direct_source_ip: proxy_bind_ip,
            #[cfg(target_os = "macos")]
            helper_socket,
            refresh_lock: tokio::sync::Mutex::new(()),
            refresh_epoch: Instant::now(),
            last_refresh: TunDirectRefreshTimes::default(),
        }
    }

    pub(super) fn bind_interface(&self, target_ip: IpAddr) -> Option<common::BindInterface> {
        let interfaces = self.bind_interfaces.load();
        if target_ip.is_ipv6() {
            interfaces.ipv6.clone()
        } else {
            interfaces.ipv4.clone()
        }
    }

    pub(super) fn can_direct(&self, target_ip: IpAddr) -> bool {
        #[cfg(windows)]
        {
            self.bind_source_ip(target_ip).is_some()
        }

        #[cfg(not(windows))]
        {
            let _ = target_ip;
            true
        }
    }

    pub(super) fn bind_source_ip(&self, target_ip: IpAddr) -> Option<IpAddr> {
        #[cfg(windows)]
        {
            select_direct_source_ip(self.direct_source_ip, target_ip)
        }

        #[cfg(not(windows))]
        {
            let _ = target_ip;
            None
        }
    }

    pub(super) async fn refresh_after_direct_failure(
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
        tcp_sessions.set_proxy_bind_route(Some(route.local_ip), Some(bind_interface.clone()));
        udp_sessions.set_proxy_bind_route(Some(route.local_ip), Some(bind_interface.clone()));

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
        self.bind_interfaces.rcu(|current| {
            let mut updated = (**current).clone();
            if target_ip.is_ipv6() {
                updated.ipv6 = bind_interface.clone();
            } else {
                updated.ipv4 = bind_interface.clone();
            }
            Arc::new(updated)
        });
    }

    fn refresh_recently(&self, target_ip: IpAddr) -> bool {
        let last_refresh_millis = self.last_refresh_millis(target_ip);
        last_refresh_millis != 0
            && self
                .elapsed_refresh_millis()
                .saturating_sub(last_refresh_millis)
                < DIRECT_EGRESS_REFRESH_COOLDOWN.as_millis() as u64
    }

    fn last_refresh_millis(&self, target_ip: IpAddr) -> u64 {
        if target_ip.is_ipv6() {
            self.last_refresh.ipv6_millis.load(Ordering::Acquire)
        } else {
            self.last_refresh.ipv4_millis.load(Ordering::Acquire)
        }
    }

    fn mark_refreshed(&self, target_ip: IpAddr) {
        let refreshed_at = self.elapsed_refresh_millis().max(1);
        if target_ip.is_ipv6() {
            self.last_refresh
                .ipv6_millis
                .store(refreshed_at, Ordering::Release);
        } else {
            self.last_refresh
                .ipv4_millis
                .store(refreshed_at, Ordering::Release);
        }
    }

    fn elapsed_refresh_millis(&self) -> u64 {
        self.refresh_epoch
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }
}
