use std::net::IpAddr;
use std::sync::{Arc, RwLock};
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

impl TunDirectEgress {
    pub(super) fn new(
        proxy_addrs: Vec<String>,
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
            bind_interfaces: RwLock::new(TunDirectBindInterfaces { ipv4, ipv6 }),
            #[cfg(target_os = "macos")]
            helper_socket,
            refresh_lock: tokio::sync::Mutex::new(()),
            last_refresh: RwLock::new(TunDirectRefreshTimes::default()),
        }
    }

    pub(super) fn bind_interface(&self, target_ip: IpAddr) -> Option<common::BindInterface> {
        let guard = self.bind_interfaces.read().ok()?;
        if target_ip.is_ipv6() {
            guard.ipv6.clone()
        } else {
            guard.ipv4.clone()
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
