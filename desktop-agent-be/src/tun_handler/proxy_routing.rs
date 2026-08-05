//! TUN 模式下 agent->proxy 控制连接的旁路准备。
//!
//! TUN 一旦接管默认路由，agent 自己连接 proxy 的 TCP 连接也可能被送回 TUN。
//! 因此在安装 TUN 路由前，需要先探测当前物理出口 IP/接口，并写入 Yamux session manager，
//! 后续新建 proxy 连接都会绑定到这个物理出口。

use super::device::tun_ipv4_peer;
use super::route;
use super::*;
use std::sync::Arc;

/// Restores the shared HTTP/SOCKS session managers to normal routing whenever
/// TUN setup exits, including cancellation, setup errors, task aborts, and
/// unwinding. The managers are shared with the non-TUN listeners, so leaving a
/// physical-interface bind behind after TUN startup fails would break their
/// later proxy connections.
pub struct ProxySessionBindGuard {
    tcp_sessions: Arc<YamuxSessionManager>,
    udp_sessions: Arc<YamuxSessionManager>,
}

impl ProxySessionBindGuard {
    pub fn new(
        tcp_sessions: Arc<YamuxSessionManager>,
        udp_sessions: Arc<YamuxSessionManager>,
    ) -> Self {
        Self {
            tcp_sessions,
            udp_sessions,
        }
    }

    pub fn clear(&self) {
        self.tcp_sessions.set_proxy_addrs_override(None);
        self.tcp_sessions.set_proxy_bind_ip(None);
        self.tcp_sessions.set_proxy_bind_interface(None);
        self.udp_sessions.set_proxy_addrs_override(None);
        self.udp_sessions.set_proxy_bind_ip(None);
        self.udp_sessions.set_proxy_bind_interface(None);
    }
}

impl Drop for ProxySessionBindGuard {
    fn drop(&mut self) {
        self.clear();
    }
}

pub(super) async fn configure_proxy_routing(
    config: &TunConfig,
    proxy_addrs: &[String],
    tcp_sessions: &YamuxSessionManager,
    udp_sessions: &YamuxSessionManager,
    shutdown: &CancellationToken,
) -> (Option<common::BindInterface>, Vec<String>) {
    // 通过 OS 路由决策探测物理出口 IP/接口，用于后续 proxy 连接 bind。
    // macOS 登录项开机自启时，默认路由和网络服务常常晚于进程启动才可用。
    let started = Instant::now();
    let mut attempts = 0usize;
    let mut last_partial_route = None;
    let proxy_route = loop {
        attempts += 1;
        match detect_proxy_route(proxy_addrs).await {
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
    let mut pinned_proxy_addrs = proxy_addrs.to_vec();
    if let Some(route) = proxy_route {
        // 这里设置的是 Yamux session manager 的“未来连接”绑定；已有连接不会被迁移。
        bind_interface = route.bind_interface.clone();
        info!(
            "检测到物理出口：ip={} interface={:?}；代理连接将绑定到该出口（尝试 {} 次，用时 {:?}）",
            route.local_ip,
            route.bind_interface,
            attempts,
            started.elapsed()
        );
        tcp_sessions.set_proxy_bind_ip(Some(route.local_ip));
        tcp_sessions.set_proxy_bind_interface(route.bind_interface.clone());
        udp_sessions.set_proxy_bind_ip(Some(route.local_ip));
        udp_sessions.set_proxy_bind_interface(route.bind_interface);

        // 每次连接只会随机选择一个受管 proxy endpoint。固定为 IP 后需同步
        // 过滤地址族，否则 IPv4 物理出口可能随机选到 IPv6 endpoint（反之亦然）。
        let same_family = proxy_addrs
            .iter()
            .filter(|address| proxy_endpoint_matches_ip_family(address, route.local_ip))
            .cloned()
            .collect::<Vec<_>>();
        if !same_family.is_empty() {
            pinned_proxy_addrs = same_family;
        }
    } else {
        warn!(
            "无法检测物理出口 IP — 代理连接可能会回环进入 TUN。\
             请确保启动 TUN 模式前代理服务器可达。"
        );
        tcp_sessions.set_proxy_bind_ip(None);
        tcp_sessions.set_proxy_bind_interface(None);
        udp_sessions.set_proxy_bind_ip(None);
        udp_sessions.set_proxy_bind_interface(None);
    }

    let pinned_proxy_addrs = Arc::new(pinned_proxy_addrs);
    tcp_sessions.set_proxy_addrs_override(Some(pinned_proxy_addrs.clone()));
    udp_sessions.set_proxy_addrs_override(Some(pinned_proxy_addrs.clone()));
    info!(
        "TUN 运行期间已固定 {} 个 proxy IP endpoint，后续重连不再依赖系统 DNS",
        pinned_proxy_addrs.len()
    );

    debug!(
        "TUN 路由预配置完成：设备={} ipv4={} mtu={}",
        config.name, config.ipv4, config.mtu
    );

    (bind_interface, pinned_proxy_addrs.as_ref().clone())
}

fn proxy_endpoint_matches_ip_family(endpoint: &str, local_ip: std::net::IpAddr) -> bool {
    endpoint
        .parse::<std::net::SocketAddr>()
        .is_ok_and(|address| address.is_ipv4() == local_ip.is_ipv4())
}

fn proxy_route_has_interface(route: &route::ProxyRoute) -> bool {
    route
        .bind_interface
        .as_ref()
        .is_some_and(bind_interface_is_usable)
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "fuchsia"))]
pub(super) fn bind_interface_is_usable(interface: &common::BindInterface) -> bool {
    interface
        .name
        .as_deref()
        .is_some_and(|name| !name.is_empty() && !name.as_bytes().contains(&0))
}

#[cfg(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
    windows,
))]
pub(super) fn bind_interface_is_usable(interface: &common::BindInterface) -> bool {
    interface.index.is_some_and(|index| index != 0)
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
pub(super) fn bind_interface_is_usable(interface: &common::BindInterface) -> bool {
    interface
        .name
        .as_deref()
        .is_some_and(|name| !name.is_empty() && !name.as_bytes().contains(&0))
        || interface.index.is_some_and(|index| index != 0)
}

pub(super) fn install_route_guard(
    config: &TunConfig,
    tun_ipv4: std::net::Ipv4Addr,
    tun_ipv4_prefix: u8,
    tun_if_index: u32,
    proxy_addrs: &[String],
) -> Result<RouteGuard> {
    // 解析 proxy IP 后安装旁路和 split-default 路由。必要路由安装失败时必须
    // 中止 TUN 启动；RouteGuard::install 会回滚本次已经安装的路由。
    let proxy_ips = route::resolve_proxy_ips_checked(proxy_addrs)?;
    let dns_capture_target = tun_ipv4_peer(tun_ipv4, tun_ipv4_prefix).unwrap_or(tun_ipv4);
    RouteGuard::install(
        tun_if_index,
        tun_ipv4,
        dns_capture_target,
        config.ipv6.as_deref(),
        config.route_state_file.as_deref(),
        &proxy_ips,
        config.proxy_dns,
    )
}
