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
pub(super) struct ProxySessionBindGuard {
    tcp_sessions: Arc<YamuxSessionManager>,
    udp_sessions: Arc<YamuxSessionManager>,
}

impl ProxySessionBindGuard {
    pub(super) fn new(
        tcp_sessions: Arc<YamuxSessionManager>,
        udp_sessions: Arc<YamuxSessionManager>,
    ) -> Self {
        Self {
            tcp_sessions,
            udp_sessions,
        }
    }

    pub(super) fn clear(&self) {
        self.tcp_sessions.set_proxy_bind_ip(None);
        self.tcp_sessions.set_proxy_bind_interface(None);
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
) -> Option<common::BindInterface> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AgentConfig;
    use std::net::{IpAddr, Ipv4Addr};

    const MINIMAL_AGENT_CONFIG: &str = r#"
listen_addr = "127.0.0.1:10080"
username = "user1"
private_key_path = "keys/user1.pem"
"#;

    #[test]
    fn proxy_session_bind_guard_clears_both_shared_managers_on_drop() {
        let config: AgentConfig = toml::from_str(MINIMAL_AGENT_CONFIG).unwrap();
        let config = Arc::new(config);
        let proxy_addrs = Arc::new(vec!["127.0.0.1:8080".to_string()]);
        let tcp_sessions = Arc::new(YamuxSessionManager::new(
            config.clone(),
            proxy_addrs.clone(),
        ));
        let udp_sessions = Arc::new(YamuxSessionManager::new_udp(config, proxy_addrs));
        let bind_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let bind_interface = common::BindInterface {
            name: Some("physical0".to_string()),
            index: Some(7),
        };

        {
            let _guard = ProxySessionBindGuard::new(tcp_sessions.clone(), udp_sessions.clone());
            tcp_sessions.set_proxy_bind_ip(Some(bind_ip));
            tcp_sessions.set_proxy_bind_interface(Some(bind_interface.clone()));
            udp_sessions.set_proxy_bind_ip(Some(bind_ip));
            udp_sessions.set_proxy_bind_interface(Some(bind_interface.clone()));

            assert_eq!(tcp_sessions.proxy_bind_ip_for_test(), Some(bind_ip));
            assert_eq!(
                tcp_sessions.proxy_bind_interface_for_test(),
                Some(bind_interface.clone())
            );
            assert_eq!(udp_sessions.proxy_bind_ip_for_test(), Some(bind_ip));
            assert_eq!(
                udp_sessions.proxy_bind_interface_for_test(),
                Some(bind_interface)
            );
        }

        assert_eq!(tcp_sessions.proxy_bind_ip_for_test(), None);
        assert_eq!(tcp_sessions.proxy_bind_interface_for_test(), None);
        assert_eq!(udp_sessions.proxy_bind_ip_for_test(), None);
        assert_eq!(udp_sessions.proxy_bind_interface_for_test(), None);
    }
}
