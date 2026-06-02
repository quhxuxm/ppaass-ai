use super::device::tun_ipv4_peer;
use super::route;
use super::*;

pub(super) async fn configure_proxy_routing(
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

pub(super) fn install_route_guard(
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
