use super::*;

#[cfg(target_os = "macos")]
pub(in crate::tun_handler::route) fn validate_macos_proxy_bypass_next_hop(
    _proxy_ip: IpAddr,
    tun_if_index: u32,
    physical_if_index: Option<u32>,
) -> Result<()> {
    let physical_if_index = physical_if_index.ok_or_else(|| {
        AgentError::Connection(
            "无法确定受管 Proxy 节点的物理出口接口，拒绝安装 split-default 以避免代理连接回环"
                .to_string(),
        )
    })?;
    if physical_if_index == tun_if_index {
        return Err(AgentError::Connection(format!(
            "受管 Proxy 节点的下一跳仍指向当前 TUN if_index={tun_if_index}，拒绝启动以避免代理连接回环"
        )));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(in crate::tun_handler::route) fn proxy_bypass_next_hop(
    routes: &[Route],
    destination: IpAddr,
    fallback_gateway: Option<IpAddr>,
    fallback_if_index: Option<u32>,
) -> (Option<IpAddr>, Option<u32>) {
    proxy_bypass_next_hop_from_routes(routes, destination, fallback_gateway, fallback_if_index)
}

#[cfg(not(target_os = "macos"))]
pub(in crate::tun_handler::route) fn proxy_bypass_next_hop(
    routes: &[Route],
    destination: IpAddr,
    fallback_gateway: Option<IpAddr>,
    fallback_if_index: Option<u32>,
) -> (Option<IpAddr>, Option<u32>) {
    route_next_hop(routes, destination, fallback_gateway, fallback_if_index)
}

/// 计算 proxy 旁路路由时不能直接采用已有的 proxy /32（或 /128）自身，
/// 否则旧 helper 留下的过期网关会被当作“当前正确下一跳”并通过验证。
pub fn proxy_bypass_next_hop_from_routes(
    routes: &[Route],
    destination: IpAddr,
    fallback_gateway: Option<IpAddr>,
    fallback_if_index: Option<u32>,
) -> (Option<IpAddr>, Option<u32>) {
    let host_prefix = if destination.is_ipv4() { 32 } else { 128 };
    routes
        .iter()
        .filter(|route| {
            route.destination().is_ipv4() == destination.is_ipv4()
                && route.contains(&destination)
                && !(route.destination() == destination && route.prefix() == host_prefix)
                && !route_is_split_default(route)
        })
        .max_by(|left, right| left.cmp(right))
        .map(|route| (route.gateway(), route.if_index()))
        .unwrap_or((fallback_gateway, fallback_if_index))
}

pub fn route_is_split_default(route: &Route) -> bool {
    if route.prefix() != 1 {
        return false;
    }
    match route.destination() {
        IpAddr::V4(destination) => {
            destination.is_unspecified() || destination == Ipv4Addr::new(128, 0, 0, 0)
        }
        IpAddr::V6(destination) => {
            destination.is_unspecified()
                || destination == Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)
        }
    }
}

pub(in crate::tun_handler::route) fn install_local_network_bypass_routes(
    mgr: &mut RouteManager,
    default_v4_gw: Option<IpAddr>,
    default_v4_if: Option<u32>,
    installed: &mut Vec<Route>,
    lease: &mut RouteLease,
) -> Result<()> {
    let routes = local_network_bypass_routes(default_v4_gw, default_v4_if);
    if routes.is_empty() {
        debug!("跳过局域网旁路路由：IPv4 默认网关或接口缺失");
        return Ok(());
    }

    for route in routes {
        match mgr.add(&route) {
            Ok(()) => {
                info!("已安装局域网旁路路由：{}", route);
                lease.record_installed(RouteKind::LocalNetworkBypass, &route)?;
                installed.push(route);
            }
            Err(e) => {
                let message = e.to_string();
                #[cfg(target_os = "macos")]
                if route_add_error_is_already_exists(&message)
                    && required_route_exists(mgr, RouteKind::LocalNetworkBypass, &route)?
                {
                    info!(
                        "局域网旁路路由已存在并验证正确，接管到当前 lease：{}",
                        route
                    );
                    lease.record_installed(RouteKind::LocalNetworkBypass, &route)?;
                    installed.push(route);
                } else {
                    warn!("安装局域网旁路路由 {} 失败：{message}", route);
                }
                #[cfg(not(target_os = "macos"))]
                if route_add_error_is_already_exists(&message) {
                    debug!("局域网旁路路由已存在：{}", route);
                } else {
                    warn!("安装局域网旁路路由 {} 失败：{message}", route);
                }
            }
        }
    }
    Ok(())
}

pub fn local_network_bypass_routes(
    default_v4_gw: Option<IpAddr>,
    default_v4_if: Option<u32>,
) -> Vec<Route> {
    let Some(default_v4_if) = default_v4_if else {
        return Vec::new();
    };
    let default_v4_gw = default_v4_gw.filter(IpAddr::is_ipv4);

    LOCAL_NETWORK_BYPASS_SPECS
        .iter()
        .filter_map(|(destination, prefix, next_hop)| {
            let route = Route::new(IpAddr::V4(*destination), *prefix).with_if_index(default_v4_if);
            match next_hop {
                LocalNetworkBypassNextHop::Gateway => {
                    default_v4_gw.map(|gateway| route.with_gateway(gateway))
                }
                LocalNetworkBypassNextHop::OnLink => Some(route),
            }
        })
        .collect()
}

pub fn route_add_error_is_already_exists(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("file exists")
        || message.contains("already in table")
        || message.contains("already exists")
}
