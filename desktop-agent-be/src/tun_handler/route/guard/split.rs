use super::*;

pub(in crate::tun_handler::route) fn install_ipv4_split_routes(
    mgr: &mut RouteManager,
    tun_if_index: u32,
    _tun_ipv4: Ipv4Addr,
    installed: &mut Vec<Route>,
    lease: &mut RouteLease,
) -> Result<()> {
    // 0.0.0.0/1 + 128.0.0.0/1 等价于默认路由，但优先级通常高于原 /0。
    // TUN/utun 是三层接口，这里使用接口路由；把 TUN 自己的 IP 当 gateway
    // 会在部分系统上导致路由不可用或回环。
    let v4_splits = [
        Route::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1).with_if_index(tun_if_index),
        Route::new(IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1).with_if_index(tun_if_index),
    ];
    for route in v4_splits {
        match mgr.add(&route) {
            Ok(()) => {
                info!("已安装 split-default 路由：{}", route);
                lease.record_installed(RouteKind::Ipv4SplitDefault, &route)?;
                installed.push(route);
            }
            Err(e) => {
                #[cfg(target_os = "macos")]
                return Err(AgentError::Connection(format!(
                    "安装必要的 IPv4 split-default 路由 {route} 失败：{e}"
                )));
                #[cfg(not(target_os = "macos"))]
                warn!("安装 split-default 路由 {} 失败：{e}", route);
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(in crate::tun_handler::route) fn required_route_exists(
    mgr: &mut RouteManager,
    kind: RouteKind,
    expected: &Route,
) -> Result<bool> {
    let routes = mgr.list().map_err(|e| {
        AgentError::Connection(format!(
            "无法读取路由表以验证已存在的必要路由 {expected}：{e}"
        ))
    })?;
    Ok(route_list_contains_expected(kind, expected, &routes))
}

pub fn route_list_contains_expected(kind: RouteKind, expected: &Route, routes: &[Route]) -> bool {
    let record = RouteRecord::from_route(kind, expected);
    routes
        .iter()
        .any(|candidate| record.matches_route(candidate))
}

pub(in crate::tun_handler::route) fn install_ipv6_split_routes(
    mgr: &mut RouteManager,
    tun_if_index: u32,
    tun_ipv6_cidr: Option<&str>,
    installed: &mut Vec<Route>,
    lease: &mut RouteLease,
) -> Result<()> {
    let Some(v6_cidr) = tun_ipv6_cidr else {
        return Ok(());
    };
    // IPv6 未正确配置时跳过，不影响 IPv4 TUN 模式。
    let Ok((_tun_ipv6, _)) = parse_cidr_v6(v6_cidr) else {
        return Ok(());
    };

    // ::/1 + 8000::/1 是 IPv6 的 split-default。
    let v6_splits = [
        Route::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1).with_if_index(tun_if_index),
        Route::new(IpAddr::V6(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)), 1)
            .with_if_index(tun_if_index),
    ];
    for route in v6_splits {
        match mgr.add(&route) {
            Ok(()) => {
                info!("已安装 IPv6 split-default 路由：{}", route);
                lease.record_installed(RouteKind::Ipv6SplitDefault, &route)?;
                installed.push(route);
            }
            Err(e) => {
                #[cfg(target_os = "macos")]
                return Err(AgentError::Connection(format!(
                    "安装必要的 IPv6 split-default 路由 {route} 失败：{e}"
                )));
                #[cfg(not(target_os = "macos"))]
                warn!("安装 IPv6 split-default 路由 {} 失败：{e}", route);
            }
        }
    }
    Ok(())
}
