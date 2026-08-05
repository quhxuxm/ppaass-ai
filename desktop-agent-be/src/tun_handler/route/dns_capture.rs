use super::*;

pub(super) struct DnsCaptureRouteContext<'a> {
    pub(super) tun_if_index: u32,
    pub(super) dns_ips: &'a [IpAddr],
    pub(super) proxy_ips: &'a [IpAddr],
    pub(super) default_v4_gateway: Option<IpAddr>,
    pub(super) default_v6_gateway: Option<IpAddr>,
}

pub(super) fn install_dns_capture_routes(
    mgr: &mut RouteManager,
    context: DnsCaptureRouteContext<'_>,
    installed: &mut Vec<Route>,
    lease: &mut RouteLease,
) -> Result<()> {
    let DnsCaptureRouteContext {
        tun_if_index,
        dns_ips,
        proxy_ips,
        default_v4_gateway,
        default_v6_gateway,
    } = context;

    if dns_ips.is_empty() {
        debug!("TUN proxy_dns 未发现可捕获的系统 DNS 服务器地址");
        return Ok(());
    }

    for ip in dns_ips {
        if proxy_ips.contains(ip) {
            debug!("系统 DNS 同时也是受管 Proxy 地址，跳过 DNS 捕获路由");
            continue;
        }
        if dns_capture_route_targets_default_gateway(*ip, default_v4_gateway, default_v6_gateway) {
            if should_capture_default_gateway_dns_route() {
                warn!(
                    "系统 DNS {ip} 同时也是默认网关；Windows 将安装 TUN DNS 捕获路由，\
                     不修改系统 DNS，DNS 请求进入 agent 后由 proxy 端解析"
                );
            } else {
                warn!("系统 DNS {ip} 同时也是默认网关，跳过普通 DNS 捕获路由以避免网络中断");
                continue;
            }
        }

        let route = match ip {
            IpAddr::V4(ip) => Route::new(IpAddr::V4(*ip), 32).with_if_index(tun_if_index),
            IpAddr::V6(ip) => Route::new(IpAddr::V6(*ip), 128).with_if_index(tun_if_index),
        };
        match mgr.add(&route) {
            Ok(()) => {
                info!("已安装系统 DNS 捕获路由（不修改系统 DNS）：{}", route);
                lease.record_installed(RouteKind::DnsCapture, &route)?;
                installed.push(route);
            }
            Err(e) => warn!("安装系统 DNS 捕获路由 {} 失败：{e}", route),
        }
    }
    Ok(())
}

pub fn dns_capture_route_targets_default_gateway(
    ip: IpAddr,
    default_v4_gateway: Option<IpAddr>,
    default_v6_gateway: Option<IpAddr>,
) -> bool {
    Some(ip) == default_v4_gateway || Some(ip) == default_v6_gateway
}

pub fn should_install_dns_capture_host_routes() -> bool {
    // macOS uses PF route-to and Windows points the TUN adapter at a virtual
    // peer DNS address. Installing a host route for every pre-existing Windows
    // DNS server is both redundant and unsafe: home routers commonly serve as
    // DNS and default gateway, so a gateway/32 route would hijack all access to
    // the gateway, not just port 53.
    !cfg!(any(target_os = "macos", windows))
}

pub fn should_capture_default_gateway_dns_route() -> bool {
    false
}
