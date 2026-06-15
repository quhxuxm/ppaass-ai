use super::*;
use tokio::net::UdpSocket;

#[derive(Debug, Clone)]
pub(crate) struct ProxyRoute {
    pub(crate) local_ip: IpAddr,
    pub(crate) bind_interface: Option<BindInterface>,
}

pub(crate) async fn detect_proxy_route(proxy_addrs: &[String]) -> Option<ProxyRoute> {
    let routes = list_routes();

    for entry in proxy_addrs {
        // 缺省端口只用于触发 OS 路由选择，不会真正发包。
        let candidate = if entry.contains(':') {
            entry.clone()
        } else {
            format!("{entry}:443")
        };
        if let Ok(mut iter) = candidate.to_socket_addrs()
            && let Some(dst) = iter.next()
        {
            // connected UDP socket 会让 OS 选择本地出口地址。
            let bind_str = if dst.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
            if let Ok(sock) = UdpSocket::bind(bind_str).await
                && sock.connect(dst).await.is_ok()
                && let Ok(local) = sock.local_addr()
            {
                let route_interface = route_bind_interface_for_dst(routes.as_deref(), dst.ip());
                let local_interface = interface_for_local_ip(local.ip());
                if let (Some(local_interface), Some(route_interface)) =
                    (&local_interface, &route_interface)
                    && local_interface != route_interface
                {
                    debug!(
                        "本地地址接口 {:?} 与路由表接口 {:?} 不一致；优先使用本地地址接口",
                        local_interface, route_interface
                    );
                }
                let bind_interface = local_interface.or(route_interface);
                return Some(ProxyRoute {
                    local_ip: local.ip(),
                    bind_interface,
                });
            }
        }
    }
    None
}

pub(crate) fn detect_default_route_interface(want_v6: bool) -> Option<BindInterface> {
    let routes = list_routes()?;
    let route = default_route(&routes, want_v6)?;
    route_bind_interface(route)
}

fn list_routes() -> Option<Vec<Route>> {
    let mut manager = RouteManager::new().ok()?;
    let routes = manager.list().ok()?;
    Some(routes)
}

fn route_bind_interface_for_dst(routes: Option<&[Route]>, dst: IpAddr) -> Option<BindInterface> {
    let routes = routes?;
    let route = best_route(routes, dst)?;
    route_bind_interface(route)
}

/// 将 `proxy_addrs` 中的每个 "host:port" 字符串解析为唯一 IP 列表。
/// 解析失败的主机名会被静默跳过（会打印警告）。
pub(crate) fn resolve_proxy_ips(proxy_addrs: &[String]) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    for entry in proxy_addrs {
        // route_manager 只需要 IP；域名在安装路由前尽力解析。
        let candidates: Vec<String> = if entry.contains(':') {
            vec![entry.clone()]
        } else {
            vec![format!("{entry}:0")]
        };
        let mut resolved = false;
        for c in candidates {
            match c.to_socket_addrs() {
                Ok(iter) => {
                    for sa in iter {
                        let ip = sa.ip();
                        // loopback proxy 不需要旁路路由，安装反而可能干扰本机访问。
                        if ip.is_loopback() {
                            debug!("代理地址 {entry} 解析为回环地址 {ip}；跳过 TUN 旁路路由");
                            continue;
                        }
                        if !out.contains(&ip) {
                            out.push(ip);
                        }
                        resolved = true;
                    }
                }
                Err(e) => debug!("解析代理地址 {entry} 失败：{e}"),
            }
        }
        if !resolved {
            warn!("无法解析代理地址 {entry}；旁路路由已跳过");
        }
    }
    out
}

/// 记录所有已安装的路由，以便在 drop 时删除。
/// 在 `routes` 中找到第一条非 TUN 的默认路由。
/// 返回 (网关, if_index) 以供安装旁路路由使用。
/// `want_v6 == true` 时查找 ::/0 而非 0.0.0.0/0。
pub(super) fn find_default_route(routes: &[Route], want_v6: bool) -> (Option<IpAddr>, Option<u32>) {
    default_route(routes, want_v6)
        .map(|route| (route.gateway(), route.if_index()))
        .unwrap_or((None, None))
}

fn default_route(routes: &[Route], want_v6: bool) -> Option<&Route> {
    routes
        .iter()
        .filter(|route| {
            if route.prefix() != 0 {
                return false;
            }
            let is_v6 = matches!(route.destination(), IpAddr::V6(_));
            if is_v6 != want_v6 {
                return false;
            }
            match route.destination() {
                IpAddr::V4(v4) => v4.is_unspecified(),
                IpAddr::V6(v6) => v6.is_unspecified(),
            }
        })
        .max_by(|left, right| left.cmp(right))
}

pub(super) fn route_next_hop(
    routes: &[Route],
    dst: IpAddr,
    fallback_gateway: Option<IpAddr>,
    fallback_if_index: Option<u32>,
) -> (Option<IpAddr>, Option<u32>) {
    #[cfg(target_os = "macos")]
    if let Some(next_hop) = macos_route_get_next_hop(dst) {
        return next_hop;
    }

    best_route(routes, dst)
        .map(|route| (route.gateway(), route.if_index()))
        .unwrap_or((fallback_gateway, fallback_if_index))
}

#[cfg(target_os = "macos")]
fn macos_route_get_next_hop(dst: IpAddr) -> Option<(Option<IpAddr>, Option<u32>)> {
    let output = Command::new("/sbin/route")
        .args(["-n", "get", &dst.to_string()])
        .output()
        .ok()?;
    if !output.status.success() {
        debug!(
            "route -n get {dst} 失败：{}",
            command_output_message(&output)
        );
        return None;
    }
    parse_macos_route_get_next_hop(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(target_os = "macos")]
pub(super) fn parse_macos_route_get_next_hop(
    output: &str,
) -> Option<(Option<IpAddr>, Option<u32>)> {
    let mut gateway = None;
    let mut if_index = None;

    for line in output.lines().map(str::trim) {
        if let Some(value) = line.strip_prefix("gateway:") {
            gateway = value.trim().parse::<IpAddr>().ok();
            continue;
        }
        if let Some(value) = line.strip_prefix("interface:") {
            if_index = interface_index_for_name(value.trim());
        }
    }

    if gateway.is_none() && if_index.is_none() {
        None
    } else {
        Some((gateway, if_index))
    }
}

fn best_route(routes: &[Route], dst: IpAddr) -> Option<&Route> {
    routes
        .iter()
        .filter(|route| route.destination().is_ipv4() == dst.is_ipv4() && route.contains(&dst))
        .max_by(|left, right| left.cmp(right))
}

fn route_bind_interface(route: &Route) -> Option<BindInterface> {
    let name = route.if_name().cloned();
    let index = route.if_index();
    if name.is_none() && index.is_none() {
        return None;
    }

    Some(BindInterface { name, index })
}

fn interface_for_local_ip(local_ip: IpAddr) -> Option<BindInterface> {
    // connected UDP socket 已经给出了内核实际选择的本地源地址；这里再反查
    // 拥有该地址的接口，比直接从路由表选最长匹配更可靠。
    let interfaces = match if_addrs::get_if_addrs() {
        Ok(interfaces) => interfaces,
        Err(e) => {
            debug!("列出本机网络接口失败：{e}");
            return None;
        }
    };

    let mut fallback = None;
    for interface in interfaces {
        if interface.ip() != local_ip {
            continue;
        }

        let is_oper_up = interface.is_oper_up();
        let bind_interface = BindInterface {
            name: Some(interface.name),
            index: interface.index,
        };
        if is_oper_up {
            return Some(bind_interface);
        }
        fallback.get_or_insert(bind_interface);
    }

    fallback
}

#[cfg(target_os = "macos")]
pub(super) fn interface_name_for_index(if_index: Option<u32>) -> Option<String> {
    let if_index = if_index?;
    if_addrs::get_if_addrs()
        .ok()?
        .into_iter()
        .find(|interface| interface.index == Some(if_index))
        .map(|interface| interface.name)
}

#[cfg(target_os = "macos")]
pub(super) fn interface_index_for_name(name: &str) -> Option<u32> {
    let interface = if_addrs::get_if_addrs()
        .ok()?
        .into_iter()
        .find(|interface| interface.name == name)?;
    interface.index
}
