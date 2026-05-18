use super::network::parse_cidr_v6;
use crate::error::{AgentError, Result};
use common::BindInterface;
use route_manager::{Route, RouteManager};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub(super) struct ProxyRoute {
    pub(super) local_ip: IpAddr,
    pub(super) bind_interface: Option<BindInterface>,
}

/// 检测 OS 当前使用哪个本地出口来到达代理服务器。
///
/// 创建一个 connected UDP 套接字（实际不发送数据包），让 OS 告知它会使用哪个
/// 本地地址。因为此操作在安装任何 TUN 路由规则之前运行，所以结果是物理网卡
/// 的 IP；同时读取当前最佳路由的接口信息。后续代理 TCP 连接会绑定到这个
/// IP/接口，防止 split-default TUN 路由生效后控制连接回环进入 TUN。
pub(super) fn detect_proxy_route(proxy_addrs: &[String]) -> Option<ProxyRoute> {
    let routes = RouteManager::new()
        .and_then(|mut manager| manager.list())
        .ok();

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
            if let Ok(sock) = std::net::UdpSocket::bind(bind_str)
                && sock.connect(dst).is_ok()
                && let Ok(local) = sock.local_addr()
            {
                let route_interface = routes
                    .as_deref()
                    .and_then(|routes| best_route(routes, dst.ip()))
                    .and_then(route_bind_interface);
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

/// 将 `proxy_addrs` 中的每个 "host:port" 字符串解析为唯一 IP 列表。
/// 解析失败的主机名会被静默跳过（会打印警告）。
pub(super) fn resolve_proxy_ips(proxy_addrs: &[String]) -> Vec<IpAddr> {
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
pub(super) struct RouteGuard {
    mgr: RouteManager,
    installed: Vec<Route>,
}

impl RouteGuard {
    /// 先安装代理 /32 旁路路由，再安装指向 TUN 的 split-default 路由。
    /// 顺序很重要：旁路路由必须先于默认重定向存在，否则内核无法到达代理。
    pub(super) fn install(
        tun_if_index: u32,
        tun_ipv4: Ipv4Addr,
        tun_ipv6_cidr: Option<&str>,
        proxy_ips: &[IpAddr],
    ) -> Result<Self> {
        let mut mgr = RouteManager::new()
            .map_err(|e| AgentError::Connection(format!("RouteManager 初始化失败：{e}")))?;

        let (default_v4_gw, default_v4_if) = match mgr.list() {
            Ok(routes) => find_default_route(&routes, false),
            Err(e) => {
                warn!("无法列出当前路由：{e}");
                (None, None)
            }
        };
        let (default_v6_gw, default_v6_if) = match mgr.list() {
            Ok(routes) => find_default_route(&routes, true),
            Err(e) => {
                warn!("无法列出当前 IPv6 路由：{e}");
                (None, None)
            }
        };
        info!(
            "现有默认路由：v4 网关={:?} 接口={:?}，v6 网关={:?} 接口={:?}",
            default_v4_gw, default_v4_if, default_v6_gw, default_v6_if
        );

        let mut installed: Vec<Route> = Vec::new();

        for ip in proxy_ips {
            // 给每个 proxy IP 安装最具体的主机路由，使 agent 到 proxy 绕过 TUN。
            let route = match ip {
                IpAddr::V4(v4) => {
                    let mut r = Route::new(IpAddr::V4(*v4), 32);
                    if let Some(gw) = default_v4_gw {
                        r = r.with_gateway(gw);
                    }
                    if let Some(idx) = default_v4_if {
                        r = r.with_if_index(idx);
                    }
                    r
                }
                IpAddr::V6(v6) => {
                    let mut r = Route::new(IpAddr::V6(*v6), 128);
                    if let Some(gw) = default_v6_gw {
                        r = r.with_gateway(gw);
                    }
                    if let Some(idx) = default_v6_if {
                        r = r.with_if_index(idx);
                    }
                    r
                }
            };
            match mgr.add(&route) {
                Ok(()) => {
                    info!("已安装代理旁路路由：{}", route);
                    installed.push(route);
                }
                Err(e) => warn!("为 {ip} 安装旁路路由失败：{e}"),
            }
        }

        // split-default 将公网流量分成两半导入 TUN，同时让更具体的旁路路由优先。
        install_ipv4_split_routes(&mut mgr, tun_if_index, tun_ipv4, &mut installed);
        install_ipv6_split_routes(&mut mgr, tun_if_index, tun_ipv6_cidr, &mut installed);

        Ok(Self { mgr, installed })
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        info!(
            "正在恢复路由表：删除 {} 条已安装的路由",
            self.installed.len()
        );
        while let Some(route) = self.installed.pop() {
            match self.mgr.delete(&route) {
                Ok(()) => debug!("已删除路由：{}", route),
                Err(e) => warn!("删除路由 {} 失败：{e}", route),
            }
        }
    }
}

fn install_ipv4_split_routes(
    mgr: &mut RouteManager,
    tun_if_index: u32,
    _tun_ipv4: Ipv4Addr,
    installed: &mut Vec<Route>,
) {
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
                installed.push(route);
            }
            Err(e) => warn!("安装 split-default 路由 {} 失败：{e}", route),
        }
    }
}

fn install_ipv6_split_routes(
    mgr: &mut RouteManager,
    tun_if_index: u32,
    tun_ipv6_cidr: Option<&str>,
    installed: &mut Vec<Route>,
) {
    let Some(v6_cidr) = tun_ipv6_cidr else {
        return;
    };
    // IPv6 未正确配置时跳过，不影响 IPv4 TUN 模式。
    let Ok((_tun_ipv6, _)) = parse_cidr_v6(v6_cidr) else {
        return;
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
                installed.push(route);
            }
            Err(e) => warn!("安装 IPv6 split-default 路由 {} 失败：{e}", route),
        }
    }
}

/// 在 `routes` 中找到第一条非 TUN 的默认路由。
/// 返回 (网关, if_index) 以供安装旁路路由使用。
/// `want_v6 == true` 时查找 ::/0 而非 0.0.0.0/0。
fn find_default_route(routes: &[Route], want_v6: bool) -> (Option<IpAddr>, Option<u32>) {
    for r in routes {
        if r.prefix() != 0 {
            continue;
        }
        let is_v6 = matches!(r.destination(), IpAddr::V6(_));
        if is_v6 != want_v6 {
            continue;
        }
        let dest_unspec = match r.destination() {
            IpAddr::V4(v4) => v4.is_unspecified(),
            IpAddr::V6(v6) => v6.is_unspecified(),
        };
        if !dest_unspec {
            continue;
        }
        return (r.gateway(), r.if_index());
    }
    (None, None)
}

fn best_route(routes: &[Route], dst: IpAddr) -> Option<&Route> {
    routes
        .iter()
        .filter(|route| route.destination().is_ipv4() == dst.is_ipv4() && route.contains(&dst))
        .max_by_key(|route| route.prefix())
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
