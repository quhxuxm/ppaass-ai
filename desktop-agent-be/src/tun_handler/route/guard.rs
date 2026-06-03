use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalNetworkBypassNextHop {
    Gateway,
    OnLink,
}

const LOCAL_NETWORK_BYPASS_SPECS: &[(Ipv4Addr, u8, LocalNetworkBypassNextHop)] = &[
    (
        Ipv4Addr::new(10, 0, 0, 0),
        8,
        LocalNetworkBypassNextHop::Gateway,
    ),
    (
        Ipv4Addr::new(100, 64, 0, 0),
        10,
        LocalNetworkBypassNextHop::Gateway,
    ),
    (
        Ipv4Addr::new(172, 16, 0, 0),
        12,
        LocalNetworkBypassNextHop::Gateway,
    ),
    (
        Ipv4Addr::new(192, 168, 0, 0),
        16,
        LocalNetworkBypassNextHop::Gateway,
    ),
    (
        Ipv4Addr::new(169, 254, 0, 0),
        16,
        LocalNetworkBypassNextHop::OnLink,
    ),
    (
        Ipv4Addr::new(224, 0, 0, 0),
        4,
        LocalNetworkBypassNextHop::OnLink,
    ),
    (
        Ipv4Addr::new(255, 255, 255, 255),
        32,
        LocalNetworkBypassNextHop::OnLink,
    ),
];

pub(crate) struct RouteGuard {
    mgr: RouteManager,
    installed: Vec<Route>,
    lease: RouteLease,
    #[cfg(target_os = "macos")]
    pf_dns_guard: Option<MacosPfDnsGuard>,
}

impl RouteGuard {
    /// 先安装代理 /32 与本地网络旁路路由，再安装指向 TUN 的 split-default 路由。
    /// 顺序很重要：旁路路由必须先于默认重定向存在，否则内核无法到达代理和局域网。
    pub(crate) fn install(
        tun_if_index: u32,
        tun_ipv4: Ipv4Addr,
        _dns_capture_target: Ipv4Addr,
        tun_ipv6_cidr: Option<&str>,
        route_state_file: Option<&str>,
        proxy_ips: &[IpAddr],
        capture_system_dns: bool,
    ) -> Result<Self> {
        let mut mgr = RouteManager::new()
            .map_err(|e| AgentError::Connection(format!("RouteManager 初始化失败：{e}")))?;
        let mut lease = RouteLease::new(route_state_file);

        lease.cleanup_stale_routes(&mut mgr);
        cleanup_existing_tun_split_routes(&mut mgr, tun_if_index);

        let routes = match mgr.list() {
            Ok(routes) => routes,
            Err(e) => {
                warn!("无法列出当前路由：{e}");
                Vec::new()
            }
        };
        let (default_v4_gw, default_v4_if) = find_default_route(&routes, false);
        let (default_v6_gw, default_v6_if) = find_default_route(&routes, true);
        info!(
            "现有默认路由：v4 网关={:?} 接口={:?}，v6 网关={:?} 接口={:?}",
            default_v4_gw, default_v4_if, default_v6_gw, default_v6_if
        );

        let mut installed: Vec<Route> = Vec::new();
        #[cfg(target_os = "macos")]
        let mut pf_dns_guard = None;

        for ip in proxy_ips {
            // 给每个 proxy IP 安装最具体的主机路由，使 agent 到 proxy 绕过 TUN。
            let route = match ip {
                IpAddr::V4(v4) => {
                    let (gateway, if_index) =
                        route_next_hop(&routes, *ip, default_v4_gw, default_v4_if);
                    let mut r = Route::new(IpAddr::V4(*v4), 32);
                    if let Some(gw) = gateway {
                        r = r.with_gateway(gw);
                    }
                    if let Some(idx) = if_index {
                        r = r.with_if_index(idx);
                    }
                    r
                }
                IpAddr::V6(v6) => {
                    let (gateway, if_index) =
                        route_next_hop(&routes, *ip, default_v6_gw, default_v6_if);
                    let mut r = Route::new(IpAddr::V6(*v6), 128);
                    if let Some(gw) = gateway {
                        r = r.with_gateway(gw);
                    }
                    if let Some(idx) = if_index {
                        r = r.with_if_index(idx);
                    }
                    r
                }
            };
            match mgr.add(&route) {
                Ok(()) => {
                    info!("已安装代理旁路路由：{}", route);
                    lease.record_installed(RouteKind::ProxyBypass, &route);
                    installed.push(route);
                }
                Err(e) => warn!("为 {ip} 安装旁路路由失败：{e}"),
            }
        }

        if capture_system_dns {
            let dns_servers = system_dns_servers();
            if should_install_dns_capture_host_routes() {
                let dns_capture_ips = dns_servers
                    .iter()
                    .map(|server| server.ip)
                    .collect::<Vec<_>>();
                install_dns_capture_routes(
                    &mut mgr,
                    DnsCaptureRouteContext {
                        tun_if_index,
                        dns_ips: &dns_capture_ips,
                        proxy_ips,
                        default_v4_gateway: default_v4_gw,
                        default_v6_gateway: default_v6_gw,
                    },
                    &mut installed,
                    &mut lease,
                );
            } else {
                debug!("macOS TUN DNS 捕获使用 PF route-to，不安装 DNS host route");
            }
            #[cfg(target_os = "macos")]
            {
                pf_dns_guard = MacosPfDnsGuard::install(
                    tun_if_index,
                    _dns_capture_target,
                    &dns_servers,
                    &macos_default_dns_interfaces(default_v4_if, default_v6_if),
                );
            }
            flush_system_dns_cache();
        }

        // macOS：在劫持默认路由前安装 ifscope 默认路由。
        // 没有这条路由时，`IP_BOUND_IF` 把直连套接字绑到物理接口后，
        // 内核做 scoped 路由查找会因为找不到 ifscope 默认路由而返回
        // "Network is unreachable" / "No route to host"，导致 *.bilibili.com 等
        // 命中 direct_access 的目标全部连接失败（symptom：浏览器无法打开）。
        #[cfg(target_os = "macos")]
        install_macos_scoped_default_bypass(
            default_v4_gw,
            default_v4_if,
            default_v6_gw,
            default_v6_if,
        );

        // direct_access 只能处理已经进入 TUN netstack 的连接；mDNS/SSDP/投屏/互联
        // 这类局域网流量更依赖物理接口和组播语义。先安装更具体的本地网络旁路，
        // 再安装 split-default，可让这些流量继续走原 Wi-Fi/以太网接口。
        install_local_network_bypass_routes(
            &mut mgr,
            default_v4_gw,
            default_v4_if,
            &mut installed,
            &mut lease,
        );

        // split-default 将公网流量分成两半导入 TUN，同时让更具体的旁路路由优先。
        install_ipv4_split_routes(&mut mgr, tun_if_index, tun_ipv4, &mut installed, &mut lease);
        install_ipv6_split_routes(
            &mut mgr,
            tun_if_index,
            tun_ipv6_cidr,
            &mut installed,
            &mut lease,
        );

        Ok(Self {
            mgr,
            installed,
            lease,
            #[cfg(target_os = "macos")]
            pf_dns_guard,
        })
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        drop(self.pf_dns_guard.take());

        info!(
            "正在恢复路由表：删除 {} 条已安装的路由",
            self.lease.state.routes.len()
        );
        let mut cleanup_ok = true;
        for record in self.lease.state.routes.iter().rev() {
            if !delete_recorded_route(&mut self.mgr, record) {
                cleanup_ok = false;
            }
        }
        self.installed.clear();
        if cleanup_ok {
            self.lease.clear();
        } else {
            warn!(
                "部分 TUN 路由未能删除，保留路由状态文件以便下次启动重试：{}",
                self.lease.path.display()
            );
        }
    }
}

fn install_local_network_bypass_routes(
    mgr: &mut RouteManager,
    default_v4_gw: Option<IpAddr>,
    default_v4_if: Option<u32>,
    installed: &mut Vec<Route>,
    lease: &mut RouteLease,
) {
    let routes = local_network_bypass_routes(default_v4_gw, default_v4_if);
    if routes.is_empty() {
        debug!("跳过局域网旁路路由：IPv4 默认网关或接口缺失");
        return;
    }

    for route in routes {
        match mgr.add(&route) {
            Ok(()) => {
                info!("已安装局域网旁路路由：{}", route);
                lease.record_installed(RouteKind::LocalNetworkBypass, &route);
                installed.push(route);
            }
            Err(e) => {
                let message = e.to_string();
                if route_add_error_is_already_exists(&message) {
                    debug!("局域网旁路路由已存在：{}", route);
                } else {
                    warn!("安装局域网旁路路由 {} 失败：{message}", route);
                }
            }
        }
    }
}

pub(super) fn local_network_bypass_routes(
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

pub(super) fn route_add_error_is_already_exists(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("file exists")
        || message.contains("already in table")
        || message.contains("already exists")
}

/// 安装 macOS ifscope 默认路由，作为代理旁路 / 直连套接字的下一跳兜底。
///
/// 没有这条路由时，使用 `IP_BOUND_IF` 绑定到物理接口的直连套接字会因
/// scoped 路由查找命中不到任何 ifscope 默认路由而失败，所有命中
/// `direct_access` 域名规则的目标都会无法连接。
#[cfg(target_os = "macos")]
fn install_macos_scoped_default_bypass(
    default_v4_gw: Option<IpAddr>,
    default_v4_if: Option<u32>,
    default_v6_gw: Option<IpAddr>,
    default_v6_if: Option<u32>,
) {
    if let (Some(gw), Some(if_idx)) = (default_v4_gw, default_v4_if)
        && let Some(if_name) = interface_name_for_index(Some(if_idx))
    {
        install_one_macos_scoped_default(&if_name, gw, false);
    } else {
        debug!("跳过 macOS IPv4 scoped default bypass：默认网关或接口缺失");
    }

    if let (Some(gw), Some(if_idx)) = (default_v6_gw, default_v6_if)
        && let Some(if_name) = interface_name_for_index(Some(if_idx))
    {
        install_one_macos_scoped_default(&if_name, gw, true);
    } else {
        debug!("跳过 macOS IPv6 scoped default bypass：默认网关或接口缺失");
    }
}

#[cfg(target_os = "macos")]
fn install_one_macos_scoped_default(if_name: &str, gateway: IpAddr, is_ipv6: bool) {
    // 形如：route -n add -ifscope en0 -net default 192.168.31.1
    let mut cmd = Command::new("/sbin/route");
    cmd.arg("-n").arg("add");
    if is_ipv6 {
        cmd.arg("-inet6");
    }
    cmd.args(["-ifscope", if_name, "-net", "default", &gateway.to_string()]);

    match cmd.output() {
        Ok(out) if out.status.success() => {
            info!(
                "已安装 macOS scoped default bypass：ifscope={if_name} gateway={gateway}；关闭 TUN 时保留该路由"
            );
        }
        Ok(out) => {
            let msg = command_output_message(&out);
            // 已存在同样的 ifscope 默认路由属于幂等成功；仅记录调试日志。
            if msg.contains("File exists") || msg.contains("already in table") {
                debug!("macOS scoped default bypass 已存在：ifscope={if_name} gateway={gateway}");
            } else {
                warn!(
                    "安装 macOS scoped default bypass 失败 ifscope={if_name} gateway={gateway}：{msg}"
                );
            }
        }
        Err(e) => warn!("运行 route add -ifscope 安装 macOS scoped default bypass 失败：{e}"),
    }
}

fn install_ipv4_split_routes(
    mgr: &mut RouteManager,
    tun_if_index: u32,
    _tun_ipv4: Ipv4Addr,
    installed: &mut Vec<Route>,
    lease: &mut RouteLease,
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
                lease.record_installed(RouteKind::Ipv4SplitDefault, &route);
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
    lease: &mut RouteLease,
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
                lease.record_installed(RouteKind::Ipv6SplitDefault, &route);
                installed.push(route);
            }
            Err(e) => warn!("安装 IPv6 split-default 路由 {} 失败：{e}", route),
        }
    }
}
