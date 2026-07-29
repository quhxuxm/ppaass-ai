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

pub(crate) struct RouteGuardInstall<'a> {
    pub(crate) tun_if_index: u32,
    pub(crate) tun_ipv4: Ipv4Addr,
    pub(crate) dns_capture_target: Ipv4Addr,
    pub(crate) tun_ipv6_cidr: Option<&'a str>,
    pub(crate) route_state_file: Option<&'a str>,
    pub(crate) proxy_ips: &'a [IpAddr],
    pub(crate) capture_system_dns: bool,
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
        let install = RouteGuardInstall {
            tun_if_index,
            tun_ipv4,
            dns_capture_target: _dns_capture_target,
            tun_ipv6_cidr,
            route_state_file,
            proxy_ips,
            capture_system_dns,
        };
        #[cfg(target_os = "macos")]
        {
            let mut ignore_pf_token = |_token: Option<&str>| Ok(());
            Self::install_with_pf_token_observer(install, &mut ignore_pf_token)
        }
        #[cfg(not(target_os = "macos"))]
        Self::install_inner(install)
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn install_with_pf_token_observer(
        install: RouteGuardInstall<'_>,
        pf_token_observer: &mut dyn FnMut(Option<&str>) -> Result<()>,
    ) -> Result<Self> {
        Self::install_inner(install, pf_token_observer)
    }

    fn install_inner(
        install: RouteGuardInstall<'_>,
        #[cfg(target_os = "macos")] pf_token_observer: &mut dyn FnMut(Option<&str>) -> Result<()>,
    ) -> Result<Self> {
        let RouteGuardInstall {
            tun_if_index,
            tun_ipv4,
            dns_capture_target,
            tun_ipv6_cidr,
            route_state_file,
            proxy_ips,
            capture_system_dns,
        } = install;
        #[cfg(not(target_os = "macos"))]
        let _ = dns_capture_target;
        let mut mgr = RouteManager::new()
            .map_err(|e| AgentError::Connection(format!("RouteManager 初始化失败：{e}")))?;
        let lease = RouteLease::new(route_state_file);
        // Do this before constructing RouteGuard. If strict stale cleanup
        // fails, a partially initialized guard must not delete the very state
        // file needed for the next deterministic recovery attempt.
        lease.cleanup_stale_routes(&mut mgr)?;
        let mut guard = Self {
            mgr,
            installed: Vec::new(),
            lease,
            #[cfg(target_os = "macos")]
            pf_dns_guard: None,
        };

        cleanup_existing_tun_split_routes(&mut guard.mgr, tun_if_index);

        let routes = match guard.mgr.list() {
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

        for ip in proxy_ips {
            // 给每个 proxy IP 安装最具体的主机路由，使 agent 到 proxy 绕过 TUN。
            let route = match ip {
                IpAddr::V4(v4) => {
                    let (gateway, if_index) =
                        proxy_bypass_next_hop(&routes, *ip, default_v4_gw, default_v4_if);
                    #[cfg(target_os = "macos")]
                    validate_macos_proxy_bypass_next_hop(*ip, tun_if_index, if_index)?;
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
                        proxy_bypass_next_hop(&routes, *ip, default_v6_gw, default_v6_if);
                    #[cfg(target_os = "macos")]
                    validate_macos_proxy_bypass_next_hop(*ip, tun_if_index, if_index)?;
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
            match guard.mgr.add(&route) {
                Ok(()) => {
                    info!("已安装代理旁路路由：{}", route);
                    guard
                        .lease
                        .record_installed(RouteKind::ProxyBypass, &route)?;
                    guard.installed.push(route);
                }
                Err(e) => {
                    #[cfg(target_os = "macos")]
                    {
                        let message = e.to_string();
                        if route_add_error_is_already_exists(&message)
                            && required_route_exists(
                                &mut guard.mgr,
                                RouteKind::ProxyBypass,
                                &route,
                            )?
                        {
                            info!("代理旁路路由已存在并验证正确，接管到当前 lease：{}", route);
                            guard
                                .lease
                                .record_installed(RouteKind::ProxyBypass, &route)?;
                            guard.installed.push(route);
                            continue;
                        }
                        return Err(AgentError::Connection(format!(
                            "为 {ip} 安装必要的代理旁路路由 {route} 失败：{message}"
                        )));
                    }
                    #[cfg(not(target_os = "macos"))]
                    warn!("为 {ip} 安装旁路路由失败：{e}");
                }
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
                    &mut guard.mgr,
                    DnsCaptureRouteContext {
                        tun_if_index,
                        dns_ips: &dns_capture_ips,
                        proxy_ips,
                        default_v4_gateway: default_v4_gw,
                        default_v6_gateway: default_v6_gw,
                    },
                    &mut guard.installed,
                    &mut guard.lease,
                )?;
            } else {
                debug!("当前平台使用专用 DNS 接管机制，不安装系统 DNS host route");
            }
            #[cfg(target_os = "macos")]
            {
                guard.pf_dns_guard = Some(MacosPfDnsGuard::install(
                    tun_if_index,
                    dns_capture_target,
                    &dns_servers,
                    &macos_default_dns_interfaces(default_v4_if, default_v6_if),
                    pf_token_observer,
                )?);
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
            &mut guard.mgr,
            default_v4_gw,
            default_v4_if,
            &mut guard.installed,
            &mut guard.lease,
        )?;

        // split-default 将公网流量分成两半导入 TUN，同时让更具体的旁路路由优先。
        install_ipv4_split_routes(
            &mut guard.mgr,
            tun_if_index,
            tun_ipv4,
            &mut guard.installed,
            &mut guard.lease,
        )?;
        install_ipv6_split_routes(
            &mut guard.mgr,
            tun_if_index,
            tun_ipv6_cidr,
            &mut guard.installed,
            &mut guard.lease,
        )?;

        Ok(guard)
    }

    pub(crate) fn cleanup(&mut self) -> Result<()> {
        let mut cleanup_errors = Vec::new();

        #[cfg(target_os = "macos")]
        if let Some(pf_dns_guard) = self.pf_dns_guard.as_mut() {
            match pf_dns_guard.cleanup() {
                Ok(()) => {
                    self.pf_dns_guard.take();
                }
                Err(err) => cleanup_errors.push(err.to_string()),
            }
        }

        info!(
            "正在恢复路由表：删除 {} 条已安装的路由",
            self.lease.state.routes.len()
        );
        let mut route_cleanup_ok = true;
        for record in self.lease.state.routes.iter().rev() {
            if !delete_recorded_route(&mut self.mgr, record) {
                route_cleanup_ok = false;
            }
        }
        self.installed.clear();
        if route_cleanup_ok {
            if let Err(err) = self.lease.clear() {
                cleanup_errors.push(format!(
                    "删除 TUN 路由状态文件 {} 失败：{err}",
                    self.lease.path.display()
                ));
            }
        } else {
            cleanup_errors.push(format!(
                "部分 TUN 路由未能删除，保留路由状态文件以便重试：{}",
                self.lease.path.display()
            ));
        }

        if cleanup_errors.is_empty() {
            Ok(())
        } else {
            Err(AgentError::Connection(cleanup_errors.join("；")))
        }
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        if let Err(err) = self.cleanup() {
            warn!("TUN route guard 析构清理失败：{err}");
        }
    }
}

mod bypass;
mod macos;
mod split;

#[cfg(not(test))]
use bypass::route_add_error_is_already_exists;
#[cfg(target_os = "macos")]
use bypass::validate_macos_proxy_bypass_next_hop;
use bypass::{install_local_network_bypass_routes, proxy_bypass_next_hop};
#[cfg(test)]
pub(super) use bypass::{
    local_network_bypass_routes, proxy_bypass_next_hop_from_routes,
    route_add_error_is_already_exists,
};
#[cfg(target_os = "macos")]
use macos::install_macos_scoped_default_bypass;
#[cfg(all(test, target_os = "macos"))]
pub(super) use macos::macos_scoped_default_command;
pub(super) use macos::refresh_macos_scoped_default_bypass;
#[cfg(test)]
pub(super) use split::route_list_contains_expected;
use split::{install_ipv4_split_routes, install_ipv6_split_routes, required_route_exists};
