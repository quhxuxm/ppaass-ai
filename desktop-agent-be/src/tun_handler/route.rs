#[cfg(target_os = "macos")]
use super::dns::SystemDnsServer;
use super::dns::{flush_system_dns_cache, system_dns_servers};
use super::network::parse_cidr_v6;
use crate::error::{AgentError, Result};
use common::BindInterface;
use route_manager::{Route, RouteManager};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

const ROUTE_STATE_VERSION: u8 = 1;
const ROUTE_STATE_FILE_NAME: &str = "tun-routes.json";
#[cfg(target_os = "macos")]
const PF_DNS_ANCHOR: &str = "com.apple/ppaass-ai-tun-dns";

#[derive(Debug, Clone)]
pub(super) struct ProxyRoute {
    pub(super) local_ip: IpAddr,
    pub(super) bind_interface: Option<BindInterface>,
}

pub(super) fn cleanup_stale_routes(route_state_file: Option<&str>) {
    let mut mgr = match RouteManager::new() {
        Ok(mgr) => mgr,
        Err(e) => {
            warn!("RouteManager 初始化失败，无法预清理遗留 TUN 路由：{e}");
            return;
        }
    };
    RouteLease::new(route_state_file).cleanup_stale_routes(&mut mgr);
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
    lease: RouteLease,
    #[cfg(target_os = "macos")]
    pf_dns_guard: Option<MacosPfDnsGuard>,
}

impl RouteGuard {
    /// 先安装代理 /32 旁路路由，再安装指向 TUN 的 split-default 路由。
    /// 顺序很重要：旁路路由必须先于默认重定向存在，否则内核无法到达代理。
    pub(super) fn install(
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
            #[cfg(target_os = "macos")]
            {
                pf_dns_guard =
                    MacosPfDnsGuard::install(tun_if_index, _dns_capture_target, &dns_servers);
            }
            flush_system_dns_cache();
        }

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

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum RouteKind {
    ProxyBypass,
    DnsCapture,
    Ipv4SplitDefault,
    Ipv6SplitDefault,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RouteRecord {
    kind: RouteKind,
    destination: IpAddr,
    prefix: u8,
    gateway: Option<IpAddr>,
    #[serde(default)]
    if_name: Option<String>,
    if_index: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RouteState {
    version: u8,
    pid: u32,
    created_unix_secs: u64,
    routes: Vec<RouteRecord>,
}

struct RouteLease {
    path: PathBuf,
    state: RouteState,
    persist_failed: bool,
}

impl RouteLease {
    fn new(route_state_file: Option<&str>) -> Self {
        Self {
            path: route_state_file_path(route_state_file),
            state: RouteState {
                version: ROUTE_STATE_VERSION,
                pid: std::process::id(),
                created_unix_secs: now_unix_secs(),
                routes: Vec::new(),
            },
            persist_failed: false,
        }
    }

    fn cleanup_stale_routes(&self, mgr: &mut RouteManager) {
        let state = match fs::read_to_string(&self.path) {
            Ok(content) => match serde_json::from_str::<RouteState>(&content) {
                Ok(state) => state,
                Err(e) => {
                    warn!(
                        "TUN 路由状态文件 {} 解析失败，将移除该文件：{e}",
                        self.path.display()
                    );
                    remove_file_if_exists(&self.path);
                    return;
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                warn!("读取 TUN 路由状态文件 {} 失败：{e}", self.path.display());
                return;
            }
        };

        if state.routes.is_empty() {
            remove_file_if_exists(&self.path);
            return;
        }

        info!(
            "发现上次 TUN 模式遗留的路由状态文件：{}，准备清理 {} 条路由",
            self.path.display(),
            state.routes.len()
        );

        let mut cleanup_ok = true;
        for record in state.routes.iter().rev() {
            if !delete_recorded_route(mgr, record) {
                cleanup_ok = false;
            }
        }

        if cleanup_ok {
            remove_file_if_exists(&self.path);
            info!("上次遗留的 TUN 路由已清理完成");
        } else {
            warn!(
                "上次遗留的部分 TUN 路由未能清理，保留状态文件以便下次重试：{}",
                self.path.display()
            );
        }
    }

    fn record_installed(&mut self, kind: RouteKind, route: &Route) {
        self.state.routes.push(RouteRecord::from_route(kind, route));
        if let Err(e) = self.persist() {
            self.persist_failed = true;
            warn!("写入 TUN 路由状态文件 {} 失败：{e}", self.path.display());
        }
    }

    fn persist(&self) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_vec_pretty(&self.state).map_err(std::io::Error::other)?;
        let tmp_path = self
            .path
            .with_extension(format!("json.tmp.{}", std::process::id()));
        fs::write(&tmp_path, data)?;
        #[cfg(windows)]
        if self.path.exists() {
            fs::remove_file(&self.path)?;
        }
        fs::rename(tmp_path, &self.path)
    }

    fn clear(&mut self) {
        if self.persist_failed {
            debug!(
                "TUN 路由状态文件此前写入失败，无需清理：{}",
                self.path.display()
            );
        }
        remove_file_if_exists(&self.path);
        self.state.routes.clear();
    }
}

impl RouteRecord {
    fn from_route(kind: RouteKind, route: &Route) -> Self {
        let if_name = route.if_name().cloned();
        #[cfg(target_os = "macos")]
        let if_name = if_name.or_else(|| interface_name_for_index(route.if_index()));

        Self {
            kind,
            destination: route.destination(),
            prefix: route.prefix(),
            gateway: route.gateway(),
            if_name,
            if_index: route.if_index(),
        }
    }

    fn to_route(&self) -> Route {
        let mut route = Route::new(self.destination, self.prefix);
        if let Some(gateway) = self.gateway {
            route = route.with_gateway(gateway);
        }
        #[cfg(target_os = "macos")]
        if let Some(if_name) = &self.if_name {
            route = route.with_if_name(if_name.clone());
        }
        if let Some(if_index) = self.if_index {
            route = route.with_if_index(if_index);
        }
        route
    }

    fn matches_route(&self, route: &Route) -> bool {
        route.destination() == self.destination
            && route.prefix() == self.prefix
            && gateways_match(self.gateway, route.gateway(), self.destination)
            && interfaces_match(self, route)
    }
}

fn gateways_match(recorded: Option<IpAddr>, actual: Option<IpAddr>, destination: IpAddr) -> bool {
    match (recorded, actual) {
        (Some(recorded), Some(actual)) => recorded == actual,
        (None, None) => true,
        (None, Some(actual)) => is_unspecified_gateway(actual, destination),
        (Some(recorded), None) => is_unspecified_gateway(recorded, destination),
    }
}

fn is_unspecified_gateway(gateway: IpAddr, destination: IpAddr) -> bool {
    gateway.is_ipv4() == destination.is_ipv4()
        && match gateway {
            IpAddr::V4(ip) => ip.is_unspecified(),
            IpAddr::V6(ip) => ip.is_unspecified(),
        }
}

fn interfaces_match(record: &RouteRecord, route: &Route) -> bool {
    let index_matches = record
        .if_index
        .zip(route.if_index())
        .is_some_and(|(expected, actual)| expected == actual);
    let name_matches = record
        .if_name
        .as_deref()
        .zip(route.if_name().map(String::as_str))
        .is_some_and(|(expected, actual)| expected == actual);

    match (record.if_index.is_some(), record.if_name.is_some()) {
        (false, false) => true,
        (true, false) => index_matches,
        (false, true) => name_matches,
        (true, true) => index_matches || name_matches,
    }
}

fn delete_recorded_route(mgr: &mut RouteManager, record: &RouteRecord) -> bool {
    let route = record.to_route();
    if let Some(matches) = matching_routes(mgr, record)
        && matches.is_empty()
    {
        debug!("TUN 路由已不存在：{}", route);
        return true;
    }

    #[cfg(target_os = "macos")]
    if delete_route_with_platform_tool(record) && !recorded_route_exists(mgr, record) {
        return true;
    }

    match mgr.delete(&route) {
        Ok(()) => {
            if !recorded_route_exists(mgr, record) {
                debug!("已清理 TUN 路由：{}", route);
                return true;
            }
            debug!("删除 TUN 路由 {} 返回成功，但路由表中仍存在匹配条目", route);
        }
        Err(e) => {
            debug!(
                "按状态文件直接删除路由 {} 失败，将检查当前路由表：{e}",
                route
            );
        }
    }

    if delete_matching_routes(mgr, record) && !recorded_route_exists(mgr, record) {
        return true;
    }

    #[cfg(not(target_os = "macos"))]
    if delete_route_with_platform_tool(record) && !recorded_route_exists(mgr, record) {
        return true;
    }

    warn!("删除 TUN 路由失败，路由表中仍存在匹配条目：{}", route);
    false
}

fn recorded_route_exists(mgr: &mut RouteManager, record: &RouteRecord) -> bool {
    match matching_routes(mgr, record) {
        Some(routes) => !routes.is_empty(),
        None => true,
    }
}

fn matching_routes(mgr: &mut RouteManager, record: &RouteRecord) -> Option<Vec<Route>> {
    match mgr.list() {
        Ok(routes) => Some(
            routes
                .into_iter()
                .filter(|candidate| record.matches_route(candidate))
                .collect(),
        ),
        Err(e) => {
            warn!("无法列出当前路由以确认 TUN 路由是否已删除：{e}");
            None
        }
    }
}

fn delete_matching_routes(mgr: &mut RouteManager, record: &RouteRecord) -> bool {
    let route = record.to_route();
    let matches = match matching_routes(mgr, record) {
        Some(matches) => matches,
        None => return false,
    };

    if matches.is_empty() {
        debug!("TUN 路由已不存在：{}", route);
        return true;
    }

    let mut deleted_all = true;
    for candidate in matches {
        match mgr.delete(&candidate) {
            Ok(()) => debug!("已按当前路由表条目清理 TUN 路由：{}", candidate),
            Err(e) => {
                deleted_all = false;
                warn!("删除当前路由表中的 TUN 路由 {} 失败：{e}", candidate);
            }
        }
    }
    deleted_all
}

fn cleanup_existing_tun_split_routes(mgr: &mut RouteManager, tun_if_index: u32) {
    let routes = [
        split_route_record(
            RouteKind::Ipv4SplitDefault,
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            1,
            tun_if_index,
        ),
        split_route_record(
            RouteKind::Ipv4SplitDefault,
            IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)),
            1,
            tun_if_index,
        ),
        split_route_record(
            RouteKind::Ipv6SplitDefault,
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            1,
            tun_if_index,
        ),
        split_route_record(
            RouteKind::Ipv6SplitDefault,
            IpAddr::V6(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)),
            1,
            tun_if_index,
        ),
    ];

    for record in routes {
        let _ = delete_recorded_route(mgr, &record);
    }
}

fn split_route_record(
    kind: RouteKind,
    destination: IpAddr,
    prefix: u8,
    tun_if_index: u32,
) -> RouteRecord {
    let if_name = None;
    #[cfg(target_os = "macos")]
    let if_name = if_name.or_else(|| interface_name_for_index(Some(tun_if_index)));

    RouteRecord {
        kind,
        destination,
        prefix,
        gateway: None,
        if_name,
        if_index: Some(tun_if_index),
    }
}

#[cfg(target_os = "macos")]
fn delete_route_with_platform_tool(record: &RouteRecord) -> bool {
    let if_name = record
        .if_name
        .clone()
        .or_else(|| interface_name_for_index(record.if_index));

    if let Some(if_name) = if_name.as_deref()
        && run_route_cleanup_command(macos_route_delete_command(record, Some(if_name), false))
    {
        return true;
    }

    if record.gateway.is_some()
        && let Some(if_name) = if_name.as_deref()
        && run_route_cleanup_command(macos_route_delete_command(record, Some(if_name), true))
    {
        return true;
    }

    if record.gateway.is_some()
        && run_route_cleanup_command(macos_route_delete_command(record, None, true))
    {
        return true;
    }

    run_route_cleanup_command(macos_route_delete_command(record, None, false))
}

#[cfg(target_os = "macos")]
fn macos_route_delete_command(
    record: &RouteRecord,
    if_scope: Option<&str>,
    include_gateway: bool,
) -> Command {
    let mut command = Command::new("route");
    command.arg("-n").arg("delete");
    if record.destination.is_ipv6() {
        command.arg("-inet6");
    }
    command.arg(if route_record_is_host(record) {
        "-host"
    } else {
        "-net"
    });
    if let Some(if_scope) = if_scope {
        command.arg("-ifscope").arg(if_scope);
    }
    command.arg(route_destination_arg(record));
    if include_gateway
        && let Some(gateway) = record.gateway
        && !is_unspecified_gateway(gateway, record.destination)
    {
        command.arg(gateway.to_string());
    }
    command
}

#[cfg(target_os = "linux")]
fn delete_route_with_platform_tool(record: &RouteRecord) -> bool {
    let mut command = Command::new("ip");
    if record.destination.is_ipv6() {
        command.arg("-6");
    }
    command
        .arg("route")
        .arg("del")
        .arg(format!("{}/{}", record.destination, record.prefix));

    run_route_cleanup_command(command)
}

#[cfg(target_os = "macos")]
fn route_record_is_host(record: &RouteRecord) -> bool {
    (record.destination.is_ipv4() && record.prefix == 32)
        || (record.destination.is_ipv6() && record.prefix == 128)
}

#[cfg(target_os = "macos")]
fn route_destination_arg(record: &RouteRecord) -> String {
    if route_record_is_host(record) {
        record.destination.to_string()
    } else {
        format!("{}/{}", record.destination, record.prefix)
    }
}

#[cfg(windows)]
fn delete_route_with_platform_tool(record: &RouteRecord) -> bool {
    let mut command = Command::new("powershell.exe");
    let destination_prefix = format!("{}/{}", record.destination, record.prefix);
    let interface_index = record
        .if_index
        .map(|if_index| if_index.to_string())
        .unwrap_or_default();
    let next_hop = record
        .gateway
        .filter(|gateway| !is_unspecified_gateway(*gateway, record.destination))
        .map(|gateway| gateway.to_string())
        .unwrap_or_default();
    let script = r#"
$DestinationPrefix = $args[0]
$InterfaceIndex = $args[1]
$NextHop = $args[2]
$filter = @{
    DestinationPrefix = $DestinationPrefix
    ErrorAction = 'SilentlyContinue'
}
if (-not [string]::IsNullOrWhiteSpace($InterfaceIndex)) {
    $filter.InterfaceIndex = [uint32]$InterfaceIndex
}
if (-not [string]::IsNullOrWhiteSpace($NextHop)) {
    $filter.NextHop = $NextHop
}
$routes = @(Get-NetRoute @filter)
foreach ($route in $routes) {
    $route | Remove-NetRoute -Confirm:$false -ErrorAction Stop
}
"#;
    let command_script = format!("& {{\n{script}\n}}");
    command
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-Command")
        .arg(command_script)
        .arg(destination_prefix)
        .arg(interface_index)
        .arg(next_hop);

    run_route_cleanup_command(command)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn delete_route_with_platform_tool(_record: &RouteRecord) -> bool {
    false
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn run_route_cleanup_command(mut command: Command) -> bool {
    debug!("运行路由清理命令：{:?}", command);
    match command.status() {
        Ok(status) if status.success() => true,
        Ok(status) => {
            debug!("路由清理命令退出状态：{status}");
            false
        }
        Err(e) => {
            debug!("运行路由清理命令失败：{e}");
            false
        }
    }
}

fn route_state_file_path(configured_file: Option<&str>) -> PathBuf {
    if let Some(path) = std::env::var_os("PPAASS_TUN_ROUTE_STATE") {
        return PathBuf::from(path);
    }

    let configured_file = configured_file
        .map(str::trim)
        .filter(|file| !file.is_empty())
        .unwrap_or(ROUTE_STATE_FILE_NAME);
    let path = PathBuf::from(configured_file);
    if path.is_absolute() {
        return path;
    }

    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(path)
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn remove_file_if_exists(path: &Path) {
    match fs::remove_file(path) {
        Ok(()) => debug!("已删除 TUN 路由状态文件：{}", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!("删除 TUN 路由状态文件 {} 失败：{e}", path.display()),
    }
}

struct DnsCaptureRouteContext<'a> {
    tun_if_index: u32,
    dns_ips: &'a [IpAddr],
    proxy_ips: &'a [IpAddr],
    default_v4_gateway: Option<IpAddr>,
    default_v6_gateway: Option<IpAddr>,
}

fn install_dns_capture_routes(
    mgr: &mut RouteManager,
    context: DnsCaptureRouteContext<'_>,
    installed: &mut Vec<Route>,
    lease: &mut RouteLease,
) {
    let DnsCaptureRouteContext {
        tun_if_index,
        dns_ips,
        proxy_ips,
        default_v4_gateway,
        default_v6_gateway,
    } = context;

    if dns_ips.is_empty() {
        debug!("TUN proxy_dns 未发现可捕获的系统 DNS 服务器地址");
        return;
    }

    for ip in dns_ips {
        if proxy_ips.contains(ip) {
            debug!("系统 DNS {ip} 同时也是代理地址，跳过 DNS 捕获路由");
            continue;
        }
        if dns_capture_route_targets_default_gateway(*ip, default_v4_gateway, default_v6_gateway) {
            warn!("系统 DNS {ip} 同时也是默认网关，跳过普通 DNS 捕获路由以避免网络中断");
            continue;
        }

        let route = match ip {
            IpAddr::V4(ip) => Route::new(IpAddr::V4(*ip), 32).with_if_index(tun_if_index),
            IpAddr::V6(ip) => Route::new(IpAddr::V6(*ip), 128).with_if_index(tun_if_index),
        };
        match mgr.add(&route) {
            Ok(()) => {
                info!("已安装系统 DNS 捕获路由（不修改系统 DNS）：{}", route);
                lease.record_installed(RouteKind::DnsCapture, &route);
                installed.push(route);
            }
            Err(e) => warn!("安装系统 DNS 捕获路由 {} 失败：{e}", route),
        }
    }
}

fn dns_capture_route_targets_default_gateway(
    ip: IpAddr,
    default_v4_gateway: Option<IpAddr>,
    default_v6_gateway: Option<IpAddr>,
) -> bool {
    Some(ip) == default_v4_gateway || Some(ip) == default_v6_gateway
}

#[cfg(target_os = "macos")]
struct MacosPfDnsGuard {
    token: Option<String>,
}

#[cfg(target_os = "macos")]
impl MacosPfDnsGuard {
    fn install(
        tun_if_index: u32,
        dns_capture_target: Ipv4Addr,
        dns_servers: &[SystemDnsServer],
    ) -> Option<Self> {
        let tun_if_name = interface_name_for_index(Some(tun_if_index))?;
        let rules = macos_pf_dns_rules(&tun_if_name, dns_capture_target, dns_servers);
        if rules.trim().is_empty() {
            debug!("macOS TUN proxy_dns 未发现需要 PF 捕获的 scoped DNS");
            return None;
        }

        let token = match macos_pf_enable() {
            Ok(token) => token,
            Err(e) => {
                warn!("启用 macOS PF 以捕获 scoped DNS 失败：{e}");
                return None;
            }
        };

        let path = std::env::temp_dir().join(format!(
            "ppaass-tun-dns-pf-{}-{}.conf",
            std::process::id(),
            now_unix_secs()
        ));
        if let Err(e) = fs::write(&path, &rules) {
            warn!("写入 macOS PF DNS 规则失败：{}：{e}", path.display());
            macos_pf_release_token(token.as_deref());
            return None;
        }

        let load_result = Command::new("/sbin/pfctl")
            .args(["-a", PF_DNS_ANCHOR, "-f"])
            .arg(&path)
            .output();
        let _ = fs::remove_file(&path);

        match load_result {
            Ok(output) if output.status.success() => {
                info!("已安装 macOS scoped DNS 捕获规则（不修改系统 DNS）");
                Some(Self { token })
            }
            Ok(output) => {
                warn!(
                    "安装 macOS PF DNS 捕获规则失败：{}",
                    command_output_message(&output)
                );
                macos_pf_flush_anchor();
                macos_pf_release_token(token.as_deref());
                None
            }
            Err(e) => {
                warn!("运行 pfctl 安装 DNS 捕获规则失败：{e}");
                macos_pf_release_token(token.as_deref());
                None
            }
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacosPfDnsGuard {
    fn drop(&mut self) {
        macos_pf_flush_anchor();
        macos_pf_release_token(self.token.as_deref());
    }
}

#[cfg(target_os = "macos")]
fn macos_pf_dns_rules(
    tun_if_name: &str,
    dns_capture_target: Ipv4Addr,
    dns_servers: &[SystemDnsServer],
) -> String {
    let mut rules = String::new();
    for server in dns_servers {
        let IpAddr::V4(dns_ip) = server.ip else {
            continue;
        };
        let Some(interface_name) = server.interface_name.as_deref() else {
            continue;
        };
        if interface_name == tun_if_name {
            continue;
        }
        rules.push_str(&format!(
            "pass out quick on {interface_name} route-to ({tun_if_name} {dns_capture_target}) inet proto {{ udp tcp }} from any to {dns_ip} port = 53 keep state\n"
        ));
    }
    rules
}

#[cfg(target_os = "macos")]
fn macos_pf_enable() -> std::io::Result<Option<String>> {
    let output = Command::new("/sbin/pfctl").arg("-E").output()?;
    if !output.status.success() {
        return Err(std::io::Error::other(command_output_message(&output)));
    }
    Ok(parse_pf_token(&output))
}

#[cfg(target_os = "macos")]
fn parse_pf_token(output: &std::process::Output) -> Option<String> {
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    combined.lines().find_map(|line| {
        let (_, token) = line.split_once("Token")?;
        let token = token.trim_start_matches([' ', ':']).trim();
        (!token.is_empty()).then(|| token.to_string())
    })
}

#[cfg(target_os = "macos")]
fn macos_pf_flush_anchor() {
    let _ = Command::new("/sbin/pfctl")
        .args(["-a", PF_DNS_ANCHOR, "-F", "all"])
        .output()
        .map_err(|e| debug!("清理 macOS PF DNS anchor 失败：{e}"));
}

#[cfg(target_os = "macos")]
fn macos_pf_release_token(token: Option<&str>) {
    let Some(token) = token else {
        return;
    };
    let _ = Command::new("/sbin/pfctl")
        .args(["-X", token])
        .output()
        .map_err(|e| debug!("释放 macOS PF enable token 失败：{e}"));
}

#[cfg(target_os = "macos")]
fn command_output_message(output: &std::process::Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() {
        if stdout.is_empty() {
            output.status.to_string()
        } else {
            stdout
        }
    } else {
        stderr
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

/// 在 `routes` 中找到第一条非 TUN 的默认路由。
/// 返回 (网关, if_index) 以供安装旁路路由使用。
/// `want_v6 == true` 时查找 ::/0 而非 0.0.0.0/0。
fn find_default_route(routes: &[Route], want_v6: bool) -> (Option<IpAddr>, Option<u32>) {
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
        .map(|route| (route.gateway(), route.if_index()))
        .unwrap_or((None, None))
}

fn route_next_hop(
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
fn parse_macos_route_get_next_hop(output: &str) -> Option<(Option<IpAddr>, Option<u32>)> {
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
fn interface_name_for_index(if_index: Option<u32>) -> Option<String> {
    let if_index = if_index?;
    if_addrs::get_if_addrs()
        .ok()?
        .into_iter()
        .find(|interface| interface.index == Some(if_index))
        .map(|interface| interface.name)
}

#[cfg(target_os = "macos")]
fn interface_index_for_name(name: &str) -> Option<u32> {
    if_addrs::get_if_addrs()
        .ok()?
        .into_iter()
        .find(|interface| interface.name == name)
        .and_then(|interface| interface.index)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(
        destination: IpAddr,
        prefix: u8,
        gateway: Option<IpAddr>,
        if_index: Option<u32>,
    ) -> RouteRecord {
        RouteRecord {
            kind: RouteKind::Ipv4SplitDefault,
            destination,
            prefix,
            gateway,
            if_name: None,
            if_index,
        }
    }

    #[test]
    fn matches_windows_unspecified_ipv4_gateway_for_on_link_route() {
        let record = record(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1, None, Some(42));
        let route = Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1)
            .with_if_index(42)
            .with_gateway(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

        assert!(record.matches_route(&route));
    }

    #[test]
    fn matches_windows_unspecified_ipv6_gateway_for_on_link_route() {
        let record = record(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1, None, Some(42));
        let route = Route::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1)
            .with_if_index(42)
            .with_gateway(IpAddr::V6(Ipv6Addr::UNSPECIFIED));

        assert!(record.matches_route(&route));
    }

    #[test]
    fn rejects_different_real_gateway() {
        let record = record(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            32,
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            Some(7),
        );
        let route = Route::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 32)
            .with_if_index(7)
            .with_gateway(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254)));

        assert!(!record.matches_route(&route));
    }

    #[test]
    fn matches_route_by_interface_name_when_index_changes() {
        let mut record = record(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1, None, Some(42));
        record.if_name = Some("utun9".to_string());
        let mut route = Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1).with_if_index(77);
        route = route.with_if_name("utun9".to_string());

        assert!(record.matches_route(&route));
    }

    #[test]
    fn skips_dns_capture_route_when_dns_is_default_gateway() {
        let gateway = IpAddr::V4(Ipv4Addr::new(192, 168, 31, 1));

        assert!(dns_capture_route_targets_default_gateway(
            gateway,
            Some(gateway),
            None
        ));
    }

    #[test]
    fn allows_dns_capture_route_when_dns_is_not_default_gateway() {
        let dns = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let gateway = IpAddr::V4(Ipv4Addr::new(192, 168, 31, 1));

        assert!(!dns_capture_route_targets_default_gateway(
            dns,
            Some(gateway),
            None
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parses_macos_route_get_gateway_even_when_interface_is_unknown() {
        let output = r#"
   route to: 140.82.30.214
destination: 140.82.30.214
    gateway: 192.168.31.1
  interface: test999
"#;

        assert_eq!(
            parse_macos_route_get_next_hop(output),
            Some((Some(IpAddr::V4(Ipv4Addr::new(192, 168, 31, 1))), None))
        );
    }
}
