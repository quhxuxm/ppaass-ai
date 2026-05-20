use super::network::parse_cidr_v6;
use crate::error::{AgentError, Result};
use common::BindInterface;
use route_manager::{Route, RouteManager};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

const ROUTE_STATE_VERSION: u8 = 1;
const ROUTE_STATE_FILE_NAME: &str = "tun-routes.json";

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
}

impl RouteGuard {
    /// 先安装代理 /32 旁路路由，再安装指向 TUN 的 split-default 路由。
    /// 顺序很重要：旁路路由必须先于默认重定向存在，否则内核无法到达代理。
    pub(super) fn install(
        tun_if_index: u32,
        tun_ipv4: Ipv4Addr,
        tun_ipv6_cidr: Option<&str>,
        route_state_file: Option<&str>,
        proxy_ips: &[IpAddr],
    ) -> Result<Self> {
        let mut mgr = RouteManager::new()
            .map_err(|e| AgentError::Connection(format!("RouteManager 初始化失败：{e}")))?;
        let mut lease = RouteLease::new(route_state_file);

        lease.cleanup_stale_routes(&mut mgr);

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
        })
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
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
    Ipv4SplitDefault,
    Ipv6SplitDefault,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RouteRecord {
    kind: RouteKind,
    destination: IpAddr,
    prefix: u8,
    gateway: Option<IpAddr>,
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
        Self {
            kind,
            destination: route.destination(),
            prefix: route.prefix(),
            gateway: route.gateway(),
            if_index: route.if_index(),
        }
    }

    fn to_route(&self) -> Route {
        let mut route = Route::new(self.destination, self.prefix);
        if let Some(gateway) = self.gateway {
            route = route.with_gateway(gateway);
        }
        if let Some(if_index) = self.if_index {
            route = route.with_if_index(if_index);
        }
        route
    }

    fn matches_route(&self, route: &Route) -> bool {
        route.destination() == self.destination
            && route.prefix() == self.prefix
            && route.gateway() == self.gateway
            && self
                .if_index
                .is_none_or(|if_index| route.if_index() == Some(if_index))
    }
}

fn delete_recorded_route(mgr: &mut RouteManager, record: &RouteRecord) -> bool {
    let route = record.to_route();
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

#[cfg(target_os = "macos")]
fn delete_route_with_platform_tool(record: &RouteRecord) -> bool {
    let mut command = Command::new("route");
    command.arg("-n").arg("delete");

    match record.destination {
        IpAddr::V4(ip) if record.prefix == 32 => {
            command.arg("-host").arg(ip.to_string());
        }
        IpAddr::V4(ip) => {
            command.arg("-net").arg(format!("{ip}/{}", record.prefix));
        }
        IpAddr::V6(ip) if record.prefix == 128 => {
            command.arg("-inet6").arg("-host").arg(ip.to_string());
        }
        IpAddr::V6(ip) => {
            command
                .arg("-inet6")
                .arg("-net")
                .arg(format!("{ip}/{}", record.prefix));
        }
    }

    run_route_cleanup_command(command)
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

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn delete_route_with_platform_tool(_record: &RouteRecord) -> bool {
    false
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
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
    best_route(routes, dst)
        .map(|route| (route.gateway(), route.if_index()))
        .unwrap_or((fallback_gateway, fallback_if_index))
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
