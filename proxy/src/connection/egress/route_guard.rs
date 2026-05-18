use std::io;
#[cfg(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
))]
use std::net::IpAddr;
use std::net::SocketAddr;

#[cfg(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
))]
use route_manager::{Route, RouteManager};

#[cfg(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
))]
use std::collections::HashMap;

#[cfg(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
))]
use std::sync::{LazyLock, Mutex};

#[cfg(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
))]
static ROUTE_REFS: LazyLock<Mutex<HashMap<RouteKey, usize>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
))]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct RouteKey {
    destination: IpAddr,
    prefix: u8,
    gateway: Option<IpAddr>,
    if_index: u32,
}

#[cfg(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
))]
pub(super) struct TargetRouteGuard {
    key: RouteKey,
    route: Route,
}

#[cfg(not(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
)))]
pub(super) struct TargetRouteGuard;

#[cfg(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
))]
impl TargetRouteGuard {
    pub(super) fn install(
        interface: &str,
        interface_index: Option<u32>,
        dst: SocketAddr,
    ) -> io::Result<Option<Self>> {
        let interface_index = interface_index
            .ok_or_else(|| io::Error::other(format!("网络设备 {interface} 没有有效 if_index")))?;
        let dst_ip = dst.ip();
        let mut manager = RouteManager::new()?;
        let routes = manager.list()?;

        if best_route(&routes, dst_ip)
            .is_some_and(|route| route_matches_interface(route, interface, interface_index))
        {
            return Ok(None);
        }

        let base_route = best_interface_route(&routes, interface, interface_index, dst_ip)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    format!("网络设备 {interface} 没有到 {dst_ip} 的可用路由"),
                )
            })?;

        let prefix = host_prefix(dst_ip);
        let mut route = Route::new(dst_ip, prefix).with_if_index(interface_index);
        if let Some(gateway) = base_route.gateway() {
            route = route.with_gateway(gateway);
        }
        let key = RouteKey {
            destination: dst_ip,
            prefix,
            gateway: base_route.gateway(),
            if_index: interface_index,
        };

        let mut refs = ROUTE_REFS
            .lock()
            .map_err(|_| io::Error::other("目标旁路路由引用计数锁已损坏"))?;
        if let Some(count) = refs.get_mut(&key) {
            *count += 1;
            return Ok(Some(Self { key, route }));
        }

        match manager.add(&route) {
            Ok(()) => {
                refs.insert(key.clone(), 1);
                Ok(Some(Self { key, route }))
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(None),
            Err(err) => Err(io::Error::new(
                err.kind(),
                format!("为目标 {dst_ip} 安装出站旁路路由失败：{err}"),
            )),
        }
    }
}

#[cfg(not(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
)))]
impl TargetRouteGuard {
    pub(super) fn install(
        _interface: &str,
        _interface_index: Option<u32>,
        _dst: SocketAddr,
    ) -> io::Result<Option<Self>> {
        Ok(None)
    }
}

#[cfg(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
))]
impl Drop for TargetRouteGuard {
    fn drop(&mut self) {
        let Ok(mut refs) = ROUTE_REFS.lock() else {
            return;
        };
        let Some(count) = refs.get_mut(&self.key) else {
            return;
        };
        if *count > 1 {
            *count -= 1;
            return;
        }
        refs.remove(&self.key);
        if let Ok(mut manager) = RouteManager::new() {
            let _ = manager.delete(&self.route);
        }
    }
}

#[cfg(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
))]
fn best_route(routes: &[Route], dst: IpAddr) -> Option<&Route> {
    routes
        .iter()
        .filter(|route| route.destination().is_ipv4() == dst.is_ipv4() && route.contains(&dst))
        .max_by_key(|route| route.prefix())
}

#[cfg(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
))]
fn best_interface_route<'a>(
    routes: &'a [Route],
    interface: &str,
    interface_index: u32,
    dst: IpAddr,
) -> Option<&'a Route> {
    routes
        .iter()
        .filter(|route| {
            route.destination().is_ipv4() == dst.is_ipv4()
                && route.contains(&dst)
                && route_matches_interface(route, interface, interface_index)
        })
        .max_by_key(|route| route.prefix())
}

#[cfg(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
))]
fn route_matches_interface(route: &Route, interface: &str, interface_index: u32) -> bool {
    route.if_index() == Some(interface_index)
        || route.if_name().is_some_and(|name| name == interface)
}

#[cfg(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
))]
fn host_prefix(ip: IpAddr) -> u8 {
    if ip.is_ipv4() { 32 } else { 128 }
}
