use super::source::iface_addr_matches_dst;
use if_addrs::get_if_addrs;
use route_manager::{Route, RouteManager};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::RwLock;
use tracing::{debug, info, warn};

pub(super) struct AutoInterfaceSelector {
    routes: RwLock<Vec<Route>>,
}

impl AutoInterfaceSelector {
    pub(super) fn new() -> io::Result<Self> {
        // auto 模式先保存启动快照；连接时若快照不可用，会重新读取路由表。
        let routes = match read_routes() {
            Ok(routes) => {
                debug!("proxy 启动时读取的本机路由表：{routes:#?}");
                info!(
                    "已缓存 proxy 启动时的路由表，共 {} 条；连接时会在默认路由不可用时自动刷新",
                    routes.len()
                );
                routes
            }
            Err(err) => {
                warn!("proxy 启动时读取路由表失败，将在连接时重试 auto 出站设备选择：{err}");
                Vec::new()
            }
        };
        Ok(Self {
            routes: RwLock::new(routes),
        })
    }

    pub(super) fn interface_for_dst(&self, dst: SocketAddr) -> io::Result<String> {
        // 根据目标地址族，从缓存路由表里挑选对应的默认路由出口。
        // 登录自启时 macOS 可能先启动进程、后建立默认路由；缓存失效时刷新一次。
        let dst_ip = dst.ip();
        let cached_result = {
            let routes = self
                .routes
                .read()
                .map_err(|_| io::Error::other("auto 出站路由缓存锁已损坏"))?;
            auto_interface_for_dst(&routes, dst_ip)
        };
        match cached_result {
            Ok(interface) => return Ok(interface),
            Err(err) if should_refresh_routes(&err) => {
                debug!("auto 出站设备缓存不可用，准备刷新路由表：{err}");
            }
            Err(err) => return Err(err),
        }

        let routes = read_routes()?;
        let refreshed_result = auto_interface_for_dst(&routes, dst_ip);
        {
            let mut cached_routes = self
                .routes
                .write()
                .map_err(|_| io::Error::other("auto 出站路由缓存锁已损坏"))?;
            *cached_routes = routes;
        }

        match refreshed_result {
            Ok(interface) => {
                info!("auto 出站设备已刷新：dst={dst_ip} interface={interface}");
                Ok(interface)
            }
            Err(err) => Err(err),
        }
    }
}

pub(super) fn is_auto_interface(interface: &str) -> bool {
    interface.eq_ignore_ascii_case("auto")
}

fn auto_interface_for_dst(routes: &[Route], dst_ip: IpAddr) -> io::Result<String> {
    // IPv4 和 IPv6 各自匹配自己的默认路由，避免跨地址族选错出口。
    let route = default_route(routes, dst_ip.is_ipv6()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("没有找到用于 auto 出站设备选择的默认路由：{dst_ip}"),
        )
    })?;

    interface_name_for_route(route, dst_ip)
}

fn read_routes() -> io::Result<Vec<Route>> {
    let mut manager = RouteManager::new()
        .map_err(|e| io::Error::other(format!("RouteManager 初始化失败：{e}")))?;
    manager
        .list()
        .map_err(|e| io::Error::other(format!("读取路由表失败：{e}")))
}

fn should_refresh_routes(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::AddrNotAvailable
    )
}

fn default_route(routes: &[Route], want_v6: bool) -> Option<&Route> {
    // 默认路由要求前缀为 0 且 destination 是对应地址族的未指定地址。
    routes.iter().find(|route| {
        if route.prefix() != 0 {
            return false;
        }

        match route.destination() {
            IpAddr::V4(ip) => !want_v6 && ip.is_unspecified(),
            IpAddr::V6(ip) => want_v6 && ip.is_unspecified(),
        }
    })
}

fn interface_name_for_route(route: &Route, dst_ip: IpAddr) -> io::Result<String> {
    // route_manager 能直接提供设备名时，仍确认该设备有目标地址族可用地址。
    if let Some(name) = route.if_name()
        && interface_has_reachable_addr(name, dst_ip)?
    {
        return Ok(name.to_string());
    }

    let Some(index) = route.if_index() else {
        return Err(io::Error::other(format!(
            "默认路由没有可用于绑定的网络设备信息：{route}"
        )));
    };

    // 某些平台只有 if_index，需要回查网卡地址列表转换成设备名。
    let mut fallback = None;
    for iface in get_if_addrs()? {
        if iface.index != Some(index) {
            continue;
        }

        fallback.get_or_insert_with(|| iface.name.clone());
        if iface_addr_matches_dst(&iface.addr, dst_ip) {
            return Ok(iface.name);
        }
    }

    if let Some(name) = fallback {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("auto 选择的出站设备 {name} 没有匹配 {dst_ip} 地址族的本地地址"),
        ));
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("默认路由引用的网络设备 if_index={index} 不存在"),
    ))
}

fn interface_has_reachable_addr(name: &str, dst_ip: IpAddr) -> io::Result<bool> {
    // auto 选出的设备必须存在同地址族的可用源地址，后续才能成功 bind。
    Ok(get_if_addrs()?
        .into_iter()
        .any(|iface| iface.name == name && iface_addr_matches_dst(&iface.addr, dst_ip)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn default_route_uses_matching_address_family() {
        let routes = vec![
            Route::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).with_if_index(1),
            Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).with_if_index(2),
            Route::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0).with_if_index(3),
        ];

        assert_eq!(default_route(&routes, false).unwrap().if_index(), Some(2));
        assert_eq!(default_route(&routes, true).unwrap().if_index(), Some(3));
    }

    #[test]
    fn refreshes_for_missing_or_unusable_cached_routes() {
        assert!(should_refresh_routes(&io::Error::new(
            io::ErrorKind::NotFound,
            "missing default route",
        )));
        assert!(should_refresh_routes(&io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "interface has no address",
        )));
        assert!(!should_refresh_routes(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            "permission",
        )));
    }
}
