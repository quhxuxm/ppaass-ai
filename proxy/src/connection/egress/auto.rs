use super::source::iface_addr_matches_dst;
use if_addrs::get_if_addrs;
use route_manager::{Route, RouteManager};
use std::io;
use std::net::{IpAddr, SocketAddr};
use tracing::{debug, info};

pub(super) struct AutoInterfaceSelector {
    routes: Vec<Route>,
}

impl AutoInterfaceSelector {
    pub(super) fn new() -> io::Result<Self> {
        let mut manager = RouteManager::new()
            .map_err(|e| io::Error::other(format!("RouteManager 初始化失败：{e}")))?;
        let routes = manager
            .list()
            .map_err(|e| io::Error::other(format!("读取路由表失败：{e}")))?;
        debug!("proxy 启动时读取的本机路由表：{routes:#?}");
        info!("已缓存 proxy 启动时的路由表，共 {} 条", routes.len());
        Ok(Self { routes })
    }

    pub(super) fn interface_for_dst(&self, dst: SocketAddr) -> io::Result<String> {
        auto_interface_for_dst(&self.routes, dst.ip())
    }
}

pub(super) fn is_auto_interface(interface: &str) -> bool {
    interface.eq_ignore_ascii_case("auto")
}

fn auto_interface_for_dst(routes: &[Route], dst_ip: IpAddr) -> io::Result<String> {
    let route = default_route(routes, dst_ip.is_ipv6()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("没有找到用于 auto 出站设备选择的默认路由：{dst_ip}"),
        )
    })?;

    interface_name_for_route(route, dst_ip)
}

fn default_route(routes: &[Route], want_v6: bool) -> Option<&Route> {
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
    Ok(get_if_addrs()?
        .into_iter()
        .any(|iface| iface.name == name && iface_addr_matches_dst(&iface.addr, dst_ip)))
}
