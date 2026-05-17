use if_addrs::{IfAddr, Ifv4Addr, Ifv6Addr, get_if_addrs};
#[cfg(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
))]
use route_manager::{Route, RouteManager};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
#[cfg(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
))]
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::num::NonZeroU32;
use std::pin::Pin;
#[cfg(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
))]
use std::sync::{LazyLock, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

pub struct EgressTcpStream {
    stream: TcpStream,
    _route_guard: Option<TargetRouteGuard>,
}

impl EgressTcpStream {
    fn new(stream: TcpStream, route_guard: Option<TargetRouteGuard>) -> Self {
        Self {
            stream,
            _route_guard: route_guard,
        }
    }
}

impl AsyncRead for EgressTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for EgressTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

pub async fn connect_tcp(
    target_addr: &str,
    interface: Option<&str>,
) -> io::Result<EgressTcpStream> {
    let Some(interface) = normalize_interface(interface) else {
        return TcpStream::connect(target_addr)
            .await
            .map(|stream| EgressTcpStream::new(stream, None));
    };

    let mut last_error = None;
    let mut resolved = false;
    for dst in tokio::net::lookup_host(target_addr).await? {
        resolved = true;
        let sources = match interface_bind_addrs(interface, dst) {
            Ok(sources) => sources,
            Err(err) => {
                last_error = Some(err);
                continue;
            }
        };

        for source in sources {
            match connect_tcp_addr(dst, interface, source).await {
                Ok(stream) => return Ok(stream),
                Err(err) => {
                    last_error = Some(connect_context_error(interface, source.addr, dst, err));
                }
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        if resolved {
            io::Error::other("所有目标地址连接失败")
        } else {
            io::Error::new(io::ErrorKind::NotFound, "未解析到目标地址")
        }
    }))
}

pub async fn connect_udp(target_addr: &str, interface: Option<&str>) -> io::Result<UdpSocket> {
    let Some(interface) = normalize_interface(interface) else {
        return connect_udp_default(target_addr).await;
    };

    let mut last_error = None;
    let mut resolved = false;
    for dst in tokio::net::lookup_host(target_addr).await? {
        resolved = true;
        let sources = match interface_bind_addrs(interface, dst) {
            Ok(sources) => sources,
            Err(err) => {
                last_error = Some(err);
                continue;
            }
        };

        for source in sources {
            match connect_udp_addr(dst, interface, source).await {
                Ok(socket) => return Ok(socket),
                Err(err) => {
                    last_error = Some(connect_context_error(interface, source.addr, dst, err));
                }
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        if resolved {
            io::Error::other("所有目标地址连接失败")
        } else {
            io::Error::new(io::ErrorKind::NotFound, "未解析到目标地址")
        }
    }))
}

fn normalize_interface(interface: Option<&str>) -> Option<&str> {
    interface.map(str::trim).filter(|name| !name.is_empty())
}

async fn connect_tcp_addr(
    dst: SocketAddr,
    interface: &str,
    source: BoundSource,
) -> io::Result<EgressTcpStream> {
    let socket = Socket::new(Domain::for_address(dst), Type::STREAM, Some(Protocol::TCP))?;
    bind_socket_to_interface(&socket, interface, source.interface_index, dst)?;
    let route_guard = TargetRouteGuard::install(interface, source.interface_index, dst)?;
    socket.bind(&SockAddr::from(source.addr))?;
    socket.set_nonblocking(true)?;

    TcpSocket::from_std_stream(socket.into())
        .connect(dst)
        .await
        .map(|stream| EgressTcpStream::new(stream, route_guard))
}

async fn connect_udp_addr(
    dst: SocketAddr,
    interface: &str,
    source: BoundSource,
) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::for_address(dst), Type::DGRAM, Some(Protocol::UDP))?;
    bind_socket_to_interface(&socket, interface, source.interface_index, dst)?;
    socket.bind(&SockAddr::from(source.addr))?;
    socket.set_nonblocking(true)?;

    let socket = UdpSocket::from_std(socket.into())?;
    socket.connect(dst).await?;
    Ok(socket)
}

async fn connect_udp_default(target_addr: &str) -> io::Result<UdpSocket> {
    let mut last_error = None;
    let mut resolved = false;
    for dst in tokio::net::lookup_host(target_addr).await? {
        resolved = true;
        let bind_addr = if dst.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        match UdpSocket::bind(bind_addr).await {
            Ok(socket) => match socket.connect(dst).await {
                Ok(()) => return Ok(socket),
                Err(err) => last_error = Some(err),
            },
            Err(err) => last_error = Some(err),
        }
    }

    Err(last_error.unwrap_or_else(|| {
        if resolved {
            io::Error::other("所有目标地址连接失败")
        } else {
            io::Error::new(io::ErrorKind::NotFound, "未解析到目标地址")
        }
    }))
}

#[derive(Clone, Copy)]
struct SourceCandidate {
    source: BoundSource,
    score: u8,
}

#[derive(Clone, Copy)]
struct BoundSource {
    addr: SocketAddr,
    interface_index: Option<u32>,
}

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
struct TargetRouteGuard {
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
struct TargetRouteGuard;

#[cfg(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
))]
impl TargetRouteGuard {
    fn install(
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
    fn install(
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

fn interface_bind_addrs(interface: &str, dst: SocketAddr) -> io::Result<Vec<BoundSource>> {
    let mut interface_exists = false;
    let mut address_family_exists = false;
    let mut candidates = Vec::new();

    for iface in get_if_addrs()? {
        if iface.name != interface {
            continue;
        }

        interface_exists = true;
        match (dst, &iface.addr) {
            (SocketAddr::V4(dst), IfAddr::V4(addr)) => {
                address_family_exists = true;
                if let Some(score) = ipv4_source_score(addr, *dst.ip()) {
                    candidates.push(SourceCandidate {
                        source: BoundSource {
                            addr: SocketAddr::new(IpAddr::V4(addr.ip), 0),
                            interface_index: iface.index,
                        },
                        score,
                    });
                }
            }
            (SocketAddr::V6(dst), IfAddr::V6(addr)) => {
                address_family_exists = true;
                if let Some(score) = ipv6_source_score(addr, *dst.ip()) {
                    candidates.push(SourceCandidate {
                        source: BoundSource {
                            addr: SocketAddr::V6(SocketAddrV6::new(
                                addr.ip,
                                0,
                                0,
                                ipv6_scope_id(addr.ip, iface.index),
                            )),
                            interface_index: iface.index,
                        },
                        score,
                    });
                }
            }
            _ => {}
        }
    }

    if !interface_exists {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("网络设备不存在：{interface}"),
        ));
    }

    if candidates.is_empty() {
        let message = if address_family_exists {
            format!("网络设备 {interface} 没有可用于连接 {dst} 的本地源地址")
        } else {
            format!("网络设备 {interface} 没有匹配目标地址族的本地地址")
        };

        return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, message));
    }

    candidates.sort_by_key(|candidate| candidate.score);
    Ok(candidates
        .into_iter()
        .map(|candidate| candidate.source)
        .collect())
}

fn connect_context_error(
    interface: &str,
    source: SocketAddr,
    dst: SocketAddr,
    err: io::Error,
) -> io::Error {
    io::Error::new(
        err.kind(),
        format!("出站设备 {interface} 使用源地址 {source} 连接 {dst} 失败：{err}"),
    )
}

fn ipv4_source_score(addr: &Ifv4Addr, dst: Ipv4Addr) -> Option<u8> {
    if addr.ip.is_unspecified() || addr.ip.is_loopback() {
        return None;
    }

    if !dst.is_link_local() && addr.ip.is_link_local() {
        return None;
    }

    if ipv4_same_subnet(addr.ip, addr.netmask, dst) {
        Some(0)
    } else {
        Some(1)
    }
}

fn ipv6_source_score(addr: &Ifv6Addr, dst: Ipv6Addr) -> Option<u8> {
    if addr.ip.is_unspecified() || addr.ip.is_loopback() {
        return None;
    }

    let source_is_link_local = ipv6_is_unicast_link_local(addr.ip);
    let dst_is_link_local = ipv6_is_unicast_link_local(dst);
    if source_is_link_local != dst_is_link_local {
        return None;
    }

    if ipv6_same_subnet(addr.ip, addr.netmask, dst) {
        Some(0)
    } else {
        Some(1)
    }
}

fn ipv4_same_subnet(ip: Ipv4Addr, netmask: Ipv4Addr, dst: Ipv4Addr) -> bool {
    (u32::from(ip) & u32::from(netmask)) == (u32::from(dst) & u32::from(netmask))
}

fn ipv6_same_subnet(ip: Ipv6Addr, netmask: Ipv6Addr, dst: Ipv6Addr) -> bool {
    let ip = ip.octets();
    let netmask = netmask.octets();
    let dst = dst.octets();
    ip.iter()
        .zip(netmask.iter())
        .zip(dst.iter())
        .all(|((ip, netmask), dst)| (ip & netmask) == (dst & netmask))
}

fn ipv6_is_unicast_link_local(ip: Ipv6Addr) -> bool {
    let bytes = ip.octets();
    bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80
}

fn ipv6_scope_id(ip: Ipv6Addr, interface_index: Option<u32>) -> u32 {
    if ipv6_is_unicast_link_local(ip) {
        interface_index.unwrap_or(0)
    } else {
        0
    }
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
fn bind_socket_to_interface(
    socket: &Socket,
    interface: &str,
    _interface_index: Option<u32>,
    _dst: SocketAddr,
) -> io::Result<()> {
    if interface.as_bytes().contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "网络设备名不能包含 NUL 字节",
        ));
    }
    socket.bind_device(Some(interface.as_bytes()))
}

#[cfg(any(
    target_os = "ios",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
))]
fn bind_socket_to_interface(
    socket: &Socket,
    interface: &str,
    interface_index: Option<u32>,
    dst: SocketAddr,
) -> io::Result<()> {
    let index = interface_index
        .and_then(NonZeroU32::new)
        .ok_or_else(|| io::Error::other(format!("网络设备 {interface} 没有有效 if_index")))?;

    if dst.is_ipv4() {
        socket.bind_device_by_index_v4(Some(index))
    } else {
        socket.bind_device_by_index_v6(Some(index))
    }
}

#[cfg(not(any(
    target_os = "android",
    target_os = "fuchsia",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
)))]
fn bind_socket_to_interface(
    _socket: &Socket,
    _interface: &str,
    _interface_index: Option<u32>,
    _dst: SocketAddr,
) -> io::Result<()> {
    Ok(())
}
