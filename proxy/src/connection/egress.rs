mod auto;
mod bind;
mod route_guard;
mod source;
mod stream;

use auto::AutoInterfaceSelector;
use bind::bind_socket_to_interface;
use route_guard::TargetRouteGuard;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use source::{BoundSource, interface_bind_addrs};
use std::borrow::Cow;
use std::io;
use std::net::SocketAddr;
pub use stream::EgressTcpStream;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

pub struct EgressState {
    interface: Option<InterfaceSelection>,
}

enum InterfaceSelection {
    Named(String),
    Auto(AutoInterfaceSelector),
}

impl EgressState {
    pub fn new(interface: Option<&str>) -> io::Result<Self> {
        // 启动阶段解析出站设备配置；auto 模式会在这里读取并缓存路由表。
        let interface = match normalize_interface(interface) {
            Some(interface) if auto::is_auto_interface(interface) => {
                Some(InterfaceSelection::Auto(AutoInterfaceSelector::new()?))
            }
            Some(interface) => Some(InterfaceSelection::Named(interface.to_string())),
            None => None,
        };

        Ok(Self { interface })
    }

    pub async fn connect_tcp(&self, target_addr: &str) -> io::Result<EgressTcpStream> {
        // 未指定出站设备时走系统默认路由，不做额外绑定。
        if self.interface.is_none() {
            let stream = TcpStream::connect(target_addr).await?;
            enable_nodelay_best_effort(&stream, "默认出站 TCP 连接");
            return Ok(EgressTcpStream::new(stream, None));
        }

        // 指定设备或 auto 模式需要按目标地址族选择可用源地址后再连接。
        connect_tcp_with_interface(target_addr, self).await
    }

    pub async fn connect_udp(&self, target_addr: &str) -> io::Result<UdpSocket> {
        // UDP 默认路径只绑定通配地址，由操作系统选择出口。
        if self.interface.is_none() {
            return connect_udp_default(target_addr).await;
        }

        // 指定设备或 auto 模式复用同一套出站设备选择逻辑。
        connect_udp_with_interface(target_addr, self).await
    }

    fn interface_for_dst(&self, dst: SocketAddr) -> io::Result<Cow<'_, str>> {
        // Named 直接使用配置值；auto 则从启动时缓存的路由表中选择出口设备。
        match &self.interface {
            Some(InterfaceSelection::Named(interface)) => Ok(Cow::Borrowed(interface.as_str())),
            Some(InterfaceSelection::Auto(selector)) => {
                selector.interface_for_dst(dst).map(Cow::Owned)
            }
            None => Err(io::Error::other("未配置出站网络设备")),
        }
    }
}

async fn connect_tcp_with_interface(
    target_addr: &str,
    egress_state: &EgressState,
) -> io::Result<EgressTcpStream> {
    if egress_state.interface.is_none() {
        let stream = TcpStream::connect(target_addr).await?;
        enable_nodelay_best_effort(&stream, "默认出站 TCP 连接");
        return Ok(EgressTcpStream::new(stream, None));
    }

    let mut last_error = None;
    let mut resolved = false;
    for dst in tokio::net::lookup_host(target_addr).await? {
        resolved = true;
        // 对每个解析出的目标地址，先确定要绑定的出站设备。
        let interface = match egress_state.interface_for_dst(dst) {
            Ok(interface) => interface,
            Err(err) => {
                last_error = Some(err);
                continue;
            }
        };
        // 再从该设备上挑选与目标地址族匹配的本地源地址。
        let sources = match interface_bind_addrs(&interface, dst) {
            Ok(sources) => sources,
            Err(err) => {
                last_error = Some(err);
                continue;
            }
        };

        for source in sources {
            // 尝试按候选源地址连接，失败则继续尝试下一个候选。
            match connect_tcp_addr(dst, &interface, source).await {
                Ok(stream) => return Ok(stream),
                Err(err) => {
                    last_error = Some(connect_context_error(&interface, source.addr, dst, err));
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

async fn connect_udp_with_interface(
    target_addr: &str,
    egress_state: &EgressState,
) -> io::Result<UdpSocket> {
    if egress_state.interface.is_none() {
        return connect_udp_default(target_addr).await;
    }

    let mut last_error = None;
    let mut resolved = false;
    for dst in tokio::net::lookup_host(target_addr).await? {
        resolved = true;
        // UDP 与 TCP 使用相同的出口设备选择，确保两种协议路径一致。
        let interface = match egress_state.interface_for_dst(dst) {
            Ok(interface) => interface,
            Err(err) => {
                last_error = Some(err);
                continue;
            }
        };
        // 只使用目标地址族兼容的源地址，避免 IPv4/IPv6 混绑。
        let sources = match interface_bind_addrs(&interface, dst) {
            Ok(sources) => sources,
            Err(err) => {
                last_error = Some(err);
                continue;
            }
        };

        for source in sources {
            // UDP connect 只设置默认对端；失败时继续尝试下一个源地址。
            match connect_udp_addr(dst, &interface, source).await {
                Ok(socket) => return Ok(socket),
                Err(err) => {
                    last_error = Some(connect_context_error(&interface, source.addr, dst, err));
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
    // 先绑定到指定网卡，再按需安装目标旁路路由，避免流量回到 TUN。
    bind_socket_to_interface(&socket, interface, source.interface_index, dst)?;
    let route_guard = TargetRouteGuard::install(interface, source.interface_index, dst)?;
    // 最后绑定本地源地址并交给 Tokio 执行异步 connect。
    socket.bind(&SockAddr::from(source.addr))?;
    socket.set_nonblocking(true)?;

    let stream = TcpSocket::from_std_stream(socket.into())
        .connect(dst)
        .await?;
    enable_nodelay_best_effort(&stream, "绑定出站 TCP 连接");
    Ok(EgressTcpStream::new(stream, route_guard))
}

fn enable_nodelay_best_effort(stream: &TcpStream, context: &str) {
    if let Err(err) = stream.set_nodelay(true) {
        tracing::warn!("设置 {context} TCP_NODELAY 失败，将继续使用默认 TCP 行为: {err}");
    }
}

async fn connect_udp_addr(
    dst: SocketAddr,
    interface: &str,
    source: BoundSource,
) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::for_address(dst), Type::DGRAM, Some(Protocol::UDP))?;
    // UDP 同样绑定到指定网卡，确保 DNS/UDP 目标也走预期出口。
    bind_socket_to_interface(&socket, interface, source.interface_index, dst)?;
    // 绑定候选源地址后再 connect，便于后续收发只面对单个对端。
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
        // 默认 UDP 路径仍按目标地址族选择通配绑定地址。
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
