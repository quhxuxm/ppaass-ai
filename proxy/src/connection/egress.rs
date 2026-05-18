mod auto;
mod bind;
mod route_guard;
mod source;
mod stream;

use auto::interface_for_dst;
use bind::bind_socket_to_interface;
use route_guard::TargetRouteGuard;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use source::{BoundSource, interface_bind_addrs};
use std::io;
use std::net::SocketAddr;
pub use stream::EgressTcpStream;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

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
        let interface = match interface_for_dst(interface, dst) {
            Ok(interface) => interface,
            Err(err) => {
                last_error = Some(err);
                continue;
            }
        };
        let sources = match interface_bind_addrs(&interface, dst) {
            Ok(sources) => sources,
            Err(err) => {
                last_error = Some(err);
                continue;
            }
        };

        for source in sources {
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

pub async fn connect_udp(target_addr: &str, interface: Option<&str>) -> io::Result<UdpSocket> {
    let Some(interface) = normalize_interface(interface) else {
        return connect_udp_default(target_addr).await;
    };

    let mut last_error = None;
    let mut resolved = false;
    for dst in tokio::net::lookup_host(target_addr).await? {
        resolved = true;
        let interface = match interface_for_dst(interface, dst) {
            Ok(interface) => interface,
            Err(err) => {
                last_error = Some(err);
                continue;
            }
        };
        let sources = match interface_bind_addrs(&interface, dst) {
            Ok(sources) => sources,
            Err(err) => {
                last_error = Some(err);
                continue;
            }
        };

        for source in sources {
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
