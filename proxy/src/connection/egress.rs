//! proxy 访问目标服务器的出站连接层。
//!
//! 默认情况下直接使用系统路由；配置 `outbound_interface` 后，会先选择出站设备和本地源地址，
//! 再把 TCP/UDP socket 绑定到指定接口。`auto` 模式会根据路由表选择原始默认出口，
//! 用于避免 proxy 与 TUN/agent 同机运行时，proxy 的目标流量又被路由回 TUN。

mod auto;
mod bind;
mod route_guard;
mod source;
mod stream;

use auto::AutoInterfaceSelector;
use bind::bind_socket_to_interface;
use route_guard::TargetRouteGuard;
use socket2::{Domain, Protocol, SockAddr, SockRef, Socket, Type};
use source::{BoundSource, interface_bind_addrs};
use std::borrow::Cow;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
pub use stream::EgressTcpStream;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

// proxy 到目标站点的出站 TCP 缓冲。
// 视频分片下载通常是目标站点到 proxy 的大流量下行，默认系统缓冲在高 RTT 或蜂窝网络下
// 容易过早限制 TCP 窗口；1MB 与 Android agent 侧保持一致，能给 HLS burst 留出余量。
const PROXY_EGRESS_TCP_BUFFER_SIZE: usize = 1024 * 1024;
const PROXY_EGRESS_TCP_ADDR_RETRY_DEADLINE: Duration = Duration::from_secs(18);
const PROXY_EGRESS_TCP_ADDR_RETRY_INITIAL_DELAY: Duration = Duration::from_millis(10);
const PROXY_EGRESS_TCP_ADDR_RETRY_MAX_DELAY: Duration = Duration::from_millis(250);

pub struct EgressState {
    // None 表示完全交给系统默认路由；Some 表示需要做接口/源地址绑定。
    interface: Option<InterfaceSelection>,
}

enum InterfaceSelection {
    // 显式指定的网卡名，例如 en0、eth0、Ethernet。
    Named(String),
    // 逻辑值 auto：按目标地址和路由表动态选择出口网卡。
    Auto(AutoInterfaceSelector),
}

impl EgressState {
    pub fn new(interface: Option<&str>) -> io::Result<Self> {
        // 启动阶段解析出站设备配置；auto 模式会读取初始路由表并在失效时刷新。
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
            let stream = connect_tcp_default_with_retry(target_addr).await?;
            tune_egress_tcp_stream(&stream, "默认出站 TCP 连接");
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
        // Named 直接使用配置值；auto 则从可刷新的路由表快照中选择出口设备。
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
        let stream = connect_tcp_default_with_retry(target_addr).await?;
        tune_egress_tcp_stream(&stream, "默认出站 TCP 连接");
        return Ok(EgressTcpStream::new(stream, None));
    }

    let mut last_error = None;
    let mut resolved = false;
    for dst in tokio::net::lookup_host(target_addr).await? {
        resolved = true;
        // 一个域名可能解析出多个 IPv4/IPv6 地址；逐个尝试能提升可达性。
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
        // UDP 也遍历所有解析结果；只有成功 bind + connect 的 socket 才会返回给 relay。
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

async fn connect_tcp_default_with_retry(target_addr: &str) -> io::Result<TcpStream> {
    let started = Instant::now();
    let mut delay = PROXY_EGRESS_TCP_ADDR_RETRY_INITIAL_DELAY;

    loop {
        match TcpStream::connect(target_addr).await {
            Ok(stream) => return Ok(stream),
            Err(err)
                if is_transient_addr_not_available(&err)
                    && started.elapsed() + delay < PROXY_EGRESS_TCP_ADDR_RETRY_DEADLINE =>
            {
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(PROXY_EGRESS_TCP_ADDR_RETRY_MAX_DELAY);
            }
            Err(err) => return Err(err),
        }
    }
}

fn is_transient_addr_not_available(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::AddrNotAvailable || err.raw_os_error() == Some(49)
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
    tune_egress_tcp_stream(&stream, "绑定出站 TCP 连接");
    Ok(EgressTcpStream::new(stream, route_guard))
}

fn tune_egress_tcp_stream(stream: &TcpStream, context: &str) {
    if let Err(err) = stream.set_nodelay(true) {
        tracing::warn!("设置 {context} TCP_NODELAY 失败，将继续使用默认 TCP 行为: {err}");
    }

    // 缓冲调优是 best-effort：部分系统会按内核上限截断或拒绝设置。
    // 设置失败不能影响连接建立，否则一个内核参数差异就会变成用户可见的请求失败。
    let sock_ref = SockRef::from(stream);
    if let Err(err) = sock_ref.set_recv_buffer_size(PROXY_EGRESS_TCP_BUFFER_SIZE) {
        tracing::warn!("设置 {context} 接收缓冲失败，将继续使用系统默认值: {err}");
    }
    if let Err(err) = sock_ref.set_send_buffer_size(PROXY_EGRESS_TCP_BUFFER_SIZE) {
        tracing::warn!("设置 {context} 发送缓冲失败，将继续使用系统默认值: {err}");
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
