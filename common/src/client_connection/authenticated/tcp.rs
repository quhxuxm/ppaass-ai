use std::net::SocketAddr;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::{TcpSocket, TcpStream};
use tracing::{debug, warn};

use super::AuthenticatedConnection;
use crate::client_connection::config::{BindInterface, ClientConnectionConfig};
use crate::client_connection::socket_bind::bind_socket_to_interface;
use crate::configure_proxy_tcp_socket;

impl AuthenticatedConnection<TcpStream> {
    pub async fn connect<C>(config: &C) -> Result<Self, std::io::Error>
    where
        C: ClientConnectionConfig,
    {
        let stream = connect_tcp_stream(config).await?;
        Self::authenticate_stream(stream, config).await
    }
}

// ---------------------------------------------------------------------------
// 辅助函数
// ---------------------------------------------------------------------------

pub(in crate::client_connection) async fn connect_tcp_stream<C>(
    config: &C,
) -> std::io::Result<TcpStream>
where
    C: ClientConnectionConfig,
{
    let remote_addr = config.remote_addr();
    let timeout = config.timeout_duration();

    debug!("正在连接远端 Proxy");

    // TCP 连接 — 可选绑定到指定本地地址，以绕过可能存在的 TUN 默认路由。
    let stream = if let Some(bind) = config.bind_addr() {
        connect_bound(config, &remote_addr, bind, config.bind_interface(), timeout).await?
    } else {
        connect_unbound(config, &remote_addr, timeout).await?
    };
    if let Err(err) = stream.set_nodelay(true) {
        warn!("设置代理连接 TCP_NODELAY 失败，将继续使用默认 TCP 行为: {err}");
    }

    Ok(stream)
}

/// 连接到 `remote_addr`，同时将套接字绑定到 `bind`。
///
/// 确保连接使用拥有 `bind.ip()` 的网络接口，而非操作系统根据当前路由表
/// 自动选择的接口——这在 TUN 模式下至关重要，可防止代理连接回环到 TUN 设备。
///
/// 如果所有绑定连接尝试都失败，则直接返回错误。
/// TUN 模式依赖这个绑定来防止代理连接回环进入 TUN，不能静默回退到普通连接。
async fn connect_bound<C>(
    config: &C,
    remote_addr: &str,
    bind: SocketAddr,
    bind_interface: Option<BindInterface>,
    timeout: std::time::Duration,
) -> std::io::Result<TcpStream>
where
    C: ClientConnectionConfig,
{
    // 异步解析远端主机名
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(remote_addr)
        .await
        .map(|it| it.collect())
        .unwrap_or_default();

    let mut last_error = None;
    let mut has_matching_addr = false;

    for dst in &addrs {
        // 跳过 IP 版本与绑定地址不匹配的地址
        let version_match = (bind.is_ipv4() && dst.is_ipv4()) || (bind.is_ipv6() && dst.is_ipv6());
        if !version_match {
            continue;
        }
        has_matching_addr = true;

        let socket = match Socket::new(Domain::for_address(*dst), Type::STREAM, Some(Protocol::TCP))
        {
            Ok(s) => s,
            Err(e) => {
                warn!("创建远端 Proxy TcpSocket 失败：{e}");
                last_error = Some(e);
                continue;
            }
        };
        if let Err(e) = config.protect_socket(&socket, *dst) {
            warn!("保护远端 Proxy socket 失败：{e}");
            last_error = Some(e);
            continue;
        }
        tune_proxy_socket(config, &socket, *dst);
        tune_proxy_keepalive(&socket, *dst);
        if let Err(e) = bind_socket_to_interface(&socket, bind_interface.as_ref(), *dst) {
            warn!("绑定远端 Proxy 连接到物理接口失败：{e}");
            last_error = Some(e);
            continue;
        }
        if let Err(e) = socket.bind(&SockAddr::from(bind)) {
            warn!("TcpSocket::bind({bind}) 失败: {e}");
            last_error = Some(e);
            continue;
        }
        if let Err(e) = socket.set_nonblocking(true) {
            warn!("设置远端 Proxy socket 非阻塞失败：{e}");
            last_error = Some(e);
            continue;
        }

        let socket = TcpSocket::from_std_stream(socket.into());
        match tokio::time::timeout(timeout, socket.connect(*dst)).await {
            Ok(Ok(stream)) => {
                debug!("已通过绑定套接字连接到远端 Proxy（本地={bind}）");
                return Ok(stream);
            }
            Ok(Err(e)) => {
                warn!("绑定连接到远端 Proxy 失败：{e}");
                last_error = Some(e);
            }
            Err(_) => {
                warn!("绑定连接到远端 Proxy 超时");
                last_error = Some(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "绑定连接到远端 Proxy 超时",
                ));
            }
        }
    }

    if !has_matching_addr {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            format!("远端 Proxy 没有与绑定地址 {bind} 匹配的 IP 版本"),
        ));
    }

    Err(last_error
        .unwrap_or_else(|| std::io::Error::other("所有到远端 Proxy 的绑定连接尝试均失败")))
}

async fn connect_unbound<C>(
    config: &C,
    remote_addr: &str,
    timeout: std::time::Duration,
) -> std::io::Result<TcpStream>
where
    C: ClientConnectionConfig,
{
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(remote_addr).await?.collect();
    let mut last_error = None;

    for dst in addrs {
        let socket = match Socket::new(Domain::for_address(dst), Type::STREAM, Some(Protocol::TCP))
        {
            Ok(socket) => socket,
            Err(e) => {
                warn!("创建远端 Proxy TcpSocket 失败：{e}");
                last_error = Some(e);
                continue;
            }
        };
        if let Err(e) = config.protect_socket(&socket, dst) {
            warn!("保护远端 Proxy socket 失败：{e}");
            last_error = Some(e);
            continue;
        }
        tune_proxy_socket(config, &socket, dst);
        tune_proxy_keepalive(&socket, dst);
        if let Err(e) = socket.set_nonblocking(true) {
            warn!("设置远端 Proxy socket 非阻塞失败：{e}");
            last_error = Some(e);
            continue;
        }

        let socket = TcpSocket::from_std_stream(socket.into());
        match tokio::time::timeout(timeout, socket.connect(dst)).await {
            Ok(Ok(stream)) => {
                debug!("已连接到远端 Proxy");
                return Ok(stream);
            }
            Ok(Err(e)) => {
                warn!("连接到远端 Proxy 失败：{e}");
                last_error = Some(e);
            }
            Err(_) => {
                warn!("连接到远端 Proxy 超时");
                last_error = Some(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "连接到远端 Proxy 超时",
                ));
            }
        }
    }

    Err(last_error.unwrap_or_else(|| std::io::Error::other("所有到远端 Proxy 的连接尝试均失败")))
}

fn tune_proxy_socket<C>(config: &C, socket: &Socket, _dst: SocketAddr)
where
    C: ClientConnectionConfig,
{
    let Some(buffer_size) = config.tcp_socket_buffer_size() else {
        return;
    };
    if let Err(err) = socket.set_recv_buffer_size(buffer_size) {
        warn!("设置远端 Proxy socket 接收缓冲失败：{err}");
    }
    if let Err(err) = socket.set_send_buffer_size(buffer_size) {
        warn!("设置远端 Proxy socket 发送缓冲失败：{err}");
    }
}

fn tune_proxy_keepalive(socket: &Socket, _dst: SocketAddr) {
    if let Err(err) = configure_proxy_tcp_socket(socket) {
        debug!("设置远端 Proxy TCP keepalive 失败：{err}");
    }
}
