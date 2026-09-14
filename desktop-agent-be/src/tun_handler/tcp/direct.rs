use super::super::TunDirectEgress;
use super::super::direct_egress::bind_direct_socket_source;
use super::super::network::TunNetworks;
use crate::error::{AgentError, Result};
use crate::yamux_session::YamuxSessionManager;
use common::{BindInterface, bind_socket_to_interface};
use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
use std::net::{IpAddr, SocketAddr};
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
use std::time::Duration;
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::timeout;
use tracing::debug;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{IPPROTO_TCP, SOCKET, SOCKET_ERROR, setsockopt};

/// macOS 待机恢复后 scoped route 可能短暂失效，避免直连卡到系统 TCP 超时。
const DIRECT_TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const DIRECT_TCP_SOCKET_BUFFER_SIZE: usize = 1024 * 1024;
#[cfg(windows)]
const DIRECT_TCP_MAX_RETRANSMIT_SECS: u32 = 30;
#[cfg(windows)]
const TCP_MAXRT: i32 = 5;

pub(super) struct DirectTcpRefreshContext<'a> {
    pub(super) target: SocketAddr,
    pub(super) target_str: &'a str,
    pub(super) direct_egress: &'a TunDirectEgress,
    pub(super) tcp_sessions: &'a YamuxSessionManager,
    pub(super) udp_sessions: &'a YamuxSessionManager,
    pub(super) tun_networks: TunNetworks,
}

pub(super) async fn connect_direct_tcp_with_refresh(
    context: DirectTcpRefreshContext<'_>,
) -> Result<TcpStream> {
    let DirectTcpRefreshContext {
        target,
        target_str,
        direct_egress,
        tcp_sessions,
        udp_sessions,
        tun_networks,
    } = context;
    let initial_bind_interface = direct_egress.bind_interface(target.ip());
    let source_ip = direct_egress.bind_source_ip(target.ip());
    match connect_direct_tcp(target, initial_bind_interface.as_ref(), source_ip).await {
        Ok(stream) => Ok(stream),
        Err(first_err) => {
            debug!(
                "TUN TCP 直连首次失败，刷新物理出口后重试：target={} bind_interface={:?} error={}",
                target_str, initial_bind_interface, first_err
            );
            let refreshed_bind_interface = direct_egress
                .refresh_after_direct_failure(target.ip(), tcp_sessions, udp_sessions, tun_networks)
                .await;
            match connect_direct_tcp(target, refreshed_bind_interface.as_ref(), source_ip).await {
                Ok(stream) => Ok(stream),
                Err(retry_err) => {
                    // 这里刻意不做 agent 侧域名解析兜底。
                    // TUN 流量进来时系统/应用已经完成了解析，agent 看到的是原始目标 IP；
                    // 如果直连失败后再用 agent 本机 DNS 重新解析域名，会改变客户端实际
                    // 选择的 CDN/出口语义，也会和“域名由 proxy 端解析”的安全要求冲突。
                    // 因此直连失败只刷新物理出口重试同一个 IP，不把域名解析拉回 agent。
                    Err(AgentError::Connection(format!(
                        "直连 {target_str} 失败：首次错误={first_err}；刷新物理出口后重试错误={retry_err}"
                    )))
                }
            }
        }
    }
}

async fn connect_direct_tcp(
    target: SocketAddr,
    bind_interface: Option<&BindInterface>,
    source_ip: Option<IpAddr>,
) -> std::io::Result<TcpStream> {
    // TUN 直连也要绑定物理接口，否则系统默认路由已指向 TUN 时会出现自回环。
    let socket = Socket::new(
        Domain::for_address(target),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    bind_socket_to_interface(&socket, bind_interface, target)?;
    bind_direct_socket_source(&socket, source_ip, target)?;
    tune_direct_tcp_socket(&socket, target);
    enable_direct_tcp_keepalive(&socket, target);
    socket.set_nonblocking(true)?;

    let socket = TcpSocket::from_std_stream(socket.into());
    timeout(DIRECT_TCP_CONNECT_TIMEOUT, socket.connect(target))
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("TUN TCP 直连 {target} 超时"),
            )
        })?
}

fn enable_direct_tcp_keepalive(socket: &Socket, target: SocketAddr) {
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(30))
        .with_retries(4);

    if let Err(err) = socket.set_tcp_keepalive(&keepalive) {
        debug!("TUN TCP 直连 keepalive 设置失败 target={target}: {err}");
    }
}

fn tune_direct_tcp_socket(socket: &Socket, target: SocketAddr) {
    if let Err(error) = socket.set_tcp_nodelay(true) {
        debug!("TUN TCP 直连 TCP_NODELAY 设置失败 target={target}: {error}");
    }
    if let Err(error) = socket.set_recv_buffer_size(DIRECT_TCP_SOCKET_BUFFER_SIZE) {
        debug!("TUN TCP 直连接收缓冲设置失败 target={target}: {error}");
    }
    if let Err(error) = socket.set_send_buffer_size(DIRECT_TCP_SOCKET_BUFFER_SIZE) {
        debug!("TUN TCP 直连发送缓冲设置失败 target={target}: {error}");
    }
    set_windows_direct_tcp_max_retransmit(socket, target);
}

#[cfg(windows)]
fn set_windows_direct_tcp_max_retransmit(socket: &Socket, target: SocketAddr) {
    let seconds = DIRECT_TCP_MAX_RETRANSMIT_SECS;
    let result = unsafe {
        setsockopt(
            socket.as_raw_socket() as SOCKET,
            IPPROTO_TCP,
            TCP_MAXRT,
            (&seconds as *const u32).cast(),
            std::mem::size_of_val(&seconds) as i32,
        )
    };
    if result == SOCKET_ERROR {
        debug!(
            "TUN TCP 直连 TCP_MAXRT 设置失败 target={target}: {}",
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(not(windows))]
fn set_windows_direct_tcp_max_retransmit(_socket: &Socket, _target: SocketAddr) {}
