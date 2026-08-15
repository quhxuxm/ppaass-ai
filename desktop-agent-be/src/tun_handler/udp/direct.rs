use super::*;
use crate::error::AgentError;
use common::{BindInterface, bind_socket_to_interface};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const DIRECT_UDP_SOCKET_BUFFER_SIZE: usize = 1024 * 1024;
const DIRECT_DNS_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(windows)]
const DIRECT_UDP_SEND_TIMEOUT: Duration = Duration::from_secs(3);

pub(super) async fn relay_direct_udp(context: DirectUdpRelayContext) -> Result<()> {
    let DirectUdpRelayContext {
        client,
        original_target,
        connect_target,
        target_label,
        mut rx,
        netstack_tx,
        direct_egress,
        tcp_sessions,
        udp_sessions,
        tun_networks,
        close_after_response,
        shutdown,
    } = context;

    // 直连 UDP 绑定临时本地端口并 connect 到目标，便于 recv 只接收该目标回复。
    let socket = connect_direct_udp_with_refresh(
        connect_target,
        &target_label,
        direct_egress.as_ref(),
        tcp_sessions.as_ref(),
        udp_sessions.as_ref(),
        tun_networks,
    )
    .await?;
    let mut outbound_bytes = 0u64;
    let mut inbound_bytes = 0u64;
    let idle_timeout = if close_after_response {
        DIRECT_DNS_RESPONSE_TIMEOUT
    } else {
        UDP_SESSION_IDLE
    };
    let idle = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle);
    let mut buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = &mut idle => {
                debug!(
                    "TUN UDP 直连会话空闲超过 {} 秒，关闭 -> {}",
                    idle_timeout.as_secs(),
                    target_label
                );
                break;
            }
            maybe_data = rx.recv() => {
                let Some(data) = maybe_data else { break };
                let data_len = data.len();
                if let Err(e) = send_direct_udp(&socket, &data).await {
                    debug!("UDP 直连发送错误：{e}");
                    #[cfg(windows)]
                    let _ = direct_egress
                        .refresh_after_direct_failure(
                            connect_target.ip(),
                            tcp_sessions.as_ref(),
                            udp_sessions.as_ref(),
                            tun_networks,
                        )
                        .await;
                    break;
                }
                let data_len = data_len as u64;
                outbound_bytes += data_len;
                telemetry::record_traffic(data_len, 0);
                idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
            }
            received = socket.recv(&mut buf) => {
                match received {
                    Ok(n) => {
                        let pkt = buf[..n].to_vec();
                        if let Err(e) = netstack_tx.send((pkt, original_target, client)).await {
                            debug!("UDP 直连回复错误：{e}");
                            break;
                        }
                        let received_bytes = n as u64;
                        inbound_bytes += received_bytes;
                        telemetry::record_traffic(0, received_bytes);
                        if close_after_response {
                            break;
                        }
                        idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                    }
                    Err(e) => {
                        debug!("UDP 直连接收错误：{e}");
                        break;
                    }
                }
            }
        }
    }
    telemetry::log_traffic(
        "TUN UDP (直连)",
        target_label,
        outbound_bytes,
        inbound_bytes,
    );
    Ok(())
}

#[cfg(windows)]
async fn send_direct_udp(socket: &UdpSocket, data: &[u8]) -> std::io::Result<usize> {
    timeout(DIRECT_UDP_SEND_TIMEOUT, socket.send(data))
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Windows 直连 UDP 上行发送超过 3 秒",
            )
        })?
}

#[cfg(not(windows))]
async fn send_direct_udp(socket: &UdpSocket, data: &[u8]) -> std::io::Result<usize> {
    socket.send(data).await
}

async fn connect_direct_udp_with_refresh(
    target: SocketAddr,
    target_label: &str,
    direct_egress: &super::super::TunDirectEgress,
    tcp_sessions: &YamuxSessionManager,
    udp_sessions: &YamuxSessionManager,
    tun_networks: TunNetworks,
) -> Result<UdpSocket> {
    let initial_bind_interface = match direct_egress.bind_interface(target.ip()) {
        Some(bind_interface) => Some(bind_interface),
        None => {
            debug!(
                "TUN UDP 直连缺少物理出口绑定，发送前尝试刷新：target={}",
                target_label
            );
            direct_egress
                .refresh_after_direct_failure(target.ip(), tcp_sessions, udp_sessions, tun_networks)
                .await
        }
    };
    let initial_bind_interface = initial_bind_interface.ok_or_else(|| {
        AgentError::Connection(format!(
            "UDP 直连 {target_label} 已拒绝：无法确定 {} 物理出口接口，不能在 TUN 模式下无绑定发送",
            if target.is_ipv6() { "IPv6" } else { "IPv4" }
        ))
    })?;

    match connect_direct_udp(target, &initial_bind_interface).await {
        Ok(socket) => Ok(socket),
        Err(first_err) => {
            debug!(
                "TUN UDP 直连首次失败，刷新物理出口后重试：target={} bind_interface={:?} error={}",
                target_label, initial_bind_interface, first_err
            );
            let refreshed_bind_interface = direct_egress
                .refresh_after_direct_failure(target.ip(), tcp_sessions, udp_sessions, tun_networks)
                .await
                .ok_or_else(|| {
                    AgentError::Connection(format!(
                        "UDP 直连 {target_label} 失败：首次错误={first_err}；\
                         刷新后仍无法确定物理出口接口"
                    ))
                })?;
            connect_direct_udp(target, &refreshed_bind_interface)
                .await
                .map_err(|retry_err| {
                    AgentError::Connection(format!(
                        "UDP 直连 {target_label} 失败：首次错误={first_err}；刷新物理出口后重试错误={retry_err}"
                    ))
                })
        }
    }
}

async fn connect_direct_udp(
    target: SocketAddr,
    bind_interface: &BindInterface,
) -> std::io::Result<UdpSocket> {
    let socket = bind_direct_udp(target, bind_interface)?;
    socket.connect(target).await?;
    Ok(socket)
}

fn bind_direct_udp(
    target: SocketAddr,
    bind_interface: &BindInterface,
) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(
        Domain::for_address(target),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    bind_socket_to_interface(&socket, Some(bind_interface), target)?;
    tune_direct_udp_socket(&socket, target);

    let bind_addr = if target.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    socket.bind(&SockAddr::from(bind_addr))?;
    socket.set_nonblocking(true)?;

    UdpSocket::from_std(socket.into())
}

fn tune_direct_udp_socket(socket: &Socket, target: SocketAddr) {
    if let Err(error) = socket.set_recv_buffer_size(DIRECT_UDP_SOCKET_BUFFER_SIZE) {
        debug!(%target, %error, "设置直连 UDP 接收缓冲失败");
    }
    if let Err(error) = socket.set_send_buffer_size(DIRECT_UDP_SOCKET_BUFFER_SIZE) {
        debug!(%target, %error, "设置直连 UDP 发送缓冲失败");
    }
}

pub(super) async fn drain_dropped_udp(
    mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    shutdown: &CancellationToken,
) {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            received = timeout(Duration::from_secs(10), rx.recv()) => {
                if !matches!(received, Ok(Some(_))) {
                    break;
                }
                // 保持会话短暂存活，避免应用持续重试被丢弃 UDP 时频繁创建/销毁任务。
            }
        }
    }
}

pub(super) fn proxy_target_label(target_label: &str, reason: Option<&str>) -> String {
    match reason {
        Some(reason) => format!("{reason}，原始目标 {target_label}"),
        None => target_label.to_string(),
    }
}
