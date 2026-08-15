use super::*;
use tokio::sync::Semaphore;

const DIRECT_DNS_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONCURRENT_DIRECT_DNS_SOCKETS: usize = 32;
static DIRECT_DNS_SOCKET_PERMITS: Semaphore =
    Semaphore::const_new(MAX_CONCURRENT_DIRECT_DNS_SOCKETS);

pub fn classify_udp_route(
    target_port: u16,
    quic_policy: QuicPolicy,
    direct_access_match: bool,
) -> UdpRoute {
    if target_port == 443 {
        if quic_policy.should_block_udp443() {
            UdpRoute::Block
        } else if direct_access_match {
            UdpRoute::Direct
        } else {
            UdpRoute::Proxy
        }
    } else if direct_access_match {
        UdpRoute::Direct
    } else {
        UdpRoute::Proxy
    }
}

pub(super) async fn relay_direct_udp(
    client: SocketAddr,
    original_target: SocketAddr,
    connect_target: SocketAddr,
    target_label: String,
    mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    netstack_tx: UdpWriter,
    close_after_response: bool,
    shutdown: CancellationToken,
) -> Result<()> {
    let _dns_socket_permit = if close_after_response {
        Some(DIRECT_DNS_SOCKET_PERMITS.acquire().await.map_err(|_| {
            AndroidAgentError::Connection("direct DNS socket limiter closed".to_string())
        })?)
    } else {
        None
    };
    let socket = bind_direct_udp(connect_target)?;
    socket.connect(connect_target).await?;
    let idle_timeout = if close_after_response {
        DIRECT_DNS_RESPONSE_TIMEOUT
    } else {
        UDP_SESSION_IDLE
    };
    let idle_sleep = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_sleep);
    let mut response_buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = &mut idle_sleep => {
                debug!("Android UDP direct session idle; closing -> {}", target_label);
                break;
            }
            maybe_data = rx.recv() => {
                let Some(data) = maybe_data else {
                    break;
                };
                if let Err(e) = socket.send(&data).await {
                    debug!("Android UDP direct send failed: {e}");
                    break;
                }
                idle_sleep.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
            }
            received = socket.recv(&mut response_buf) => {
                match received {
                    Ok(n) => {
                        let pkt = response_buf[..n].to_vec();
                        if let Err(e) = netstack_tx.send((pkt, original_target, client)).await {
                            debug!("Android UDP direct response writeback failed: {e}");
                            break;
                        }
                        if close_after_response {
                            break;
                        }
                        idle_sleep.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                    }
                    Err(e) => {
                        debug!("Android UDP direct receive failed: {e}");
                        break;
                    }
                }
            }
        }
    }
    debug!("Android TUN UDP direct relay ended -> {}", target_label);
    Ok(())
}

pub(super) fn bind_direct_udp(target: SocketAddr) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(
        Domain::for_address(target),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    protect_direct_socket(&socket)?;
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

pub(in crate::netstack) fn tune_direct_udp_socket(socket: &Socket, target: SocketAddr) {
    if let Err(err) = socket.set_recv_buffer_size(crate::config::ANDROID_SOCKET_BUFFER_SIZE) {
        debug!("Android TUN UDP direct recv buffer setup failed target={target}: {err}");
    }
    if let Err(err) = socket.set_send_buffer_size(crate::config::ANDROID_SOCKET_BUFFER_SIZE) {
        debug!("Android TUN UDP direct send buffer setup failed target={target}: {err}");
    }
}

pub(super) fn protect_direct_socket(socket: &Socket) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;

        crate::socket_protector::protect_fd(socket.as_raw_fd())
    }

    #[cfg(not(unix))]
    {
        let _ = socket;
        Ok(())
    }
}

pub(super) async fn drain_dropped_udp(
    mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            received = timeout(Duration::from_secs(10), rx.recv()) => {
                if !matches!(received, Ok(Some(_))) {
                    break;
                }
            }
        }
    }
}

pub(super) fn proxy_target_label(target_label: &str, reason: Option<&str>) -> String {
    match reason {
        Some(reason) => format!("{reason}, original {target_label}"),
        None => target_label.to_string(),
    }
}
