use std::net::SocketAddr;
use std::time::Duration;

use common::{DEFAULT_STREAM_RELAY_BUFFER_SIZE, spawn_guarded};
use futures::StreamExt;
use protocol::{Address, TransportProtocol};
use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use super::ForwardContext;
use super::domain_sniff::{extract_http_host, extract_tls_sni};
use super::network::{address_for_tun_target, reject_tun_target};
use crate::android_log;
use crate::error::{AndroidAgentError, Result};

const SNIFF_MAX_BYTES: usize = 4096;
const SNIFF_TIMEOUT: Duration = Duration::from_millis(100);

pub(super) fn spawn_tcp_listener(
    mut tcp_listener: netstack_smoltcp::TcpListener,
    context: ForwardContext,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    spawn_guarded("android tcp listener", async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                accepted = tcp_listener.next() => {
                    let Some((stream, source, target)) = accepted else { break };
                    let context = context.clone();
                    spawn_guarded("android tun tcp flow", async move {
                        if let Err(err) = handle_tcp(stream, source, target, context).await {
                            debug!("TUN TCP flow ended: {err}");
                        }
                    });
                }
            }
        }
        debug!("android TCP listener task exited");
    })
}

async fn handle_tcp(
    mut client: netstack_smoltcp::TcpStream,
    source: SocketAddr,
    target: SocketAddr,
    context: ForwardContext,
) -> Result<()> {
    let (address, proxy_dns_request) = address_for_tun_target(target, context.proxy_dns);
    if !proxy_dns_request {
        reject_tun_target("TCP", source, target, context.tun_networks)?;
    }

    let target_label = if proxy_dns_request {
        format!("{target} -> proxy DNS")
    } else {
        target.to_string()
    };

    let mut direct_target = None;
    let mut direct_reason = None;
    let mut proxy_address = address.clone();
    let mut proxy_reason = None;
    if !proxy_dns_request && context.direct_checker.is_direct(&address) {
        direct_target = Some(target);
    }

    if direct_target.is_none()
        && !proxy_dns_request
        && let Some(domain) = context
            .direct_domain_cache
            .matching_domain_for_ip(target.ip(), |domain| {
                context.direct_checker.is_direct_domain(domain)
            })
    {
        debug!(
            "Android TUN TCP cached direct domain matched: {} ({})",
            target, domain
        );
        direct_reason = Some(format!("cached domain {domain}"));
        direct_target = Some(target);
    }

    if direct_target.is_none()
        && !proxy_dns_request
        && let Some(domain) = context
            .direct_domain_cache
            .matching_domain_for_ip(target.ip(), |_| true)
    {
        debug!(
            "Android TUN TCP cached proxy domain matched: {} ({})",
            target, domain
        );
        proxy_address = domain_address(&domain, target.port());
        proxy_reason = Some(format!("cached domain {domain}"));
    }

    let mut sniffed = Vec::new();
    if direct_target.is_none() && !proxy_dns_request {
        sniffed = sniff_first_bytes(&mut client, target.port()).await;
        if !sniffed.is_empty()
            && let Some(domain) = sniff_domain(target.port(), &sniffed)
        {
            debug!("Android TUN TCP sniffed domain {} <- {}", domain, target);
            context
                .direct_domain_cache
                .record_resolution(&domain, &[target.ip().to_string()]);
            if context.direct_checker.is_direct_domain(&domain) {
                debug!(
                    "Android TUN TCP sniffed direct domain matched: {} ({})",
                    target, domain
                );
                direct_reason = Some(format!("sniffed domain {domain}"));
                direct_target = Some(target);
            } else {
                debug!(
                    "Android TUN TCP sniffed proxy domain matched: {} ({})",
                    target, domain
                );
                proxy_address = domain_address(&domain, target.port());
                proxy_reason = Some(format!("sniffed domain {domain}"));
            }
        }
    }

    if let Some(connect_target) = direct_target {
        let target_str = match direct_reason {
            Some(reason) => format!("{connect_target} ({reason}, original {target})"),
            None => format!("{connect_target} (original {target})"),
        };
        debug!("Android TUN TCP direct -> {}", target_str);
        android_log::info(format!("Android TUN TCP DIRECT {target_str}"));
        let mut target_stream = connect_direct_tcp(connect_target).await.map_err(|e| {
            android_log::warn(format!("Android TUN TCP DIRECT failed {target_str}: {e}"));
            AndroidAgentError::Connection(format!("direct connect {target_str} failed: {e}"))
        })?;
        if !sniffed.is_empty() {
            if let Err(e) = target_stream.write_all(&sniffed).await {
                debug!("Android TUN TCP direct initial bytes write failed: {e}");
            } else if let Err(e) = target_stream.flush().await {
                debug!("Android TUN TCP direct initial bytes flush failed: {e}");
            }
        }
        if let Err(e) = tokio::io::copy_bidirectional_with_sizes(
            &mut client,
            &mut target_stream,
            DEFAULT_STREAM_RELAY_BUFFER_SIZE,
            DEFAULT_STREAM_RELAY_BUFFER_SIZE,
        )
        .await
        {
            debug!("Android TUN TCP direct relay ended: {e}");
        }
        let _ = client.shutdown().await;
        return Ok(());
    }

    let proxy_label = proxy_target_label(&target_label, proxy_reason.as_deref());
    if proxy_dns_request {
        debug!("Android TUN TCP DNS -> proxy -> {}", target_label);
    } else {
        debug!("Android TUN TCP proxy -> {}", proxy_label);
        android_log::info(format!("Android TUN TCP PROXY {proxy_label}"));
    }
    let mut proxy_io = match context
        .tcp_pool
        .get_connected_stream(proxy_address, TransportProtocol::Tcp)
        .await
    {
        Ok(proxy_io) => proxy_io,
        Err(e) => {
            android_log::error(format!(
                "Android TUN TCP PROXY connect failed {proxy_label}: {e}"
            ));
            return Err(e);
        }
    };
    if !sniffed.is_empty() {
        if let Err(e) = proxy_io.write_all(&sniffed).await {
            debug!("Android TUN TCP proxy initial bytes write failed: {e}");
        } else if let Err(e) = proxy_io.flush().await {
            debug!("Android TUN TCP proxy initial bytes flush failed: {e}");
        }
    }
    if let Err(e) = tokio::io::copy_bidirectional_with_sizes(
        &mut client,
        &mut proxy_io,
        DEFAULT_STREAM_RELAY_BUFFER_SIZE,
        DEFAULT_STREAM_RELAY_BUFFER_SIZE,
    )
    .await
    {
        debug!("Android TUN TCP proxy relay ended: {e}");
    }
    let _ = client.shutdown().await;
    Ok(())
}

async fn sniff_first_bytes(client: &mut netstack_smoltcp::TcpStream, port: u16) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(SNIFF_MAX_BYTES);
    let deadline = tokio::time::Instant::now() + SNIFF_TIMEOUT;
    let mut chunk = [0u8; 1024];

    loop {
        if buffer.len() >= SNIFF_MAX_BYTES {
            break;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, client.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                buffer.extend_from_slice(&chunk[..n]);
                if sniff_domain(port, &buffer).is_some() {
                    break;
                }
            }
            Ok(Err(e)) => {
                debug!("Android TUN TCP sniff read failed: {e}");
                break;
            }
            Err(_) => break,
        }
    }

    buffer
}

fn sniff_domain(port: u16, buf: &[u8]) -> Option<String> {
    match port {
        80 | 8080 | 8000 => extract_http_host(buf).or_else(|| extract_tls_sni(buf)),
        _ => extract_tls_sni(buf).or_else(|| extract_http_host(buf)),
    }
}

fn domain_address(domain: &str, port: u16) -> Address {
    Address::Domain {
        host: domain.to_string(),
        port,
    }
}

fn proxy_target_label(target_label: &str, reason: Option<&str>) -> String {
    match reason {
        Some(reason) => format!("{reason}, original {target_label}"),
        None => target_label.to_string(),
    }
}

async fn connect_direct_tcp(target: SocketAddr) -> std::io::Result<TcpStream> {
    let socket = Socket::new(
        Domain::for_address(target),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    protect_direct_socket(&socket)?;
    enable_direct_tcp_keepalive(&socket, target);
    socket.set_nonblocking(true)?;

    let socket = TcpSocket::from_std_stream(socket.into());
    socket.connect(target).await
}

fn enable_direct_tcp_keepalive(socket: &Socket, target: SocketAddr) {
    tune_direct_tcp_socket(socket, target);

    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(30))
        .with_retries(4);

    if let Err(err) = socket.set_tcp_keepalive(&keepalive) {
        debug!("Android TUN TCP direct keepalive setup failed target={target}: {err}");
    }
}

fn tune_direct_tcp_socket(socket: &Socket, target: SocketAddr) {
    if let Err(err) = socket.set_tcp_nodelay(true) {
        debug!("Android TUN TCP direct TCP_NODELAY setup failed target={target}: {err}");
    }
    if let Err(err) = socket.set_recv_buffer_size(crate::config::ANDROID_SOCKET_BUFFER_SIZE) {
        debug!("Android TUN TCP direct recv buffer setup failed target={target}: {err}");
    }
    if let Err(err) = socket.set_send_buffer_size(crate::config::ANDROID_SOCKET_BUFFER_SIZE) {
        debug!("Android TUN TCP direct send buffer setup failed target={target}: {err}");
    }
}

fn protect_direct_socket(socket: &Socket) -> std::io::Result<()> {
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
