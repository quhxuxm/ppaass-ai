use std::net::SocketAddr;
use std::time::Duration;

use common::spawn_guarded;
use futures::StreamExt;
use protocol::TransportProtocol;
use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use super::ForwardContext;
use super::network::{address_for_tun_target, reject_tun_target};
use crate::android_log;
use crate::error::{AndroidAgentError, Result};
use crate::tcp_relay::{TcpRelayOptions, relay_tcp_bidirectional};

const TUN_TCP_PREFETCH_LIMIT: usize = 64 * 1024;
const TUN_TCP_PREFETCH_CHUNK: usize = 16 * 1024;

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
    let proxy_address = address.clone();
    let mut proxy_reason = None;
    if !proxy_dns_request && context.direct_checker.is_direct(&address) {
        direct_target = Some(target);
    }

    if direct_target.is_none()
        && !proxy_dns_request
        && context.direct_checker.has_domain_direct_rules()
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
            "Android TUN TCP cached proxy domain matched for label only: {} ({})，proxy target keeps original IP",
            target, domain
        );
        proxy_reason = Some(format!("cached domain {domain}"));
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
        match relay_tcp_bidirectional(
            &mut client,
            &mut target_stream,
            TcpRelayOptions::tun("direct"),
        )
        .await
        {
            Ok(stats) => debug!(
                "Android TUN TCP direct relay ended up={} down={}",
                stats.client_to_remote, stats.remote_to_client
            ),
            Err(e) => debug!("Android TUN TCP direct relay ended: {e}"),
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
    let (mut proxy_io, prefetched) = match connect_proxy_stream_with_tun_prefetch(
        &mut client,
        &context,
        proxy_address,
        &proxy_label,
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            android_log::error(format!(
                "Android TUN TCP PROXY connect failed {proxy_label}: {e}"
            ));
            return Err(e);
        }
    };
    if !prefetched.is_empty() {
        // 这里只做原样补写，不解析 TLS SNI/HTTP Host，也不参与直连规则。
        // Android TUN 的三次握手已经由 netstack 接住；等待 proxy 建连时如果完全不读本地流，
        // 浏览器或视频 App 的首包会被接收窗口卡住。缓存少量字节并在远端通道建立后立即写出，
        // 可以减少 HLS 小分片连接在建连阶段的抖动。
        proxy_io.write_all(&prefetched).await?;
        proxy_io.flush().await?;
    }
    // Android TUN TCP 不再抢读首包做 SNI/Host 嗅探。proxy 路径直接把原始
    // netstack TCP 流交给 copy_bidirectional，避免“先读后补发”影响视频分片。
    match relay_tcp_bidirectional(&mut client, &mut proxy_io, TcpRelayOptions::tun("proxy")).await {
        Ok(stats) => debug!(
            "Android TUN TCP proxy relay ended up={} down={}",
            stats.client_to_remote, stats.remote_to_client
        ),
        Err(e) => debug!("Android TUN TCP proxy relay ended: {e}"),
    }
    let _ = client.shutdown().await;
    Ok(())
}

fn proxy_target_label(target_label: &str, reason: Option<&str>) -> String {
    match reason {
        Some(reason) => format!("{reason}, original {target_label}"),
        None => target_label.to_string(),
    }
}

async fn connect_proxy_stream_with_tun_prefetch(
    client: &mut netstack_smoltcp::TcpStream,
    context: &ForwardContext,
    proxy_address: protocol::Address,
    label: &str,
) -> Result<(crate::yamux_session::AndroidYamuxTargetStream, Vec<u8>)> {
    let mut connect = Box::pin(
        context
            .tcp_sessions
            .connect_to_target(proxy_address, TransportProtocol::Tcp),
    );
    let mut prefetched = Vec::with_capacity(TUN_TCP_PREFETCH_CHUNK);

    loop {
        if prefetched.len() >= TUN_TCP_PREFETCH_LIMIT {
            debug!(
                "Android TUN TCP prefetch reached {} bytes, waiting for proxy connect: {}",
                TUN_TCP_PREFETCH_LIMIT, label
            );
            let proxy_io = connect.await?;
            return Ok((proxy_io, prefetched));
        }

        let remaining = TUN_TCP_PREFETCH_LIMIT - prefetched.len();
        let mut buf = vec![0u8; remaining.min(TUN_TCP_PREFETCH_CHUNK)];
        tokio::select! {
            proxy_io = &mut connect => {
                return Ok((proxy_io?, prefetched));
            }
            read = client.read(&mut buf) => {
                let read = read?;
                if read == 0 {
                    if prefetched.is_empty() {
                        return Err(AndroidAgentError::Connection(format!(
                            "Android TUN TCP client closed before proxy connect: {label}"
                        )));
                    }
                    let proxy_io = connect.await?;
                    return Ok((proxy_io, prefetched));
                }
                prefetched.extend_from_slice(&buf[..read]);
            }
        }
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
