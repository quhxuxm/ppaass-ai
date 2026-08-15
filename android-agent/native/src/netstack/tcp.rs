use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use common::{spawn_guarded, tls_client_hello_server_name};
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
use super::network::{address_for_tun_target, reject_tun_target};
use crate::error::{AndroidAgentError, Result};
use crate::tcp_relay::{TcpRelayOptions, relay_tcp_bidirectional};

const DIRECT_TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const TUN_TCP_PREFETCH_LIMIT: usize = 64 * 1024;
const TUN_TCP_PREFETCH_CHUNK: usize = 16 * 1024;
const TLS_SNI_PREFETCH_TIMEOUT: Duration = Duration::from_millis(250);
const TLS_SNI_PREFETCH_LIMIT: usize = 16 * 1024;

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
    let mut proxy_address = address.clone();
    let mut proxy_reason = None;
    // proxy_dns=false 时 DNS 查询由 agent 直连上游 DNS 服务器。
    if !proxy_dns_request
        && (context.direct_checker.is_direct(&address)
            || (!context.proxy_dns && target.port() == 53))
    {
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
        direct_target = Some(target);
    }

    if direct_target.is_none()
        && !proxy_dns_request
        && let Some(domain) = context
            .direct_domain_cache
            .matching_domain_for_ip(target.ip(), |_| true)
    {
        debug!(
            "Android TUN TCP uses cached domain as proxy target: {} ({})",
            target, domain
        );
        proxy_address = proxy_target_address(proxy_address, Some(&domain));
        proxy_reason = Some(format!("cached domain {domain}"));
    }

    if let Some(connect_target) = direct_target {
        let target_str = target_label.as_str();
        debug!("Android TUN TCP direct -> {}", target_str);
        let direct_connect = async {
            connect_direct_tcp(connect_target).await.map_err(|error| {
                debug!("Android TUN TCP direct connect failed {target_str}: {error}");
                AndroidAgentError::Connection(format!(
                    "direct connect {target_str} failed: {error}"
                ))
            })
        };
        let (mut target_stream, prefetched) =
            connect_with_tun_prefetch(&mut client, direct_connect, &target_str).await?;
        write_prefetched(&mut target_stream, &prefetched).await?;
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
            debug!("Android TUN TCP proxy connect failed {proxy_label}: {e}");
            return Err(e);
        }
    };
    if !prefetched.is_empty() {
        // Android TUN 的三次握手已经由 netstack 接住；等待 proxy 建连时如果完全不读本地流，
        // 浏览器或视频 App 的首包会被接收窗口卡住。缓存内容可能包含用于恢复代理目标域名
        // 的 ClientHello，建立远端连接后必须完整、原样补写。
        write_prefetched(&mut proxy_io, &prefetched).await?;
    }
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
    proxy_address: Address,
    label: &str,
) -> Result<(crate::yamux_session::AndroidYamuxTargetStream, Vec<u8>)> {
    let sni_prefetch = prefetch_tls_sni_for_ip(client, &proxy_address).await?;
    let proxy_address = proxy_target_address(
        proxy_address,
        tls_client_hello_server_name(&sni_prefetch).as_deref(),
    );
    let (stream, mut prefetched) = connect_with_tun_prefetch(
        client,
        context
            .tcp_sessions
            .connect_to_target(proxy_address, TransportProtocol::Tcp),
        label,
    )
    .await?;
    if !sni_prefetch.is_empty() {
        let mut combined = sni_prefetch;
        combined.append(&mut prefetched);
        return Ok((stream, combined));
    }
    Ok((stream, prefetched))
}

pub fn proxy_target_address(original: Address, domain: Option<&str>) -> Address {
    match domain.map(str::trim).filter(|host| !host.is_empty()) {
        Some(host) => Address::Domain {
            host: host.to_string(),
            port: original.port(),
        },
        None => original,
    }
}

pub fn should_prefetch_tls_sni(address: &Address) -> bool {
    address.port() == 443 && matches!(address, Address::Ipv4 { .. } | Address::Ipv6 { .. })
}

async fn prefetch_tls_sni_for_ip(
    client: &mut netstack_smoltcp::TcpStream,
    address: &Address,
) -> Result<Vec<u8>> {
    if !should_prefetch_tls_sni(address) {
        return Ok(Vec::new());
    }

    let mut packet = vec![0_u8; TLS_SNI_PREFETCH_LIMIT];
    match timeout(TLS_SNI_PREFETCH_TIMEOUT, client.read(&mut packet)).await {
        Ok(Ok(0)) | Err(_) => Ok(Vec::new()),
        Ok(Ok(read)) => {
            packet.truncate(read);
            Ok(packet)
        }
        Ok(Err(error)) => Err(error.into()),
    }
}

async fn connect_with_tun_prefetch<T, F>(
    client: &mut netstack_smoltcp::TcpStream,
    connect: F,
    label: &str,
) -> Result<(T, Vec<u8>)>
where
    F: Future<Output = Result<T>>,
{
    let mut connect = Box::pin(connect);
    let mut prefetched = Vec::with_capacity(TUN_TCP_PREFETCH_CHUNK);
    let mut chunk = vec![0u8; TUN_TCP_PREFETCH_CHUNK];

    loop {
        if prefetched.len() >= TUN_TCP_PREFETCH_LIMIT {
            debug!(
                "Android TUN TCP prefetch reached {} bytes, waiting for proxy connect: {}",
                TUN_TCP_PREFETCH_LIMIT, label
            );
            let proxy_io = connect.await?;
            return Ok((proxy_io, prefetched));
        }

        let read_limit = (TUN_TCP_PREFETCH_LIMIT - prefetched.len()).min(chunk.len());
        tokio::select! {
            proxy_io = &mut connect => {
                return Ok((proxy_io?, prefetched));
            }
            read = client.read(&mut chunk[..read_limit]) => {
                let read = read?;
                if read == 0 {
                    if prefetched.is_empty() {
                        return Err(AndroidAgentError::Connection(format!(
                            "Android TUN TCP client closed before remote connect: {label}"
                        )));
                    }
                    let proxy_io = connect.await?;
                    return Ok((proxy_io, prefetched));
                }
                prefetched.extend_from_slice(&chunk[..read]);
            }
        }
    }
}

async fn write_prefetched<W>(remote: &mut W, prefetched: &[u8]) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    if prefetched.is_empty() {
        return Ok(());
    }
    remote.write_all(prefetched).await?;
    remote.flush().await?;
    Ok(())
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
    timeout(DIRECT_TCP_CONNECT_TIMEOUT, socket.connect(target))
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("Android TUN TCP direct connect {target} timed out"),
            )
        })?
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
