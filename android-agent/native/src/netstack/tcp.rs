use std::net::SocketAddr;
use std::time::Duration;

use common::{DEFAULT_STREAM_RELAY_BUFFER_SIZE, spawn_guarded};
use futures::StreamExt;
use protocol::{Address, TransportProtocol};
use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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
/// Android VPN 中视频 App/浏览器也会产生大量 HTTPS 短连接；嗅探等待需要压低，
/// 否则每个 HLS 分片请求都会额外叠加首包延迟。
const SNIFF_TIMEOUT: Duration = Duration::from_millis(60);
/// 已经读到部分首包后，后续补读只等待一个很短的空闲窗口，避免 TLS record
/// 被慢速拆包时把 VPN 数据面卡到总超时。
const SNIFF_INTER_READ_TIMEOUT: Duration = Duration::from_millis(10);

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
    if direct_target.is_none() && !proxy_dns_request && proxy_reason.is_none() {
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
    if let Err(e) =
        relay_tun_tcp_proxy_with_flush(&mut client, &mut proxy_io, DEFAULT_STREAM_RELAY_BUFFER_SIZE)
            .await
    {
        debug!("Android TUN TCP proxy relay ended: {e}");
    }
    let _ = client.shutdown().await;
    Ok(())
}

async fn relay_tun_tcp_proxy_with_flush<C, P>(
    client: &mut C,
    proxy_io: &mut P,
    relay_buffer_size: usize,
) -> std::io::Result<(u64, u64)>
where
    C: AsyncRead + AsyncWrite + Unpin,
    P: AsyncRead + AsyncWrite + Unpin,
{
    // Android VPN 的 proxy 路径最终会落到 legacy ClientStream 或 Yamux stream。
    // legacy 常规通道写入的是 DataPacket 协议帧：只 poll_write 可能先停在 framed
    // writer 的内部缓冲中。这里和桌面 TUN proxy 路径保持一致，每次转发后显式
    // flush，同时用半关闭状态机保留 TCP 的单方向 EOF 语义，避免视频分片响应被
    // 过早截断。
    let (mut client_reader, mut client_writer) = tokio::io::split(client);
    let (mut proxy_reader, mut proxy_writer) = tokio::io::split(proxy_io);
    let mut client_buf = vec![0u8; relay_buffer_size];
    let mut proxy_buf = vec![0u8; relay_buffer_size];
    let mut client_done = false;
    let mut proxy_done = false;
    let mut client_to_proxy = 0u64;
    let mut proxy_to_client = 0u64;

    loop {
        if client_done && proxy_done {
            break;
        }

        tokio::select! {
            read = client_reader.read(&mut client_buf), if !client_done => {
                match read {
                    Ok(0) => {
                        client_done = true;
                        // 客户端请求方向 EOF 只关闭 proxy 写半边，响应方向仍要继续
                        // 排空；这对 HLS/HTTPS 分片尤其重要。
                        proxy_writer.shutdown().await?;
                    }
                    Ok(n) => {
                        proxy_writer.write_all(&client_buf[..n]).await?;
                        proxy_writer.flush().await?;
                        client_to_proxy += n as u64;
                    }
                    Err(e) => return Err(e),
                }
            }
            read = proxy_reader.read(&mut proxy_buf), if !proxy_done => {
                match read {
                    Ok(0) => {
                        proxy_done = true;
                        // proxy 响应方向 EOF 时只通知本地 TCP 写半边结束；如果客户
                        // 端还有待发送数据，另一方向仍可自然走到 EOF。
                        client_writer.shutdown().await?;
                    }
                    Ok(n) => {
                        client_writer.write_all(&proxy_buf[..n]).await?;
                        client_writer.flush().await?;
                        proxy_to_client += n as u64;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }

    Ok((client_to_proxy, proxy_to_client))
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
        let read_timeout = if buffer.is_empty() {
            remaining
        } else {
            remaining.min(SNIFF_INTER_READ_TIMEOUT)
        };
        match timeout(read_timeout, client.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                buffer.extend_from_slice(&chunk[..n]);
                if sniff_buffer_ready(port, &buffer) {
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

fn sniff_buffer_ready(port: u16, buf: &[u8]) -> bool {
    if sniff_domain(port, buf).is_some() {
        return true;
    }

    // Android VPN 模式下，浏览器和视频 App 的 HTTPS/HLS 请求经常表现为大量短 TCP
    // 连接。如果 TLS ClientHello 没有可见 SNI（例如 ECH、特殊握手或非标准客户端），
    // 继续等满 SNIFF_TIMEOUT 会给每条新连接叠加首包延迟；一旦已经拿到完整 TLS
    // record 或完整 HTTP 头，就立即放行，把已读字节原样补发给目标或 proxy。
    has_complete_tls_record(buf) || has_complete_http_headers(buf)
}

fn has_complete_tls_record(buf: &[u8]) -> bool {
    if buf.len() < 5 || buf[0] != 0x16 {
        return false;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    buf.len() >= 5usize.saturating_add(record_len)
}

fn has_complete_http_headers(buf: &[u8]) -> bool {
    std::str::from_utf8(buf)
        .map(|text| text.contains("\r\n\r\n"))
        .unwrap_or(false)
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn sniff_buffer_waits_for_complete_tls_record() {
        let partial_tls = [0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x02];
        let complete_tls = [0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04];

        assert!(!sniff_buffer_ready(443, &partial_tls));
        assert!(sniff_buffer_ready(443, &complete_tls));
    }

    #[test]
    fn sniff_buffer_stops_on_complete_http_headers() {
        let partial_http = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        let complete_http = b"GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n";

        assert!(!has_complete_http_headers(partial_http));
        assert!(has_complete_http_headers(complete_http));
        assert!(sniff_buffer_ready(443, complete_http));
    }

    #[tokio::test]
    async fn proxy_relay_keeps_response_after_client_half_close() {
        let (mut client_relay, mut client_peer) = tokio::io::duplex(1024);
        let (mut proxy_relay, mut proxy_peer) = tokio::io::duplex(1024);

        let relay = tokio::spawn(async move {
            relay_tun_tcp_proxy_with_flush(&mut client_relay, &mut proxy_relay, 64).await
        });

        // 模拟 Android VPN 里的请求方向先结束。relay 只能关闭 proxy 写半边，
        // 不能因此丢掉 proxy 随后返回的响应体。
        client_peer.write_all(b"GET").await.unwrap();
        client_peer.shutdown().await.unwrap();

        let mut request = [0u8; 3];
        proxy_peer.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"GET");

        let mut eof_probe = [0u8; 1];
        assert_eq!(proxy_peer.read(&mut eof_probe).await.unwrap(), 0);

        proxy_peer.write_all(b"complete-body").await.unwrap();
        proxy_peer.shutdown().await.unwrap();

        let mut response = Vec::new();
        client_peer.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"complete-body");

        let (client_to_proxy, proxy_to_client) =
            tokio::time::timeout(Duration::from_secs(5), relay)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        assert_eq!(client_to_proxy, 3);
        assert_eq!(proxy_to_client, b"complete-body".len() as u64);
    }
}
