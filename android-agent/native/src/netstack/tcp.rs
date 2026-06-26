use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use common::{TCP_RELAY_COPY_BUFFER_SIZE, spawn_guarded};
use futures::StreamExt;
use protocol::TransportProtocol;
use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpSocket, TcpStream};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use super::ForwardContext;
use super::network::{address_for_tun_target, reject_tun_target};
use crate::android_log;
use crate::error::{AndroidAgentError, Result};

const TUN_TCP_PREFETCH_LIMIT: usize = 64 * 1024;
const TUN_TCP_PREFETCH_CHUNK: usize = 16 * 1024;

struct AndroidTcpRelayIo<'a, S> {
    inner: &'a mut S,
    label: &'a str,
}

impl<'a, S> AndroidTcpRelayIo<'a, S> {
    fn new(inner: &'a mut S, label: &'a str) -> Self {
        Self { inner, label }
    }
}

impl<S> AsyncRead for AndroidTcpRelayIo<'_, S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut *this.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for AndroidTcpRelayIo<'_, S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut *this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut *this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut *this.inner).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) if can_ignore_tcp_shutdown_error(&error) => {
                // Android TUN 里的请求方向经常比响应方向先结束。BrokenPipe/Reset
                // 多数只是对端已经先关写半边，不能因为这个取消响应方向剩余数据；
                // 否则浏览器看到的 HLS 分片就可能“读了一半停住”。
                debug!(
                    "Android TUN TCP relay 忽略 {} shutdown 错误：{}",
                    this.label, error
                );
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

async fn relay_tun_tcp_bidirectional<C, R>(
    client: &mut C,
    remote: &mut R,
    label: &str,
) -> io::Result<(u64, u64)>
where
    C: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    // Android 端不再维护单独 buffer 或手写 flush 状态机；直连、legacy proxy、
    // Yamux proxy 都统一适配成 AsyncRead/AsyncWrite 后交给 Tokio copy_bidirectional。
    let mut client_io = AndroidTcpRelayIo::new(client, label);
    let mut remote_io = AndroidTcpRelayIo::new(remote, label);
    tokio::io::copy_bidirectional_with_sizes(
        &mut client_io,
        &mut remote_io,
        TCP_RELAY_COPY_BUFFER_SIZE,
        TCP_RELAY_COPY_BUFFER_SIZE,
    )
    .await
}

fn can_ignore_tcp_shutdown_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset | io::ErrorKind::NotConnected
    )
}

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
        match relay_tun_tcp_bidirectional(&mut client, &mut target_stream, "direct").await {
            Ok((up, down)) => debug!("Android TUN TCP direct relay ended up={up} down={down}"),
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
    match relay_tun_tcp_bidirectional(&mut client, &mut proxy_io, "proxy").await {
        Ok((up, down)) => debug!("Android TUN TCP proxy relay ended up={up} down={down}"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};

    #[tokio::test]
    async fn proxy_relay_keeps_response_after_client_half_close() {
        let (mut client_relay, mut client_peer) = tokio::io::duplex(1024);
        let (mut proxy_relay, mut proxy_peer) = tokio::io::duplex(1024);

        let relay = tokio::spawn(async move {
            relay_tun_tcp_bidirectional(&mut client_relay, &mut proxy_relay, "test").await
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

    #[tokio::test]
    async fn proxy_relay_keeps_response_when_request_shutdown_errors() {
        let (mut client_relay, mut client_peer) = tokio::io::duplex(1024);
        let mut proxy = ShutdownErrorProxy::new(b"complete-body");

        let relay = tokio::spawn(async move {
            relay_tun_tcp_bidirectional(&mut client_relay, &mut proxy, "test").await
        });

        client_peer.write_all(b"GET").await.unwrap();
        client_peer.shutdown().await.unwrap();

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

    struct ShutdownErrorProxy {
        state: Arc<Mutex<ShutdownErrorProxyState>>,
    }

    struct ShutdownErrorProxyState {
        body: VecDeque<u8>,
        body_released: bool,
        read_waker: Option<Waker>,
    }

    impl ShutdownErrorProxy {
        fn new(body: &[u8]) -> Self {
            Self {
                state: Arc::new(Mutex::new(ShutdownErrorProxyState {
                    body: body.iter().copied().collect(),
                    body_released: false,
                    read_waker: None,
                })),
            }
        }
    }

    impl AsyncRead for ShutdownErrorProxy {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let mut state = self.state.lock().unwrap();
            if !state.body_released {
                state.read_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }

            while buf.remaining() > 0 {
                let Some(byte) = state.body.pop_front() else {
                    break;
                };
                buf.put_slice(&[byte]);
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ShutdownErrorProxy {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            let mut state = self.state.lock().unwrap();
            state.body_released = true;
            if let Some(waker) = state.read_waker.take() {
                waker.wake();
            }
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "synthetic shutdown error",
            )))
        }
    }
}
