//! 桌面端 TCP 隧道中继的统一实现。
//!
//! TUN、HTTP CONNECT、SOCKS CONNECT/BIND 最终都是“本地客户端流 <-> 远端流”的
//! 双向字节中继。过去各入口分别使用 `copy_bidirectional_with_sizes` 或手写循环，
//! 容易出现某一路径修了半关闭/flush，另一条路径仍保留旧行为。
//!
//! 这里集中处理三件事：
//! 1. 默认路径走 Tokio copy，保留较好的吞吐和批量 flush 行为；
//! 2. legacy DataPacket/SinkWriter 可按需开启逐写 flush，避免请求/窗口更新滞留；
//! 3. TUN 写回浏览器时只发起 shutdown，不等待 netstack-smoltcp 完全 Closed。

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::Poll;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

/// 一次双向 TCP relay 的字节统计。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpRelayStats {
    pub client_to_remote: u64,
    pub remote_to_client: u64,
}

#[derive(Debug)]
struct RelayDirectionOutcome {
    bytes: u64,
    error: Option<io::Error>,
}

impl RelayDirectionOutcome {
    fn ok(bytes: u64) -> Self {
        Self { bytes, error: None }
    }

    fn err(bytes: u64, error: io::Error) -> Self {
        Self {
            bytes,
            error: Some(error),
        }
    }
}

/// 本地客户端写半边的关闭方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientShutdownMode {
    /// 普通 TCP/HTTP/SOCKS 路径：等待 writer 完成标准 shutdown。
    AwaitClosed,
    /// TUN/netstack 路径：只 poll 一次 shutdown，触发 FIN 后立刻返回。
    ///
    /// netstack-smoltcp 的 shutdown 会等到底层 TCP 进入完全 Closed；每个 HLS 分片
    /// 尾部都等待这个状态会放大卡顿。第一次 poll 已经把 send_state 标成 Close，
    /// runner 会继续排空 send_buffer 并发送 FIN。
    InitiateOnly,
}

/// 中继结束策略。
#[derive(Debug, Clone, Copy)]
pub struct TcpRelayOptions<'a> {
    /// 日志标签，用于定位具体目标。
    pub label: &'a str,
    /// remote->client 方向 EOF 后，关闭本地客户端写半边的方式。
    pub client_shutdown: ClientShutdownMode,
    /// 是否每次 write 后立即 flush。只应给 legacy framed DataPacket 通道开启；
    /// 裸 TCP/Yamux 使用 Tokio copy 或延迟 flush 吞吐更稳。
    pub flush_each_write: bool,
    /// 是否强制使用手写 relay。TUN 需要特殊 shutdown；普通路径可走 Tokio copy。
    pub force_manual: bool,
}

impl<'a> TcpRelayOptions<'a> {
    pub fn standard(label: &'a str) -> Self {
        Self {
            label,
            client_shutdown: ClientShutdownMode::AwaitClosed,
            flush_each_write: false,
            force_manual: false,
        }
    }

    pub fn tun(label: &'a str) -> Self {
        Self {
            label,
            client_shutdown: ClientShutdownMode::InitiateOnly,
            flush_each_write: false,
            force_manual: true,
        }
    }

    pub fn tun_framed(label: &'a str) -> Self {
        Self {
            label,
            client_shutdown: ClientShutdownMode::InitiateOnly,
            flush_each_write: true,
            force_manual: true,
        }
    }

    /// HTTP CONNECT / SOCKS5 代理入口连接到 legacy framed proxy stream 时使用。
    ///
    /// framed 写端需要逐写 flush，确保 DataPacket 不滞留；但本地客户端是普通
    /// TCP socket，不是 netstack-smoltcp，因此 EOF 后仍等待标准 shutdown 完成。
    pub fn framed_proxy(label: &'a str) -> Self {
        Self {
            label,
            client_shutdown: ClientShutdownMode::AwaitClosed,
            flush_each_write: true,
            force_manual: true,
        }
    }
}

/// 统一 TCP 隧道 relay。
///
/// `client` 表示本地应用/浏览器侧；`remote` 表示直连目标或 proxy stream。
/// 返回值顺序固定为 client->remote、remote->client，方便各入口记录 telemetry。
pub async fn relay_tcp_bidirectional<C, R>(
    client: &mut C,
    remote: &mut R,
    relay_buffer_size: usize,
    options: TcpRelayOptions<'_>,
) -> io::Result<TcpRelayStats>
where
    C: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    if !options.force_manual && !options.flush_each_write {
        let (client_to_remote, remote_to_client) = tokio::io::copy_bidirectional_with_sizes(
            client,
            remote,
            relay_buffer_size,
            relay_buffer_size,
        )
        .await?;
        return Ok(TcpRelayStats {
            client_to_remote,
            remote_to_client,
        });
    }

    let (mut client_reader, mut client_writer) = tokio::io::split(client);
    let (mut remote_reader, mut remote_writer) = tokio::io::split(remote);
    let mut client_buf = vec![0u8; relay_buffer_size];
    let mut remote_buf = vec![0u8; relay_buffer_size];

    // client->remote 与 remote->client 必须并发，而不是放进单个 select 分支后
    // 在分支里长时间 await write/shutdown。后者会让一侧的慢 shutdown 挡住另一侧
    // 读取 FIN、窗口更新或剩余响应数据。
    let client_to_remote = async {
        let mut bytes = 0u64;
        loop {
            match client_reader.read(&mut client_buf).await {
                Ok(0) => {
                    // 本地请求方向 EOF 只表示 remote 写半边应该结束，remote->client
                    // 方向仍要继续排空。
                    if !options.flush_each_write
                        && let Err(error) = remote_writer.flush().await
                    {
                        return RelayDirectionOutcome::err(bytes, error);
                    }
                    if let Err(error) = remote_writer.shutdown().await {
                        return RelayDirectionOutcome::err(bytes, error);
                    }
                    break;
                }
                Ok(n) => {
                    if let Err(error) = remote_writer.write_all(&client_buf[..n]).await {
                        return RelayDirectionOutcome::err(bytes, error);
                    }
                    // legacy DataPacket/SinkWriter 需要 flush 才能推动 framed writer。
                    // 裸 TCP/Yamux 不开启逐写 flush，避免高吞吐分片被小 flush 打碎。
                    if options.flush_each_write
                        && let Err(error) = remote_writer.flush().await
                    {
                        return RelayDirectionOutcome::err(bytes, error);
                    }
                    bytes += n as u64;
                }
                Err(error) => return RelayDirectionOutcome::err(bytes, error),
            }
        }
        RelayDirectionOutcome::ok(bytes)
    };

    let remote_to_client = async {
        let mut bytes = 0u64;
        loop {
            match remote_reader.read(&mut remote_buf).await {
                Ok(0) => {
                    if !options.flush_each_write
                        && let Err(error) = client_writer.flush().await
                    {
                        return RelayDirectionOutcome::err(bytes, error);
                    }
                    if let Err(error) = shutdown_client_writer(&mut client_writer, options).await {
                        return RelayDirectionOutcome::err(bytes, error);
                    }
                    break;
                }
                Ok(n) => {
                    if let Err(error) = client_writer.write_all(&remote_buf[..n]).await {
                        return RelayDirectionOutcome::err(bytes, error);
                    }
                    if options.flush_each_write
                        && let Err(error) = client_writer.flush().await
                    {
                        return RelayDirectionOutcome::err(bytes, error);
                    }
                    bytes += n as u64;
                }
                Err(error) => return RelayDirectionOutcome::err(bytes, error),
            }
        }
        RelayDirectionOutcome::ok(bytes)
    };

    // 这里不能使用 try_join!。TUN/浏览器/远端服务器关闭 TCP 半边的时序并不总是
    // 对称，请求方向在 shutdown 时出现 BrokenPipe 往往只表示对端已经不再接收
    // 请求体；此时响应方向可能还有 HLS 分片数据正在写回浏览器。若 try_join!
    // 立即取消另一个 future，就会制造“分片只下载了一部分”的假截断。
    let (client_to_remote, remote_to_client) = tokio::join!(client_to_remote, remote_to_client);
    let client_to_remote_error = client_to_remote.error;
    let remote_to_client_error = remote_to_client.error;
    if let Some(error) = &client_to_remote_error {
        debug!(
            "TCP relay client->remote 方向结束时有错误，已继续等待 remote->client 排空：target={} error={}",
            options.label, error
        );
    }
    if let Some(error) = &remote_to_client_error {
        debug!(
            "TCP relay remote->client 方向结束时有错误，已继续等待 client->remote 收尾：target={} error={}",
            options.label, error
        );
    }

    Ok(TcpRelayStats {
        client_to_remote: client_to_remote.bytes,
        remote_to_client: remote_to_client.bytes,
    })
}

async fn shutdown_client_writer<W>(writer: &mut W, options: TcpRelayOptions<'_>) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    match options.client_shutdown {
        ClientShutdownMode::AwaitClosed => writer.shutdown().await,
        ClientShutdownMode::InitiateOnly => {
            let result = poll_fn(|cx| match Pin::new(&mut *writer).poll_shutdown(cx) {
                Poll::Ready(result) => Poll::Ready(result),
                Poll::Pending => Poll::Ready(Ok(())),
            })
            .await;
            if result.is_ok() {
                debug!(
                    "TCP relay 已触发本地客户端写半边关闭，不等待完全 Closed：target={}",
                    options.label
                );
            }
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Waker};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};

    #[tokio::test]
    async fn relay_keeps_response_after_client_half_close() {
        let (mut client_relay, mut client_peer) = tokio::io::duplex(1024);
        let (mut remote_relay, mut remote_peer) = tokio::io::duplex(1024);

        let relay = tokio::spawn(async move {
            relay_tcp_bidirectional(
                &mut client_relay,
                &mut remote_relay,
                64,
                TcpRelayOptions::standard("test"),
            )
            .await
        });

        client_peer.write_all(b"GET").await.unwrap();
        client_peer.shutdown().await.unwrap();

        let mut request = [0u8; 3];
        remote_peer.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"GET");

        let mut eof_probe = [0u8; 1];
        assert_eq!(remote_peer.read(&mut eof_probe).await.unwrap(), 0);

        remote_peer.write_all(b"complete-body").await.unwrap();
        remote_peer.shutdown().await.unwrap();

        let mut response = Vec::new();
        client_peer.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"complete-body");

        let stats = tokio::time::timeout(std::time::Duration::from_secs(5), relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(stats.client_to_remote, 3);
        assert_eq!(stats.remote_to_client, b"complete-body".len() as u64);
    }

    #[tokio::test]
    async fn manual_framed_relay_keeps_response_after_client_half_close() {
        let (mut client_relay, mut client_peer) = tokio::io::duplex(1024);
        let (mut remote_relay, mut remote_peer) = tokio::io::duplex(1024);

        let relay = tokio::spawn(async move {
            relay_tcp_bidirectional(
                &mut client_relay,
                &mut remote_relay,
                64,
                TcpRelayOptions::tun_framed("test"),
            )
            .await
        });

        client_peer.write_all(b"GET").await.unwrap();
        client_peer.shutdown().await.unwrap();

        let mut request = [0u8; 3];
        remote_peer.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"GET");

        let mut eof_probe = [0u8; 1];
        assert_eq!(remote_peer.read(&mut eof_probe).await.unwrap(), 0);

        remote_peer.write_all(b"complete-body").await.unwrap();
        remote_peer.shutdown().await.unwrap();

        let mut response = Vec::new();
        client_peer.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"complete-body");

        let stats = tokio::time::timeout(std::time::Duration::from_secs(5), relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(stats.client_to_remote, 3);
        assert_eq!(stats.remote_to_client, b"complete-body".len() as u64);
    }

    #[tokio::test]
    async fn manual_relay_does_not_cancel_response_when_request_shutdown_errors() {
        let (mut client_relay, mut client_peer) = tokio::io::duplex(1024);
        let mut remote = ShutdownErrorRemote::new(b"complete-body");

        let relay = tokio::spawn(async move {
            relay_tcp_bidirectional(
                &mut client_relay,
                &mut remote,
                64,
                TcpRelayOptions::tun("test"),
            )
            .await
        });

        client_peer.write_all(b"GET").await.unwrap();
        client_peer.shutdown().await.unwrap();

        let mut response = Vec::new();
        client_peer.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"complete-body");

        let stats = tokio::time::timeout(std::time::Duration::from_secs(5), relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(stats.client_to_remote, 3);
        assert_eq!(stats.remote_to_client, b"complete-body".len() as u64);
    }

    struct ShutdownErrorRemote {
        state: Arc<Mutex<ShutdownErrorRemoteState>>,
    }

    struct ShutdownErrorRemoteState {
        body: VecDeque<u8>,
        body_released: bool,
        read_waker: Option<Waker>,
    }

    impl ShutdownErrorRemote {
        fn new(body: &[u8]) -> Self {
            Self {
                state: Arc::new(Mutex::new(ShutdownErrorRemoteState {
                    body: body.iter().copied().collect(),
                    body_released: false,
                    read_waker: None,
                })),
            }
        }
    }

    impl AsyncRead for ShutdownErrorRemote {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
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

    impl AsyncWrite for ShutdownErrorRemote {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let mut state = self.state.lock().unwrap();
            state.body_released = true;
            if let Some(waker) = state.read_waker.take() {
                waker.wake();
            }
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "synthetic shutdown error",
            )))
        }
    }
}
