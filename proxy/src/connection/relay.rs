//! legacy TCP/UDP 数据中继。
//!
//! agent 与 proxy 之间传的是 `DataPacket`，目标服务器侧通常是裸 TCP/UDP。
//! 本模块的核心工作就是把 packet-based 的 agent 连接适配成 `AsyncRead/AsyncWrite`，
//! 再与目标 socket 做双向搬运。

use super::*;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use tokio::io::ReadBuf;
use tokio::sync::watch;

struct RelayCopyIo<'a, S> {
    inner: &'a mut S,
    label: &'static str,
    activity_tx: watch::Sender<()>,
    read_bytes: Arc<AtomicU64>,
    read_eof: Arc<std::sync::atomic::AtomicBool>,
}

impl<'a, S> RelayCopyIo<'a, S> {
    fn new(
        inner: &'a mut S,
        label: &'static str,
        activity_tx: watch::Sender<()>,
        read_bytes: Arc<AtomicU64>,
        read_eof: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            inner,
            label,
            activity_tx,
            read_bytes,
            read_eof,
        }
    }

    fn mark_activity(&self) {
        // watch 只用作轻量“有活动”信号，不承载数据；发送失败说明 watchdog 已经退出。
        let _ = self.activity_tx.send(());
    }
}

impl<S> AsyncRead for RelayCopyIo<'_, S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let filled_before = buf.filled().len();
        let result = Pin::new(&mut *this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let read = buf.filled().len().saturating_sub(filled_before);
            if read > 0 {
                this.read_bytes.fetch_add(read as u64, Ordering::AcqRel);
                this.mark_activity();
            } else {
                this.read_eof
                    .store(true, std::sync::atomic::Ordering::Release);
                this.mark_activity();
            }
        }
        result
    }
}

impl<S> AsyncWrite for RelayCopyIo<'_, S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut *this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = &result
            && *written > 0
        {
            this.mark_activity();
        }
        result
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
                // copy_bidirectional 的半关闭语义是正确的，但真实网络里 shutdown
                // 可能遇到对端已关闭写半边的 BrokenPipe/Reset。这里把这类错误视为
                // “半关闭已经没有必要继续”，避免请求方向的小错误取消响应方向排空。
                debug!(
                    "TCP relay 忽略 {label} shutdown 错误：{error}",
                    label = this.label
                );
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl ServerConnection {
    #[instrument(skip(self, udp_socket))]
    pub(super) async fn relay_udp(
        &mut self,
        stream_id: String,
        udp_socket: UdpSocket,
    ) -> Result<()> {
        // UDP 没有天然字节流，这里用 StreamReader/SinkWriter 拼成类流式中继。
        // 这个 legacy UDP 路径面向单个已 connect 的 UDP socket；
        // 多目标 UDP 共享连接走 udp_relay.rs 的 flow_id 机制。
        let stream_id_filter = stream_id.clone();

        // 使用自定义 Sink 将 UDP 响应数据重新封装成 proxy DataPacket。
        let sink = BytesToProxyResponseSink {
            inner: &mut self.writer,
            stream_id: stream_id.clone(),
            end_sent: false,
        };

        let stream_id_stop = stream_id.clone();
        // 从 agent 到 UDP 的方向只消费当前 stream_id 的数据包。
        // 遇到同一 stream 的空 end 包时停止，让对端主动关闭能传播到本地中继。
        let stream = (&mut self.reader)
            .take_while(move |res| {
                let continue_stream = match res {
                    Ok(ProxyRequest::Data(packet)) => {
                        !(packet.stream_id == stream_id_stop
                            && packet.is_end
                            && packet.data.is_empty())
                    }
                    Ok(_) => true,
                    // 出错时停止流，防止连接泄漏
                    Err(_) => false,
                };
                futures::future::ready(continue_stream)
            })
            .filter_map(move |res| {
                let result = match res {
                    Ok(ProxyRequest::Data(packet)) => {
                        // 只处理该流的数据包
                        trace!(
                            packet.stream_id,
                            stream_id_filter, "从 agent 收到 UDP 数据包：{packet:?}"
                        );
                        if packet.stream_id == stream_id_filter && !packet.data.is_empty() {
                            Some(Ok(Bytes::from(packet.data)))
                        } else {
                            None
                        }
                    }
                    Ok(_) => None,
                    Err(e) => Some(Err(io::Error::other(e))),
                };

                futures::future::ready(result)
            });

        let writer = SinkWriter::new(sink);
        let reader = StreamReader::new(stream);

        // AgentIo 把“从 agent 读”和“写回 agent”合成一个双向 IO。
        let agent_io = AgentIo { reader, writer };

        let udp_socket = Arc::new(udp_socket);
        let udp_recv = udp_socket.clone();
        let udp_send = udp_socket.clone();

        let (mut agent_reader, mut agent_writer) = tokio::io::split(agent_io);

        let udp_relay_idle_timeout =
            Duration::from_secs(self.proxy_config.udp_relay_idle_timeout_secs);
        let idle_timeout = tokio::time::sleep(udp_relay_idle_timeout);
        tokio::pin!(idle_timeout);
        let mut agent_buf = vec![0u8; 65535];
        let mut udp_buf = vec![0u8; 65535];

        loop {
            // 任一方向有数据就重置 idle；两边都长期无数据才关闭 UDP socket。
            tokio::select! {
                _ = &mut idle_timeout => {
                    debug!(
                        "UDP 中继空闲超过 {} 秒，关闭 socket",
                        udp_relay_idle_timeout.as_secs()
                    );
                    break;
                }
                read = agent_reader.read(&mut agent_buf) => {
                    match read {
                        Ok(0) => break,
                        Ok(n) => {
                            let data = &agent_buf[..n];
                            trace!(
                                "从 agent 收到发往目标的 UDP 数据：{:?}\n{}",
                                udp_socket.peer_addr(),
                                pretty_hex::pretty_hex(&data)
                            );
                            match tokio::time::timeout(udp_relay_idle_timeout, udp_send.send(data)).await {
                                Ok(Ok(_)) => {
                                    idle_timeout.as_mut().reset(tokio::time::Instant::now() + udp_relay_idle_timeout);
                                }
                                Ok(Err(e)) => {
                                    debug!("UDP 发送错误：{}", e);
                                    break;
                                }
                                Err(_) => {
                                    debug!("UDP 发送超过 {} 秒，关闭 socket", udp_relay_idle_timeout.as_secs());
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            debug!("读取 agent 数据错误：{}", e);
                            break;
                        }
                    }
                }
                recv = udp_recv.recv(&mut udp_buf) => {
                    match recv {
                        Ok(n) => {
                            let data = &udp_buf[..n];
                            trace!(
                                "从目标收到发往 agent 的 UDP 数据：{:?}\n{}",
                                udp_socket.peer_addr(),
                                pretty_hex::pretty_hex(&data)
                            );
                            let write_result = tokio::time::timeout(udp_relay_idle_timeout, async {
                                agent_writer.write_all(data).await?;
                                agent_writer.flush().await
                            }).await;
                            match write_result {
                                Ok(Ok(())) => {
                                    idle_timeout.as_mut().reset(tokio::time::Instant::now() + udp_relay_idle_timeout);
                                }
                                Ok(Err(e)) => {
                                    debug!("写入 agent 数据错误：{}", e);
                                    break;
                                }
                                Err(_) => {
                                    debug!("写入 agent 超过 {} 秒，关闭 UDP 中继", udp_relay_idle_timeout.as_secs());
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            debug!("UDP 接收错误：{}", e);
                            break;
                        }
                    }
                }
            }
        }

        debug!("UDP 中继已结束");
        Ok(())
    }

    pub(super) async fn relay<S>(&mut self, stream_id: String, target_stream: &mut S) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        // TCP 中继把 agent 数据包流和目标 TCP 流转换成双向字节拷贝。
        // legacy 模式下，一条 agent->proxy TCP 连接通常只服务一个 request_id。
        let stream_id_filter = stream_id.clone();

        // 使用自定义 Sink 实现，避免 SinkExt::with 与闭包引发 HRTB 问题
        let sink = BytesToProxyResponseSink {
            inner: &mut self.writer,
            stream_id: stream_id.clone(),
            end_sent: false,
        };

        let stream_id_stop = stream_id.clone();
        // agent 数据流中可能混有其他消息，只取当前 stream 的 DataPacket。
        // 这种过滤让同一 reader 的非 Data/其他 stream_id 消息不会污染当前目标连接。
        let stream = (&mut self.reader)
            .take_while(move |res| {
                let continue_stream = match res {
                    Ok(ProxyRequest::Data(packet)) => {
                        !(packet.stream_id == stream_id_stop
                            && packet.is_end
                            && packet.data.is_empty())
                    }
                    Ok(_) => true,
                    // 出错时停止流，防止连接泄漏
                    Err(_) => false,
                };
                futures::future::ready(continue_stream)
            })
            .filter_map(move |res| {
                let result = match res {
                    Ok(ProxyRequest::Data(packet)) => {
                        // 只处理该流的数据包
                        if packet.stream_id == stream_id_filter {
                            if !packet.data.is_empty() {
                                Some(Ok(Bytes::from(packet.data)))
                            } else {
                                None
                            }
                        } else {
                            // 其他流的数据，跳过
                            None
                        }
                    }
                    Ok(_) => None, // 忽略非 Data 数据包
                    Err(e) => Some(Err(io::Error::other(e))),
                };

                futures::future::ready(result)
            });

        let writer = SinkWriter::new(sink);
        let reader = StreamReader::new(stream);

        // AgentIo 让 packet-based 的 agent 连接呈现为 AsyncRead/AsyncWrite。
        let mut agent_io = AgentIo { reader, writer };

        let tcp_relay_idle_timeout_secs = self.proxy_config.tcp_relay_idle_timeout_secs;
        let half_close_idle_timeout_secs = self.proxy_config.tcp_relay_half_close_idle_timeout_secs;
        let timeouts =
            TcpRelayTimeouts::new(tcp_relay_idle_timeout_secs, half_close_idle_timeout_secs);

        let (up_bytes, down_bytes) =
            relay_tcp_with_half_close(target_stream, &mut agent_io, timeouts).await?;

        debug!("中继已结束：上行 {}，下行 {}", up_bytes, down_bytes);

        Ok(())
    }
}

pub(super) async fn relay_tcp_with_half_close<T, A>(
    target_stream: &mut T,
    agent_io: &mut A,
    timeouts: TcpRelayTimeouts,
) -> io::Result<(u64, u64)>
where
    T: AsyncRead + AsyncWrite + Unpin,
    A: AsyncRead + AsyncWrite + Unpin,
{
    // TCP relay 只保留这一套实现：始终使用明确的半关闭状态机。
    // 真正的字节搬运交给 Tokio copy_bidirectional；它的半关闭和双方向
    // 并发语义比手写 select 更稳定。外层 RelayCopyIo 只负责两件事：
    // 1. 记录读写活动，让 proxy 仍能执行“空闲超时”；
    // 2. 忽略无害的 shutdown 错误，避免请求方向 BrokenPipe 取消响应方向排空。
    //
    // 参数顺序使用 agent_io -> target_stream，因此返回值天然是：
    // agent->target 上行字节、target->agent 下行字节。
    let up_total = Arc::new(AtomicU64::new(0));
    let down_total = Arc::new(AtomicU64::new(0));
    let agent_eof = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let target_eof = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (activity_tx, mut activity_rx) = watch::channel(());
    let mut agent_copy_io = RelayCopyIo::new(
        agent_io,
        "agent->target",
        activity_tx.clone(),
        up_total.clone(),
        agent_eof.clone(),
    );
    let mut target_copy_io = RelayCopyIo::new(
        target_stream,
        "target->agent",
        activity_tx,
        down_total.clone(),
        target_eof.clone(),
    );

    let relay = tokio::io::copy_bidirectional_with_sizes(
        &mut agent_copy_io,
        &mut target_copy_io,
        common::TCP_RELAY_COPY_BUFFER_SIZE,
        common::TCP_RELAY_COPY_BUFFER_SIZE,
    );
    tokio::pin!(relay);

    loop {
        let half_closed = agent_eof.load(Ordering::Acquire) || target_eof.load(Ordering::Acquire);
        if let Some(timeout) = timeouts.current(half_closed) {
            let idle = tokio::time::sleep(timeout);
            tokio::pin!(idle);
            tokio::select! {
                result = &mut relay => return result,
                _ = &mut idle => {
                    if half_closed {
                        debug!("TCP 中继半关闭后空闲超过 {} 秒，关闭连接", timeout.as_secs());
                    } else {
                        debug!("TCP 中继空闲超过 {} 秒，关闭连接", timeout.as_secs());
                    }
                    return Ok((
                        up_total.load(Ordering::Acquire),
                        down_total.load(Ordering::Acquire),
                    ));
                }
                changed = activity_rx.changed() => {
                    if changed.is_err() {
                        // 两个方向都结束时 relay_directions 会先返回；这里保守地继续轮询，
                        // 避免 watch 发送端被提前 drop 时误判为空闲。
                        continue;
                    }
                }
            }
        } else {
            tokio::select! {
                result = &mut relay => return result,
                changed = activity_rx.changed() => {
                    if changed.is_err() {
                        continue;
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct TcpRelayTimeouts {
    idle: Option<Duration>,
    half_close_idle: Option<Duration>,
}

impl TcpRelayTimeouts {
    fn new(idle_secs: u64, half_close_idle_secs: u64) -> Self {
        Self {
            idle: duration_from_secs(idle_secs),
            half_close_idle: duration_from_secs(half_close_idle_secs),
        }
    }

    #[cfg(test)]
    fn from_durations(idle: Option<Duration>, half_close_idle: Option<Duration>) -> Self {
        Self {
            idle,
            half_close_idle,
        }
    }

    fn current(self, half_closed: bool) -> Option<Duration> {
        if !half_closed {
            return self.idle;
        }

        match (self.idle, self.half_close_idle) {
            (Some(idle), Some(half_close_idle)) => Some(idle.min(half_close_idle)),
            (Some(idle), None) => Some(idle),
            (None, Some(half_close_idle)) => Some(half_close_idle),
            (None, None) => None,
        }
    }
}

fn duration_from_secs(secs: u64) -> Option<Duration> {
    if secs == 0 {
        None
    } else {
        Some(Duration::from_secs(secs))
    }
}

fn can_ignore_tcp_shutdown_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset | io::ErrorKind::NotConnected
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn relay_keeps_target_response_after_agent_half_close() {
        let (mut target_relay, mut target_peer) = tokio::io::duplex(1024);
        let (mut agent_relay, mut agent_peer) = tokio::io::duplex(1024);

        let relay = tokio::spawn(async move {
            relay_tcp_with_half_close(
                &mut target_relay,
                &mut agent_relay,
                TcpRelayTimeouts::from_durations(
                    Some(Duration::from_secs(5)),
                    Some(Duration::from_secs(5)),
                ),
            )
            .await
        });

        // 模拟 agent 请求方向先结束：这在协议层表现为空 end 包或 TCP FIN。
        // relay 不能因此立即结束，否则目标随后返回的响应体会被截断。
        agent_peer.write_all(b"GET").await.unwrap();
        agent_peer.shutdown().await.unwrap();

        let mut request = [0u8; 3];
        target_peer.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"GET");

        let mut eof_probe = [0u8; 1];
        assert_eq!(target_peer.read(&mut eof_probe).await.unwrap(), 0);

        target_peer.write_all(b"complete-body").await.unwrap();
        target_peer.shutdown().await.unwrap();

        let mut response = Vec::new();
        agent_peer.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"complete-body");

        let (up_bytes, down_bytes) = tokio::time::timeout(Duration::from_secs(5), relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(up_bytes, 3);
        assert_eq!(down_bytes, b"complete-body".len() as u64);
    }

    #[tokio::test]
    async fn relay_keeps_half_close_when_idle_timeout_disabled() {
        let (mut target_relay, mut target_peer) = tokio::io::duplex(1024);
        let (mut agent_relay, mut agent_peer) = tokio::io::duplex(1024);

        let relay = tokio::spawn(async move {
            relay_tcp_with_half_close(
                &mut target_relay,
                &mut agent_relay,
                TcpRelayTimeouts::from_durations(None, None),
            )
            .await
        });

        // timeout=0 的配置现在只表示“不启用超时”，不能再切回旧的
        // copy_bidirectional 路径；半关闭语义必须和启用超时时完全一致。
        agent_peer.write_all(b"GET").await.unwrap();
        agent_peer.shutdown().await.unwrap();

        let mut request = [0u8; 3];
        target_peer.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"GET");

        let mut eof_probe = [0u8; 1];
        assert_eq!(target_peer.read(&mut eof_probe).await.unwrap(), 0);

        target_peer.write_all(b"complete-body").await.unwrap();
        target_peer.shutdown().await.unwrap();

        let mut response = Vec::new();
        agent_peer.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"complete-body");

        let (up_bytes, down_bytes) = tokio::time::timeout(Duration::from_secs(5), relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(up_bytes, 3);
        assert_eq!(down_bytes, b"complete-body".len() as u64);
    }

    #[tokio::test]
    async fn relay_keeps_response_when_request_shutdown_errors() {
        let mut target_relay = ShutdownErrorTarget::new(b"complete-body");
        let (mut agent_relay, mut agent_peer) = tokio::io::duplex(1024);

        let relay = tokio::spawn(async move {
            relay_tcp_with_half_close(
                &mut target_relay,
                &mut agent_relay,
                TcpRelayTimeouts::from_durations(
                    Some(Duration::from_secs(5)),
                    Some(Duration::from_secs(5)),
                ),
            )
            .await
        });

        agent_peer.write_all(b"GET").await.unwrap();
        agent_peer.shutdown().await.unwrap();

        let mut response = Vec::new();
        agent_peer.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"complete-body");

        let (up_bytes, down_bytes) = tokio::time::timeout(Duration::from_secs(5), relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(up_bytes, 3);
        assert_eq!(down_bytes, b"complete-body".len() as u64);
    }

    #[tokio::test]
    async fn relay_drains_response_when_request_shutdown_stalls() {
        let mut target_relay = PendingShutdownTarget::new(b"complete-body");
        let (mut agent_relay, mut agent_peer) = tokio::io::duplex(1024);

        let relay = tokio::spawn(async move {
            relay_tcp_with_half_close(
                &mut target_relay,
                &mut agent_relay,
                TcpRelayTimeouts::from_durations(
                    Some(Duration::from_millis(100)),
                    Some(Duration::from_millis(100)),
                ),
            )
            .await
        });

        // 模拟目标写半边关闭迟迟不完成：旧的单 select relay 会卡在
        // agent->target 的 shutdown 上，导致 target->agent 已经可读的响应无法排空。
        // 新实现两个方向独立并发，所以下行响应应当先完整写回 agent；剩余挂起方向
        // 再由 idle timeout 回收。
        agent_peer.write_all(b"GET").await.unwrap();
        agent_peer.shutdown().await.unwrap();

        let mut response = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(5),
            agent_peer.read_to_end(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response, b"complete-body");

        let (up_bytes, down_bytes) = tokio::time::timeout(Duration::from_secs(5), relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(up_bytes, 3);
        assert_eq!(down_bytes, b"complete-body".len() as u64);
    }

    #[tokio::test]
    async fn relay_recycles_idle_persistent_target_after_agent_half_close() {
        let (mut target_relay, mut target_peer) = tokio::io::duplex(1024);
        let (mut agent_relay, mut agent_peer) = tokio::io::duplex(1024);

        let relay = tokio::spawn(async move {
            relay_tcp_with_half_close(
                &mut target_relay,
                &mut agent_relay,
                TcpRelayTimeouts::from_durations(
                    Some(Duration::from_secs(30)),
                    Some(Duration::from_millis(80)),
                ),
            )
            .await
        });

        agent_peer.write_all(b"GET").await.unwrap();
        agent_peer.shutdown().await.unwrap();

        let mut request = [0u8; 3];
        target_peer.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"GET");

        let mut eof_probe = [0u8; 1];
        assert_eq!(target_peer.read(&mut eof_probe).await.unwrap(), 0);

        let (up_bytes, down_bytes) = tokio::time::timeout(Duration::from_secs(2), relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(up_bytes, 3);
        assert_eq!(down_bytes, 0);

        let mut closed_probe = [0u8; 1];
        assert_eq!(target_peer.read(&mut closed_probe).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn relay_half_close_idle_keeps_active_slow_response() {
        let (mut target_relay, mut target_peer) = tokio::io::duplex(1024);
        let (mut agent_relay, mut agent_peer) = tokio::io::duplex(1024);

        let relay = tokio::spawn(async move {
            relay_tcp_with_half_close(
                &mut target_relay,
                &mut agent_relay,
                TcpRelayTimeouts::from_durations(
                    Some(Duration::from_secs(30)),
                    Some(Duration::from_millis(120)),
                ),
            )
            .await
        });

        agent_peer.write_all(b"GET").await.unwrap();
        agent_peer.shutdown().await.unwrap();

        let mut request = [0u8; 3];
        target_peer.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"GET");

        let mut eof_probe = [0u8; 1];
        assert_eq!(target_peer.read(&mut eof_probe).await.unwrap(), 0);

        target_peer.write_all(b"part-1").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        target_peer.write_all(b"part-2").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        target_peer.write_all(b"part-3").await.unwrap();
        target_peer.shutdown().await.unwrap();

        let mut response = Vec::new();
        agent_peer.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"part-1part-2part-3");

        let (up_bytes, down_bytes) = tokio::time::timeout(Duration::from_secs(2), relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(up_bytes, 3);
        assert_eq!(down_bytes, b"part-1part-2part-3".len() as u64);
    }

    #[tokio::test]
    async fn relay_does_not_apply_half_close_timeout_before_eof() {
        let (mut target_relay, mut target_peer) = tokio::io::duplex(1024);
        let (mut agent_relay, mut agent_peer) = tokio::io::duplex(1024);

        let relay = tokio::spawn(async move {
            relay_tcp_with_half_close(
                &mut target_relay,
                &mut agent_relay,
                TcpRelayTimeouts::from_durations(
                    Some(Duration::from_millis(300)),
                    Some(Duration::from_millis(50)),
                ),
            )
            .await
        });
        tokio::pin!(relay);

        agent_peer.write_all(b"PING").await.unwrap();
        let mut request = [0u8; 4];
        target_peer.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"PING");

        assert!(
            tokio::time::timeout(Duration::from_millis(120), &mut relay)
                .await
                .is_err()
        );

        drop(agent_peer);
        drop(target_peer);
        let result = tokio::time::timeout(Duration::from_secs(2), &mut relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(result.0, 4);
    }

    #[tokio::test]
    async fn relay_activity_does_not_reset_on_flush_without_bytes() {
        let (activity_tx, mut activity_rx) = tokio::sync::watch::channel(());
        activity_rx.borrow_and_update();
        let read_bytes = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut sink = tokio::io::sink();
        let mut relay_io = RelayCopyIo::new(
            &mut sink,
            "flush-only",
            activity_tx,
            read_bytes.clone(),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        );

        relay_io.flush().await.unwrap();

        assert!(!activity_rx.has_changed().unwrap());
        assert_eq!(read_bytes.load(Ordering::Acquire), 0);
    }

    struct ShutdownErrorTarget {
        state: Arc<Mutex<ShutdownErrorTargetState>>,
    }

    struct ShutdownErrorTargetState {
        body: VecDeque<u8>,
        body_released: bool,
        read_waker: Option<Waker>,
    }

    impl ShutdownErrorTarget {
        fn new(body: &[u8]) -> Self {
            Self {
                state: Arc::new(Mutex::new(ShutdownErrorTargetState {
                    body: body.iter().copied().collect(),
                    body_released: false,
                    read_waker: None,
                })),
            }
        }
    }

    impl AsyncRead for ShutdownErrorTarget {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
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

    impl AsyncWrite for ShutdownErrorTarget {
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

    struct PendingShutdownTarget {
        body: VecDeque<u8>,
    }

    impl PendingShutdownTarget {
        fn new(body: &[u8]) -> Self {
            Self {
                body: body.iter().copied().collect(),
            }
        }
    }

    impl AsyncRead for PendingShutdownTarget {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            while buf.remaining() > 0 {
                let Some(byte) = self.body.pop_front() else {
                    break;
                };
                buf.put_slice(&[byte]);
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for PendingShutdownTarget {
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
            Poll::Pending
        }
    }
}
