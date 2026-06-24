//! legacy TCP/UDP 数据中继。
//!
//! agent 与 proxy 之间传的是 `DataPacket`，目标服务器侧通常是裸 TCP/UDP。
//! 本模块的核心工作就是把 packet-based 的 agent 连接适配成 `AsyncRead/AsyncWrite`，
//! 再与目标 socket 做双向搬运。

use super::*;

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
        let username = self.user_config.as_ref().map(|c| c.username.clone());
        let monitor_stream = self.bandwidth_monitor.clone();
        let username_stream = username.clone();
        let stream_id_filter = stream_id.clone();

        // 使用自定义 Sink 将 UDP 响应数据重新封装成 proxy DataPacket。
        let sink = BytesToProxyResponseSink {
            inner: &mut self.writer,
            stream_id: stream_id.clone(),
            username: username.clone(),
            bandwidth_monitor: self.bandwidth_monitor.clone(),
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
                let user = username_stream.as_ref();
                let monitor = &monitor_stream;

                let result = match res {
                    Ok(ProxyRequest::Data(packet)) => {
                        // 只处理该流的数据包
                        trace!(
                            packet.stream_id,
                            stream_id_filter, "从 agent 收到 UDP 数据包：{packet:?}"
                        );
                        if packet.stream_id == stream_id_filter && !packet.data.is_empty() {
                            if let Some(u) = user {
                                monitor.record_received(u, packet.data.len() as u64);
                            }
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
        let mut agent_buf = [0u8; 65535];
        let mut udp_buf = [0u8; 65535];

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
        let username = self.user_config.as_ref().map(|c| c.username.clone());
        let monitor_stream = self.bandwidth_monitor.clone();
        let username_stream = username.clone();
        let stream_id_filter = stream_id.clone();

        // 使用自定义 Sink 实现，避免 SinkExt::with 与闭包引发 HRTB 问题
        let sink = BytesToProxyResponseSink {
            inner: &mut self.writer,
            stream_id: stream_id.clone(),
            username: username.clone(),
            bandwidth_monitor: self.bandwidth_monitor.clone(),
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
                let user = username_stream.as_ref();
                let monitor = &monitor_stream;

                let result = match res {
                    Ok(ProxyRequest::Data(packet)) => {
                        // 只处理该流的数据包
                        if packet.stream_id == stream_id_filter {
                            if !packet.data.is_empty() {
                                if let Some(u) = user {
                                    monitor.record_received(u, packet.data.len() as u64);
                                }
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
        let relay_buffer_size = self.proxy_config.tcp_relay_buffer_size();
        let idle_timeout = if tcp_relay_idle_timeout_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(tcp_relay_idle_timeout_secs))
        };

        let (up_bytes, down_bytes) = relay_tcp_with_half_close(
            target_stream,
            &mut agent_io,
            idle_timeout,
            relay_buffer_size,
        )
        .await?;

        debug!(
            "中继已结束：上行 {}，下行 {}，buffer={} bytes",
            up_bytes, down_bytes, relay_buffer_size
        );

        Ok(())
    }
}

pub(super) async fn relay_tcp_with_half_close<T, A>(
    target_stream: &mut T,
    agent_io: &mut A,
    idle_timeout: Option<Duration>,
    relay_buffer_size: usize,
) -> io::Result<(u64, u64)>
where
    T: AsyncRead + AsyncWrite + Unpin,
    A: AsyncRead + AsyncWrite + Unpin,
{
    // TCP relay 只保留这一套实现：始终使用明确的半关闭状态机。
    // `idle_timeout = None` 只关闭超时控制，不再回退到 copy_bidirectional，
    // 避免不同配置下出现两套 EOF/shutdown 语义。
    //
    // 单方向读/写/shutdown 出错时，只停止该方向，不立刻退出整个 relay。
    // 请求方向的 BrokenPipe 经常只是远端已经不再接收请求体，目标方向仍可能
    // 有完整响应需要写回 agent；直接 break 会导致视频分片响应被人为截断。
    let idle = tokio::time::sleep(idle_timeout.unwrap_or(Duration::from_secs(3600)));
    tokio::pin!(idle);

    let (mut target_reader, mut target_writer) = tokio::io::split(target_stream);
    let (mut agent_reader, mut agent_writer) = tokio::io::split(agent_io);
    let mut up_bytes: u64 = 0;
    let mut down_bytes: u64 = 0;
    let mut agent_buf = vec![0u8; relay_buffer_size];
    let mut target_buf = vec![0u8; relay_buffer_size];
    let mut agent_done = false;
    let mut target_done = false;

    loop {
        if agent_done && target_done {
            break;
        }

        tokio::select! {
            _ = &mut idle, if idle_timeout.is_some() => {
                let timeout = idle_timeout.expect("select guard ensures timeout exists");
                debug!("TCP 中继空闲超过 {} 秒，关闭连接", timeout.as_secs());
                break;
            }
            read = agent_reader.read(&mut agent_buf), if !agent_done => {
                match read {
                    Ok(0) => {
                        agent_done = true;
                        // agent->target 方向结束只代表请求方向 EOF。TCP 支持半关闭，
                        // 目标服务器仍可能继续返回响应体；这里仅关闭目标写半边，
                        // 继续保留 target->agent 方向，避免 HLS 分片读到一半就被截断。
                        match run_tcp_relay_io(idle_timeout, target_writer.shutdown()).await {
                            Ok(true) => {
                                if let Some(timeout) = idle_timeout {
                                    idle.as_mut().reset(tokio::time::Instant::now() + timeout);
                                }
                            }
                            Ok(false) => {
                                let timeout = idle_timeout.expect("timeout result requires timeout");
                                debug!(
                                    "TCP relay 关闭目标写半边超过 {} 秒，关闭连接",
                                    timeout.as_secs()
                                );
                                agent_done = true;
                            }
                            Err(e) => {
                                debug!("TCP relay 关闭目标写半边失败：{}", e);
                                agent_done = true;
                            }
                        }
                    }
                    Ok(n) => {
                        up_bytes += n as u64;
                        match run_tcp_relay_io(idle_timeout, async {
                            target_writer.write_all(&agent_buf[..n]).await?;
                            target_writer.flush().await
                        }).await {
                            Ok(true) => {
                                if let Some(timeout) = idle_timeout {
                                    idle.as_mut().reset(tokio::time::Instant::now() + timeout);
                                }
                            }
                            Ok(false) => {
                                let timeout = idle_timeout.expect("timeout result requires timeout");
                                debug!("TCP relay 写入目标超过 {} 秒，关闭连接", timeout.as_secs());
                                agent_done = true;
                            }
                            Err(e) => {
                                debug!("TCP relay 写入目标失败：{}", e);
                                agent_done = true;
                            }
                        }
                    }
                    Err(e) => {
                        debug!("TCP relay 读取 agent 数据失败：{}", e);
                        agent_done = true;
                    }
                }
            }
            read = target_reader.read(&mut target_buf), if !target_done => {
                match read {
                    Ok(0) => {
                        target_done = true;
                        // target->agent 方向结束时也只关闭写回 agent 的半边，并发送
                        // DataPacket end 标记。agent 仍可在另一方向完成剩余写入或 EOF
                        // 传播，保持和 copy_bidirectional 一致的半关闭语义。
                        match run_tcp_relay_io(idle_timeout, agent_writer.shutdown()).await {
                            Ok(true) => {
                                if let Some(timeout) = idle_timeout {
                                    idle.as_mut().reset(tokio::time::Instant::now() + timeout);
                                }
                            }
                            Ok(false) => {
                                let timeout = idle_timeout.expect("timeout result requires timeout");
                                debug!(
                                    "TCP relay 关闭 agent 写半边超过 {} 秒，关闭连接",
                                    timeout.as_secs()
                                );
                                target_done = true;
                            }
                            Err(e) => {
                                debug!("TCP relay 关闭 agent 写半边失败：{}", e);
                                target_done = true;
                            }
                        }
                    }
                    Ok(n) => {
                        down_bytes += n as u64;
                        match run_tcp_relay_io(idle_timeout, async {
                            agent_writer.write_all(&target_buf[..n]).await?;
                            agent_writer.flush().await
                        }).await {
                            Ok(true) => {
                                if let Some(timeout) = idle_timeout {
                                    idle.as_mut().reset(tokio::time::Instant::now() + timeout);
                                }
                            }
                            Ok(false) => {
                                let timeout = idle_timeout.expect("timeout result requires timeout");
                                debug!("TCP relay 写回 agent 超过 {} 秒，关闭连接", timeout.as_secs());
                                target_done = true;
                            }
                            Err(e) => {
                                debug!("TCP relay 写回 agent 失败：{}", e);
                                target_done = true;
                            }
                        }
                    }
                    Err(e) => {
                        debug!("TCP relay 读取目标数据失败：{}", e);
                        target_done = true;
                    }
                }
            }
        }
    }

    Ok((up_bytes, down_bytes))
}

async fn run_tcp_relay_io<F>(idle_timeout: Option<Duration>, operation: F) -> io::Result<bool>
where
    F: std::future::Future<Output = io::Result<()>>,
{
    // 返回值含义：true 表示操作完成，false 表示命中超时。
    // 这样 timeout=0/None 时仍复用同一套 relay 状态机，只是不包 timeout。
    if let Some(timeout) = idle_timeout {
        match tokio::time::timeout(timeout, operation).await {
            Ok(result) => result.map(|_| true),
            Err(_) => Ok(false),
        }
    } else {
        operation.await.map(|_| true)
    }
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
                Some(Duration::from_secs(5)),
                64,
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
            relay_tcp_with_half_close(&mut target_relay, &mut agent_relay, None, 64).await
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
                Some(Duration::from_secs(5)),
                64,
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
}
