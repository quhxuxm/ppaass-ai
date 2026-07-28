//! 共享 UDP relay。
//!
//! 与 legacy `relay_udp` 的“一条连接只对应一个 UDP 目标”不同，这里一条
//! agent->proxy 连接可以承载多个 UDP 目标。agent 把每个 UDP 包包成
//! `UdpRelayPacket { flow_id, address, data }`，proxy 按 flow_id 维护独立 UDP socket。

use super::udp_relay_flow::{
    QueuedUdpRelayResponse, UDP_RELAY_RESPONSE_BATCH_LIMIT, UdpRelayFlowChannels, UdpRelayFlowSet,
    udp_relay_channel_size,
};
use super::*;
use crate::config::PERMISSION_PROXY_CONNECT_UDP;
use tokio::time::Instant;

impl ServerConnection {
    pub(super) async fn handle_udp_relay_connect(
        &mut self,
        connect_request: ConnectRequest,
    ) -> Result<()> {
        debug!("正在建立 UDP 共享中继");
        // CONNECT 分流前已经检查过一次；发送成功响应前再查一次，覆盖两次操作
        // 之间发生的撤权/换钥。之后同一个独立 guard 按绝对 expiry 和周期重验关闭 relay。
        let authorization = self.authorization_context()?;
        authorization.validate(PERMISSION_PROXY_CONNECT_UDP).await?;
        let relay_authorization = authorization.clone();
        let authorization_guard = relay_authorization.enforce(
            PERMISSION_PROXY_CONNECT_UDP,
            self.authorization_recheck_secs(),
        );
        tokio::pin!(authorization_guard);
        let connect_success =
            self.send_connect_success(connect_request.request_id.clone(), "UDP relay connected");
        tokio::select! {
            biased;
            authorization_result = &mut authorization_guard => return authorization_result,
            result = connect_success => result?,
        }

        let channel_size = udp_relay_channel_size(&self.proxy_config);
        // response_tx：各个 flow 任务把目标响应送回主 relay 循环。
        // flow_done_tx：flow 空闲/失败退出后通知主循环清理 flows 表。
        let (response_tx, mut response_rx) =
            tokio::sync::mpsc::channel::<QueuedUdpRelayResponse>(channel_size);
        let (flow_done_tx, mut flow_done_rx) = tokio::sync::mpsc::channel::<u64>(channel_size);
        // legacy UDP relay 的外层是 `ProxyRequest/ProxyResponse::Data`。flow 的创建、
        // 上下行队列、buffer permit 和 socket 生命周期都交给 `UdpRelayFlowSet`；
        // 本函数只负责：
        // 1. 从 agent 的 DataPacket 里解析 UdpRelayPacket；
        // 2. 把目标响应重新包回当前 request_id 对应的 DataPacket；
        // 3. 管理这条共享 relay 连接自身的 idle 生命周期。
        let mut flow_set = UdpRelayFlowSet::new(
            self.proxy_config.as_ref(),
            self.egress_state.clone(),
            self.access_recorder.clone(),
            self.user_config
                .as_ref()
                .map(|user| user.username.clone())
                .unwrap_or_default(),
            UdpRelayFlowChannels {
                response_tx: response_tx.clone(),
                flow_done_tx: flow_done_tx.clone(),
            },
            "UDP relay",
            "proxy udp relay flow",
        )
        .with_authorization(authorization);
        // 发送 ConnectSuccess 前刚完成的查询也可作为新 flow 的授权依据；一秒
        // 合并窗口只减少突发查询，不延长外层五秒周期的撤权窗口。
        flow_set.record_authorization_success(Instant::now());
        let stream_id = connect_request.request_id;
        let relay_idle_timeout = flow_set.idle_timeout();
        let relay_idle = tokio::time::sleep(relay_idle_timeout);
        tokio::pin!(relay_idle);

        loop {
            tokio::select! {
                biased;
                authorization_result = &mut authorization_guard => {
                    warn!("UDP 共享中继授权已失效，主动关闭：{:?}", authorization_result.as_ref().err());
                    return authorization_result;
                }
                _ = &mut relay_idle => {
                    debug!(
                        "UDP 共享中继空闲超过 {} 秒，关闭该连接",
                        relay_idle_timeout.as_secs()
                    );
                    break;
                }
                request = self.reader.next() => {
                    let request = match request {
                        Some(Ok(request)) => request,
                        Some(Err(e)) => return Err(ProxyError::Protocol(protocol::ProtocolError::Io(e))),
                        None => break,
                    };

                    let ProxyRequest::Data(packet) = request else {
                        continue;
                    };
                    if packet.stream_id != stream_id {
                        continue;
                    }
                    if packet.is_end && packet.data.is_empty() {
                        break;
                    }
                    if packet.data.is_empty() {
                        continue;
                    }

                    // 任何有效上行包都表示共享 relay 仍在使用中，重置连接级 idle。
                    // flow 自己还有 per-flow idle；连接级 idle 只用于整条共享通道无流量时退出。
                    relay_idle.as_mut().reset(tokio::time::Instant::now() + relay_idle_timeout);

                    // agent 的 DataPacket payload 内部还包了一层 UdpRelayPacket，
                    // 这层携带 flow_id 和真正的 UDP 目标地址。
                    let relay_packet = match UdpRelayPacket::decode(&packet.data) {
                        Ok(packet) => packet,
                        Err(e) => {
                            debug!("UDP relay 数据包解析失败：{e}");
                            continue;
                        }
                    };

                    let dispatch = flow_set.dispatch(relay_packet);
                    tokio::select! {
                        biased;
                        authorization_result = &mut authorization_guard => {
                            warn!("UDP 共享中继授权已失效，主动关闭：{:?}", authorization_result.as_ref().err());
                            return authorization_result;
                        }
                        dispatch_result = dispatch => dispatch_result?,
                    }
                }
                response = response_rx.recv() => {
                    let Some(response) = response else { break };
                    // 下行响应可能在同一 tick 内已经积压多个。这里一次取出一小批一起 feed，
                    // 最后统一 flush，减少高包率场景下 `send().await`/flush 对 relay 主循环
                    // 的唤醒压力。批量大小由公共常量控制，避免 drain 过多导致上行读取延迟。
                    let send_responses = send_udp_relay_response_batch_with_timeout(
                        &mut self.writer,
                        &mut response_rx,
                        response,
                        &stream_id,
                        relay_idle_timeout,
                    );
                    let send_result = tokio::select! {
                        biased;
                        authorization_result = &mut authorization_guard => {
                            warn!("UDP 共享中继授权已失效，主动关闭：{:?}", authorization_result.as_ref().err());
                            return authorization_result;
                        }
                        send_result = send_responses => send_result,
                    };
                    if let Err(err) = send_result {
                        warn!("UDP 共享中继写回 agent 失败，关闭该连接：{err}");
                        return Err(err);
                    }
                    relay_idle.as_mut().reset(tokio::time::Instant::now() + relay_idle_timeout);
                }
                done = flow_done_rx.recv() => {
                    let Some(flow_id) = done else { break };
                    flow_set.remove(flow_id);
                }
            }
        }

        debug!("UDP 共享中继已结束");
        Ok(())
    }
}

async fn send_udp_relay_response_batch_with_timeout(
    writer: &mut FramedWriter,
    response_rx: &mut tokio::sync::mpsc::Receiver<QueuedUdpRelayResponse>,
    first_response: QueuedUdpRelayResponse,
    stream_id: &str,
    write_timeout: Duration,
) -> Result<()> {
    match tokio::time::timeout(
        write_timeout,
        send_udp_relay_response_batch(writer, response_rx, first_response, stream_id),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(ProxyError::Connection(format!(
            "Timed out writing UDP relay responses after {} seconds",
            write_timeout.as_secs()
        ))),
    }
}

async fn send_udp_relay_response_batch(
    writer: &mut FramedWriter,
    response_rx: &mut tokio::sync::mpsc::Receiver<QueuedUdpRelayResponse>,
    first_response: QueuedUdpRelayResponse,
    stream_id: &str,
) -> Result<()> {
    // 首个响应来自 `recv().await`，一定存在；额外响应用 `try_recv` 非阻塞 drain。
    feed_udp_relay_response(writer, first_response, stream_id).await?;
    let mut batch_size = 1usize;

    for _ in 1..UDP_RELAY_RESPONSE_BATCH_LIMIT {
        match response_rx.try_recv() {
            Ok(response) => {
                batch_size += 1;
                feed_udp_relay_response(writer, response, stream_id).await?;
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
        }
    }

    writer
        .flush()
        .await
        .map_err(|e| ProxyError::Connection(format!("Failed to flush UDP relay responses: {e}")))?;
    if batch_size > 1 {
        debug!("UDP relay response 批量 flush：batch_size={batch_size}");
    }
    Ok(())
}

async fn feed_udp_relay_response(
    writer: &mut FramedWriter,
    response: QueuedUdpRelayResponse,
    stream_id: &str,
) -> Result<()> {
    let QueuedUdpRelayResponse { packet } = response;
    // 目标响应重新编码成 UdpRelayPacket，再包回当前 stream_id 的 DataPacket。
    // 使用 `feed` 而不是 `send`，让调用方可以批量排队后统一 flush。
    let encoded = packet.encode().map_err(ProxyError::Protocol)?;
    let packet = protocol::DataPacket {
        stream_id: stream_id.to_owned(),
        data: encoded,
        is_end: false,
    };
    writer
        .feed(ProxyResponse::Data(packet))
        .await
        .map_err(|e| ProxyError::Connection(format!("Failed to queue UDP relay response: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    struct PendingAgentStream;

    impl AsyncRead for PendingAgentStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for PendingAgentStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn udp_relay_response_write_times_out_when_agent_stalls() {
        let cipher_state = Arc::new(CipherState::new());
        cipher_state
            .set_session_cipher(Arc::new(
                protocol::tcp_transport::TcpSessionCipher::new(
                    protocol::tcp_transport::TcpSessionRole::Proxy,
                    [1; 32],
                    [2; 32],
                    [3; 32],
                    [4; 32],
                    [5; 16],
                )
                .unwrap(),
            ))
            .unwrap();
        let framed = proxy_framed_stream(PendingAgentStream, ProxyCodec::new(cipher_state));
        let (mut writer, _reader) = framed.split();
        let (_response_tx, mut response_rx) = tokio::sync::mpsc::channel(1);
        let response = QueuedUdpRelayResponse {
            packet: UdpRelayPacket {
                flow_id: 7,
                address: Address::Ipv4 {
                    addr: [127, 0, 0, 1],
                    port: 443,
                },
                data: b"pong".to_vec(),
            },
        };

        let err = send_udp_relay_response_batch_with_timeout(
            &mut writer,
            &mut response_rx,
            response,
            "udp-relay-test",
            Duration::from_millis(20),
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("Timed out writing UDP relay responses")
        );
    }
}
