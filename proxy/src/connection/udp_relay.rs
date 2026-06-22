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

impl ServerConnection {
    pub(super) async fn handle_udp_relay_connect(
        &mut self,
        connect_request: ConnectRequest,
    ) -> Result<()> {
        debug!("正在建立 UDP 共享中继");
        // 先告诉 agent 共享中继已经建立；后续所有 UDP 数据都走同一个 request_id。
        self.send_connect_success(connect_request.request_id.clone(), "UDP relay connected")
            .await?;

        let username = self.user_config.as_ref().map(|c| c.username.clone());
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
            self.connection_limiter.clone(),
            UdpRelayFlowChannels {
                response_tx: response_tx.clone(),
                flow_done_tx: flow_done_tx.clone(),
            },
            "UDP relay",
            "proxy udp relay flow",
        );
        let stream_id = connect_request.request_id;
        let relay_idle_timeout = flow_set.idle_timeout();
        let relay_idle = tokio::time::sleep(relay_idle_timeout);
        tokio::pin!(relay_idle);

        loop {
            tokio::select! {
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

                    if let Some(user) = &username {
                        self.bandwidth_monitor.record_received(user, packet.data.len() as u64);
                    }

                    // agent 的 DataPacket payload 内部还包了一层 UdpRelayPacket，
                    // 这层携带 flow_id 和真正的 UDP 目标地址。
                    let relay_packet = match UdpRelayPacket::decode(&packet.data) {
                        Ok(packet) => packet,
                        Err(e) => {
                            debug!("UDP relay 数据包解析失败：{e}");
                            continue;
                        }
                    };

                    flow_set.dispatch(relay_packet).await;
                }
                response = response_rx.recv() => {
                    let Some(response) = response else { break };
                    // 下行响应可能在同一 tick 内已经积压多个。这里一次取出一小批一起 feed，
                    // 最后统一 flush，减少高包率场景下 `send().await`/flush 对 relay 主循环
                    // 的唤醒压力。批量大小由公共常量控制，避免 drain 过多导致上行读取延迟。
                    send_udp_relay_response_batch(
                        &mut self.writer,
                        &mut response_rx,
                        response,
                        &stream_id,
                        username.as_deref(),
                        self.bandwidth_monitor.as_ref(),
                    ).await?;
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

async fn send_udp_relay_response_batch(
    writer: &mut FramedWriter,
    response_rx: &mut tokio::sync::mpsc::Receiver<QueuedUdpRelayResponse>,
    first_response: QueuedUdpRelayResponse,
    stream_id: &str,
    username: Option<&str>,
    bandwidth_monitor: &BandwidthMonitor,
) -> Result<()> {
    // 首个响应来自 `recv().await`，一定存在；额外响应用 `try_recv` 非阻塞 drain。
    // 常见低流量场景不会分配 extra_buffer_permits，只有实际 drain 到更多响应才扩容。
    let first_buffer_permit = feed_udp_relay_response(
        writer,
        first_response,
        stream_id,
        username,
        bandwidth_monitor,
    )
    .await?;
    let mut extra_buffer_permits = Vec::new();

    for _ in 1..UDP_RELAY_RESPONSE_BATCH_LIMIT {
        match response_rx.try_recv() {
            Ok(response) => {
                // `feed_udp_relay_response` 会把响应排入 Framed sink，但数据可能还在
                // sink/codec/socket 的内部缓冲里。因此这里收集 permit，等本批 flush
                // 成功后再释放，保证 buffered bytes 统计覆盖真实写出前的积压。
                extra_buffer_permits.push(
                    feed_udp_relay_response(
                        writer,
                        response,
                        stream_id,
                        username,
                        bandwidth_monitor,
                    )
                    .await?,
                );
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
        }
    }

    writer
        .flush()
        .await
        .map_err(|e| ProxyError::Connection(format!("Failed to flush UDP relay responses: {e}")))?;
    // 明确 drop 是为了强调 permit 的释放点：只有这一批数据完成 flush 后，才把下行
    // buffered bytes 从全局预算中扣回去。
    drop(first_buffer_permit);
    drop(extra_buffer_permits);
    Ok(())
}

async fn feed_udp_relay_response(
    writer: &mut FramedWriter,
    response: QueuedUdpRelayResponse,
    stream_id: &str,
    username: Option<&str>,
    bandwidth_monitor: &BandwidthMonitor,
) -> Result<UdpRelayBufferedBytesPermit> {
    let QueuedUdpRelayResponse {
        packet,
        _buffer_permit: buffer_permit,
    } = response;
    // 目标响应重新编码成 UdpRelayPacket，再包回当前 stream_id 的 DataPacket。
    // 使用 `feed` 而不是 `send`，让调用方可以批量排队后统一 flush。
    let encoded = packet.encode().map_err(ProxyError::Protocol)?;
    if let Some(user) = username {
        bandwidth_monitor.record_sent(user, encoded.len() as u64);
    }
    let packet = protocol::DataPacket {
        stream_id: stream_id.to_owned(),
        data: encoded,
        is_end: false,
    };
    writer
        .feed(ProxyResponse::Data(packet))
        .await
        .map_err(|e| ProxyError::Connection(format!("Failed to queue UDP relay response: {e}")))?;
    Ok(buffer_permit)
}
