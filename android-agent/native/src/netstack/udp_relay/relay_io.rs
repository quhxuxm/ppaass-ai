use super::*;

pub(super) async fn connect_udp_relay_stream(
    context: &ForwardContext,
) -> Result<impl AsyncRead + AsyncWrite + Unpin + Send + 'static> {
    context
        .udp_sessions
        .connect_to_target(Address::UdpRelay, TransportProtocol::Udp)
        .await
}

pub async fn send_udp_relay_request_batch<W>(
    writer: &mut W,
    state: &mut UdpRelayState,
    first_request: UdpRelayRequest,
    rx: &mut mpsc::Receiver<UdpRelayRequest>,
    stats: &UdpRelayStats,
) -> std::result::Result<(), Box<(io::Error, UdpRelayRequest)>>
where
    W: AsyncWrite + Unpin,
{
    let mut batch = Vec::with_capacity(UDP_RELAY_REQUEST_BATCH_LIMIT);
    batch.push(first_request);
    for _ in 1..UDP_RELAY_REQUEST_BATCH_LIMIT {
        match rx.try_recv() {
            Ok(request) => batch.push(request),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
        }
    }

    // QUIC/实时 UDP 在 Android VPN 下会产生高包率。逐包 flush 会让 agent->proxy
    // 外层连接承受大量小写入和调度唤醒；这里仍保持“一个 UDP datagram 编成一个
    // UdpRelayPacket”的协议边界，只把当前队列里已经积压的一小批统一 flush。
    let mut payload_bytes = 0usize;
    for request in &batch {
        write_udp_relay_request(writer, state, request)
            .await
            .map_err(|err| (err, request.clone()))?;
        payload_bytes += request.packet.len();
    }

    writer
        .flush()
        .await
        .map_err(|err| (err, batch[0].clone()))?;
    stats.record_sent_batch(batch.len(), payload_bytes);
    if batch.len() > 1 {
        debug!(
            "Android TUN UDP relay request batch flush: batch_size={}",
            batch.len()
        );
    }
    Ok(())
}

pub(super) async fn write_udp_relay_request<W>(
    writer: &mut W,
    state: &mut UdpRelayState,
    request: &UdpRelayRequest,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    // proxy 根据 flow_id/address 建立或复用目标 UDP socket；Android 侧只负责把
    // VPN netstack 中的 datagram 封成 UdpRelayPacket 后送入共享 relay。
    let flow_id = state.flow_id(request.client, request.target);
    let packet = UdpRelayPacket::encode_parts(flow_id, &request.address, &request.packet)
        .map_err(io::Error::other)?;

    writer.write_all(&packet).await
}

pub(super) async fn handle_udp_relay_response(
    netstack_tx: &UdpWriter,
    state: &mut UdpRelayState,
    response: &[u8],
) -> io::Result<usize> {
    // proxy 回复携带 flow_id；这里还原原始 client/target 后写回 Android VPN netstack。
    let packet = UdpRelayPacket::decode(response).map_err(io::Error::other)?;
    let Some(flow) = state.flow(packet.flow_id) else {
        debug!(
            "Android TUN UDP relay response had no matching flow id={}",
            packet.flow_id
        );
        return Ok(0);
    };

    let payload_bytes = packet.data.len();
    netstack_tx
        .send((packet.data, flow.target, flow.client))
        .await?;
    Ok(payload_bytes)
}

pub(super) fn spawn_udp_relay_stats_logger(stats: Arc<UdpRelayStats>, shutdown: CancellationToken) {
    spawn_guarded("android tun udp relay stats", async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = interval.tick() => {
                    let snapshot = stats.snapshot_and_reset();
                    if snapshot.sent_packets == 0
                        && snapshot.response_packets == 0
                        && snapshot.queue_drops == 0
                    {
                        continue;
                    }

                    // Android VPN 下看不到 HTTPS/QUIC 内部 URL，这里只输出共享 UDP
                    // relay 的低频聚合指标，用来定位卡顿是否来自 agent 队列丢包、
                    // 高频 flush 压力或 proxy 响应不足。
                    info!(
                        "Android TUN UDP relay stats: sent_packets={} sent_payload_bytes={} responses={} response_payload_bytes={} batches={} batched_packets={} queue_drops={}",
                        snapshot.sent_packets,
                        snapshot.sent_payload_bytes,
                        snapshot.response_packets,
                        snapshot.response_payload_bytes,
                        snapshot.send_batches,
                        snapshot.send_batched_packets,
                        snapshot.queue_drops
                    );
                }
            }
        }
    });
}
