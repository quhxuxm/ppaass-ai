//! TUN 普通 UDP 的共享 proxy relay。
//!
//! 与 `handle_tun_udp` 的单会话 proxy stream 不同，这里把多个 UDP source/target flow
//! 按稳定哈希分片到多条 `Address::UdpRelay` 连接上。适合 QUIC 等高并发 UDP，
//! 能减少频繁建连，同时避免所有 flow 都挤在单条 relay stream 上。

use super::udp::UdpWriter;

mod state;

use crate::telemetry;
use crate::yamux_session::YamuxSessionManager;
use common::spawn_guarded;
use futures::SinkExt;
use protocol::{Address, TransportProtocol, UdpRelayPacket, udp_transport::UDP_MAX_MESSAGE_SIZE};
pub(super) use state::UdpRelay;
pub use state::{UdpFlowKey, UdpRelayRequest, UdpRelayState, UdpRelayStats};
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

const UDP_RELAY_CHANNEL_SIZE: usize = 4096;
const UDP_RELAY_SHARD_COUNT: usize = 4;
const UDP_RELAY_REQUEST_BATCH_LIMIT: usize = 32;
const UDP_FLOW_TTL: Duration = Duration::from_secs(300);
const UDP_RELAY_CONNECTION_IDLE: Duration = Duration::from_secs(30);

async fn run_udp_relay(
    sessions: Arc<YamuxSessionManager>,
    netstack_tx: UdpWriter,
    mut rx: mpsc::Receiver<UdpRelayRequest>,
    shutdown: CancellationToken,
    stats: Arc<UdpRelayStats>,
) {
    let mut state = UdpRelayState::new();
    // 写入失败时保留当前请求，重建共享连接后优先重发，避免首包直接丢失。
    let mut retry_request = None;
    let mut reconnect_delay = Duration::from_millis(200);

    loop {
        let first_request = match retry_request.take() {
            Some(request) => request,
            None => {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    maybe_request = rx.recv() => {
                        let Some(request) = maybe_request else { break };
                        request
                    }
                }
            }
        };

        let connected = connect_udp_relay_stream(&sessions).await;
        let proxy_io = match connected {
            Ok(proxy_io) => {
                reconnect_delay = Duration::from_millis(200);
                proxy_io
            }
            Err(e) => {
                warn!("TUN UDP 共享连接创建失败：{e}");
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(reconnect_delay) => {}
                }
                reconnect_delay = (reconnect_delay * 2).min(Duration::from_secs(5));
                retry_request = Some(first_request);
                continue;
            }
        };
        debug!("TUN UDP 已建立共享 proxy 连接");
        let (mut reader, mut writer) = tokio::io::split(proxy_io);
        let mut cleanup = tokio::time::interval(Duration::from_secs(60));
        cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let idle = tokio::time::sleep(UDP_RELAY_CONNECTION_IDLE);
        tokio::pin!(idle);
        retry_request = Some(first_request);
        // UdpRelayPacket adds flow/address metadata to the original UDP payload.
        // Keep one complete native-UDP message in a single AsyncRead call.
        let mut response_buf = vec![0u8; UDP_MAX_MESSAGE_SIZE];

        loop {
            if let Some(request) = retry_request.take() {
                if let Err((e, request)) =
                    send_udp_request_batch(&mut writer, &mut state, request, &mut rx, &stats).await
                {
                    debug!("TUN UDP 共享连接写入失败：{e}");
                    retry_request = Some(request);
                    break;
                }
                idle.as_mut()
                    .reset(tokio::time::Instant::now() + UDP_RELAY_CONNECTION_IDLE);
                continue;
            }

            tokio::select! {
                _ = shutdown.cancelled() => {
                    let _ = writer.shutdown().await;
                    return;
                }
                _ = &mut idle => {
                    debug!(
                        "TUN UDP 共享连接空闲超过 {} 秒，主动关闭 proxy 连接",
                        UDP_RELAY_CONNECTION_IDLE.as_secs()
                    );
                    let _ = writer.shutdown().await;
                    break;
                }
                _ = cleanup.tick() => {
                    state.cleanup_expired();
                    debug!(
                        "TUN UDP relay shard 观测：active_flows={} tracked_flow_keys={}",
                        state.active_flows(),
                        state.tracked_flow_keys()
                    );
                },
                maybe_request = rx.recv() => {
                    let Some(request) = maybe_request else {
                        let _ = writer.shutdown().await;
                        return;
                    };
                    if let Err((e, request)) =
                        send_udp_request_batch(&mut writer, &mut state, request, &mut rx, &stats).await
                    {
                        debug!("TUN UDP 共享连接写入失败：{e}");
                        retry_request = Some(request);
                        break;
                    }
                    idle.as_mut().reset(tokio::time::Instant::now() + UDP_RELAY_CONNECTION_IDLE);
                }
                read = reader.read(&mut response_buf) => {
                    match read {
                        Ok(0) => {
                            debug!("TUN UDP 共享连接已关闭");
                            break;
                        }
                        Ok(n) => {
                            match handle_udp_response(
                                &netstack_tx,
                                &state,
                                &response_buf[..n],
                            ).await {
                                Ok(payload_bytes) => {
                                    stats.record_response(payload_bytes);
                                    telemetry::record_traffic(0, payload_bytes as u64);
                                }
                                Err(e) => debug!("TUN UDP 回复写回失败：{e}"),
                            }
                            idle.as_mut().reset(tokio::time::Instant::now() + UDP_RELAY_CONNECTION_IDLE);
                        }
                        Err(e) => {
                            debug!("TUN UDP 共享连接读取失败：{e}");
                            break;
                        }
                    }
                }
            }
        }
    }

    debug!("TUN UDP 共享转发器退出");
}

async fn connect_udp_relay_stream(
    sessions: &YamuxSessionManager,
) -> crate::error::Result<impl AsyncRead + AsyncWrite + Unpin + Send + 'static> {
    let connected = sessions
        .connect_to_target(Address::UdpRelay, TransportProtocol::Udp)
        .await?;
    Ok(connected.into_async_io())
}

pub async fn send_udp_request_batch<W>(
    writer: &mut W,
    state: &mut UdpRelayState,
    first_request: UdpRelayRequest,
    rx: &mut mpsc::Receiver<UdpRelayRequest>,
    stats: &UdpRelayStats,
) -> Result<(), (io::Error, UdpRelayRequest)>
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

    // QUIC/实时 UDP 在 TUN 下会产生高包率。逐包 flush 会让 agent->proxy 外层
    // 连接承担大量唤醒和小写入开销；这里保留“一个 UDP datagram 编成一个
    // UdpRelayPacket”的边界，只把已经排队的一小批包统一 flush。
    let mut payload_bytes = 0usize;
    for request in &batch {
        write_udp_request(writer, state, request)
            .await
            .map_err(|err| (err, request.clone()))?;
        payload_bytes += request.packet.len();
    }

    writer
        .flush()
        .await
        .map_err(|err| (err, batch[0].clone()))?;
    stats.record_sent_batch(batch.len(), payload_bytes);
    telemetry::record_traffic(payload_bytes as u64, 0);
    if batch.len() > 1 {
        debug!(
            "TUN UDP relay request 批量 flush：batch_size={}",
            batch.len()
        );
    }
    Ok(())
}

async fn write_udp_request<W>(
    writer: &mut W,
    state: &mut UdpRelayState,
    request: &UdpRelayRequest,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    // 每个 TUN UDP datagram 被编码成 UdpRelayPacket，proxy 根据 flow_id/address 发往目标。
    let flow_id = state.flow_id(request.client, request.target);
    let packet = UdpRelayPacket {
        flow_id,
        address: request.address.clone(),
        data: request.packet.clone(),
    }
    .encode()
    .map_err(io::Error::other)?;

    writer.write_all(&packet).await
}

async fn handle_udp_response(
    netstack_tx: &UdpWriter,
    state: &UdpRelayState,
    response: &[u8],
) -> io::Result<usize> {
    // proxy 回复带 flow_id；agent 还原原始 client/target 后写回 netstack。
    let packet = UdpRelayPacket::decode(response).map_err(io::Error::other)?;
    let Some(flow) = state.flow(packet.flow_id) else {
        debug!("TUN UDP 收到无匹配 flow 的回复 id={}", packet.flow_id);
        return Ok(0);
    };

    let payload_bytes = packet.data.len();
    let mut s = netstack_tx.lock().await;
    s.send((packet.data, flow.target, flow.client)).await?;
    Ok(payload_bytes)
}

fn spawn_udp_relay_stats_logger(stats: Arc<UdpRelayStats>, shutdown: CancellationToken) {
    spawn_guarded("desktop tun udp relay stats", async move {
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

                    // TUN 下无法看到 HTTPS/QUIC 内部 URL，这里按共享 UDP relay 维度输出
                    // 低频聚合指标，用于判断卡顿是否来自 agent 侧队列丢包或高包率 flush 压力。
                    info!(
                        "TUN UDP relay 观测：sent_packets={} sent_payload_bytes={} responses={} response_payload_bytes={} batches={} batched_packets={} queue_drops={}",
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
