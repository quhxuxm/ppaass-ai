//! TUN 普通 UDP 的共享 proxy relay。
//!
//! 与 `handle_tun_udp` 的单会话 proxy stream 不同，这里把多个 UDP source/target flow
//! 按稳定哈希分片到多条 `Address::UdpRelay` 连接上。适合 QUIC 等高并发 UDP，
//! 能减少频繁建连，同时避免所有 flow 都挤在单条 relay stream 上。

use super::udp::UdpWriter;
use crate::telemetry;
use crate::yamux_session::YamuxSessionManager;
use common::spawn_guarded;
use futures::SinkExt;
use protocol::{Address, TransportProtocol, UdpRelayPacket, udp_transport::UDP_MAX_MESSAGE_SIZE};
use std::collections::{HashMap, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

const UDP_RELAY_CHANNEL_SIZE: usize = 4096;
const UDP_RELAY_SHARD_COUNT: usize = 4;
const UDP_RELAY_REQUEST_BATCH_LIMIT: usize = 32;
const UDP_FLOW_TTL: Duration = Duration::from_secs(300);
const UDP_RELAY_CONNECTION_IDLE: Duration = Duration::from_secs(30);

pub(super) struct UdpRelay {
    shards: Vec<mpsc::Sender<UdpRelayRequest>>,
    stats: Arc<UdpRelayStats>,
}

#[derive(Clone, Debug)]
struct UdpRelayRequest {
    client: SocketAddr,
    target: SocketAddr,
    address: Address,
    packet: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq)]
struct UdpFlowKey {
    client: SocketAddr,
    target: SocketAddr,
}

impl PartialEq for UdpFlowKey {
    fn eq(&self, other: &Self) -> bool {
        self.client == other.client && self.target == other.target
    }
}

impl Hash for UdpFlowKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.client.hash(state);
        self.target.hash(state);
    }
}

struct UdpRelayState {
    // (client,target) -> flow_id，保证同一 UDP flow 在 proxy 端对应同一个 UDP socket。
    flow_ids: HashMap<UdpFlowKey, u64>,
    // flow_id -> (client,target)，用于把 proxy 响应写回正确的 netstack 方向。
    flows: HashMap<u64, UdpFlowKey>,
    last_seen: HashMap<u64, Instant>,
    next_flow_id: u64,
}

#[derive(Debug, Default)]
struct UdpRelayStats {
    sent_packets: AtomicU64,
    sent_payload_bytes: AtomicU64,
    send_batches: AtomicU64,
    send_batched_packets: AtomicU64,
    response_packets: AtomicU64,
    response_payload_bytes: AtomicU64,
    queue_drops: AtomicU64,
}

#[derive(Debug, Default)]
struct UdpRelayStatsSnapshot {
    sent_packets: u64,
    sent_payload_bytes: u64,
    send_batches: u64,
    send_batched_packets: u64,
    response_packets: u64,
    response_payload_bytes: u64,
    queue_drops: u64,
}

impl UdpRelayStats {
    fn record_sent_batch(&self, packets: usize, payload_bytes: usize) {
        self.sent_packets
            .fetch_add(packets as u64, Ordering::Relaxed);
        self.sent_payload_bytes
            .fetch_add(payload_bytes as u64, Ordering::Relaxed);
        self.send_batches.fetch_add(1, Ordering::Relaxed);
        if packets > 1 {
            self.send_batched_packets
                .fetch_add(packets as u64, Ordering::Relaxed);
        }
    }

    fn record_response(&self, payload_bytes: usize) {
        self.response_packets.fetch_add(1, Ordering::Relaxed);
        self.response_payload_bytes
            .fetch_add(payload_bytes as u64, Ordering::Relaxed);
    }

    fn record_queue_drop(&self) {
        self.queue_drops.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot_and_reset(&self) -> UdpRelayStatsSnapshot {
        UdpRelayStatsSnapshot {
            sent_packets: self.sent_packets.swap(0, Ordering::Relaxed),
            sent_payload_bytes: self.sent_payload_bytes.swap(0, Ordering::Relaxed),
            send_batches: self.send_batches.swap(0, Ordering::Relaxed),
            send_batched_packets: self.send_batched_packets.swap(0, Ordering::Relaxed),
            response_packets: self.response_packets.swap(0, Ordering::Relaxed),
            response_payload_bytes: self.response_payload_bytes.swap(0, Ordering::Relaxed),
            queue_drops: self.queue_drops.swap(0, Ordering::Relaxed),
        }
    }
}

impl UdpRelayState {
    fn new() -> Self {
        Self {
            flow_ids: HashMap::new(),
            flows: HashMap::new(),
            last_seen: HashMap::new(),
            next_flow_id: 1,
        }
    }

    fn flow_id(&mut self, client: SocketAddr, target: SocketAddr) -> u64 {
        let key = UdpFlowKey { client, target };
        if let Some(id) = self.flow_ids.get(&key) {
            self.last_seen.insert(*id, Instant::now());
            return *id;
        }

        let id = self.next_available_flow_id();
        self.flow_ids.insert(key, id);
        self.flows.insert(id, key);
        self.last_seen.insert(id, Instant::now());
        id
    }

    fn flow(&self, flow_id: u64) -> Option<UdpFlowKey> {
        self.flows.get(&flow_id).copied()
    }

    fn active_flows(&self) -> usize {
        self.flows.len()
    }

    fn tracked_flow_keys(&self) -> usize {
        self.flow_ids.len()
    }

    fn next_available_flow_id(&mut self) -> u64 {
        loop {
            let id = self.next_flow_id;
            self.next_flow_id = self.next_flow_id.wrapping_add(1).max(1);
            if !self.flows.contains_key(&id) {
                return id;
            }
        }
    }

    fn cleanup_expired(&mut self) {
        let now = Instant::now();
        let expired: Vec<u64> = self
            .last_seen
            .iter()
            .filter_map(|(id, last_seen)| ((*last_seen + UDP_FLOW_TTL) <= now).then_some(*id))
            .collect();

        for id in expired {
            self.last_seen.remove(&id);
            if let Some(key) = self.flows.remove(&id) {
                self.flow_ids.remove(&key);
            }
        }
    }
}

impl UdpRelay {
    pub(super) fn spawn(
        sessions: Arc<YamuxSessionManager>,
        netstack_tx: UdpWriter,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        let mut shards = Vec::with_capacity(UDP_RELAY_SHARD_COUNT);
        let stats = Arc::new(UdpRelayStats::default());
        for shard_index in 0..UDP_RELAY_SHARD_COUNT {
            let (tx, rx) = mpsc::channel(UDP_RELAY_CHANNEL_SIZE);
            shards.push(tx);
            debug!("启动 TUN UDP 共享 relay shard {shard_index}");
            spawn_guarded(
                "desktop tun udp relay",
                run_udp_relay(
                    sessions.clone(),
                    netstack_tx.clone(),
                    rx,
                    shutdown.clone(),
                    stats.clone(),
                ),
            );
        }
        spawn_udp_relay_stats_logger(stats.clone(), shutdown);
        Arc::new(Self { shards, stats })
    }

    pub(super) fn send(
        &self,
        client: SocketAddr,
        target: SocketAddr,
        address: Address,
        packet: Vec<u8>,
    ) {
        let shard_index = udp_relay_shard_index(client, target, self.shards.len());
        match self.shards[shard_index].try_send(UdpRelayRequest {
            client,
            target,
            address,
            packet,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.stats.record_queue_drop();
                debug!("TUN UDP 共享转发队列已满，丢弃一个 UDP 包");
            }
            Err(TrySendError::Closed(_)) => debug!("TUN UDP 共享转发器已关闭，丢弃请求"),
        }
    }
}

fn udp_relay_shard_index(client: SocketAddr, target: SocketAddr, shard_count: usize) -> usize {
    debug_assert!(shard_count > 0);
    let key = UdpFlowKey { client, target };
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    (hasher.finish() % shard_count as u64) as usize
}

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

async fn send_udp_request_batch<W>(
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[test]
    fn assigns_stable_flow_ids() {
        let mut state = UdpRelayState::new();
        let client: SocketAddr = "10.10.10.2:10000".parse().unwrap();
        let target: SocketAddr = "8.8.8.8:443".parse().unwrap();

        let first = state.flow_id(client, target);
        let second = state.flow_id(client, target);

        assert_eq!(first, second);
        assert_eq!(state.flow(first).unwrap().client, client);
        assert_eq!(state.flow(first).unwrap().target, target);
    }

    #[tokio::test]
    async fn encodes_quic_target_for_udp_relay() {
        let mut state = UdpRelayState::new();
        let client: SocketAddr = "10.10.10.2:10000".parse().unwrap();
        let target: SocketAddr = "8.8.8.8:443".parse().unwrap();
        let address = Address::Ipv4 {
            addr: [8, 8, 8, 8],
            port: 443,
        };
        let request = UdpRelayRequest {
            client,
            target,
            address: address.clone(),
            packet: b"quic-client-initial".to_vec(),
        };
        let (mut writer, mut reader) = tokio::io::duplex(4096);

        let mut rx = tokio::sync::mpsc::channel(1).1;
        let stats = UdpRelayStats::default();
        send_udp_request_batch(&mut writer, &mut state, request, &mut rx, &stats)
            .await
            .unwrap();
        drop(writer);

        let mut encoded = Vec::new();
        reader.read_to_end(&mut encoded).await.unwrap();
        let packet = UdpRelayPacket::decode(&encoded).unwrap();

        assert_eq!(packet.flow_id, 1);
        match packet.address {
            Address::Ipv4 { addr, port } => {
                assert_eq!(addr, [8, 8, 8, 8]);
                assert_eq!(port, 443);
            }
            other => panic!("unexpected relay address: {other:?}"),
        }
        assert_eq!(packet.data, b"quic-client-initial");
        assert_eq!(state.flow(packet.flow_id).unwrap().client, client);
        assert_eq!(state.flow(packet.flow_id).unwrap().target, target);
    }
}
