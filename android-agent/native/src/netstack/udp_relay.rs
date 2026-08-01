use std::collections::{HashMap, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use common::spawn_guarded;
use futures::SinkExt;
use protocol::{Address, TransportProtocol, UdpRelayPacket, udp_transport::UDP_MAX_MESSAGE_SIZE};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::ForwardContext;
use super::udp::UdpWriter;
use crate::error::Result;

const UDP_FLOW_TTL: Duration = Duration::from_secs(300);
const UDP_RELAY_CHANNEL_SIZE: usize = 4096;
const UDP_RELAY_SHARD_COUNT: usize = 4;
const UDP_RELAY_REQUEST_BATCH_LIMIT: usize = 32;
const UDP_RELAY_CONNECTION_IDLE: Duration = Duration::from_secs(30);

pub(super) struct UdpRelay {
    shards: Vec<mpsc::Sender<UdpRelayRequest>>,
    stats: Arc<UdpRelayStats>,
}

#[derive(Clone, Debug)]
pub struct UdpRelayRequest {
    pub client: SocketAddr,
    pub target: SocketAddr,
    pub address: Address,
    pub packet: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UdpFlowKey {
    pub client: SocketAddr,
    pub target: SocketAddr,
}

pub struct UdpRelayState {
    // (client,target) -> flow_id，保证 Android VPN 内同一 UDP flow 在 proxy 端复用同一个 UDP socket。
    flow_ids: HashMap<UdpFlowKey, u64>,
    // flow_id -> (client,target)，用于把 proxy 响应写回正确的 netstack 方向。
    flows: HashMap<u64, UdpFlowKey>,
    last_seen: HashMap<u64, Instant>,
    next_flow_id: u64,
}

#[derive(Debug, Default)]
pub struct UdpRelayStats {
    sent_packets: AtomicU64,
    sent_payload_bytes: AtomicU64,
    send_batches: AtomicU64,
    send_batched_packets: AtomicU64,
    response_packets: AtomicU64,
    response_payload_bytes: AtomicU64,
    queue_drops: AtomicU64,
}

#[derive(Debug, Default)]
pub struct UdpRelayStatsSnapshot {
    pub sent_packets: u64,
    pub sent_payload_bytes: u64,
    pub send_batches: u64,
    pub send_batched_packets: u64,
    pub response_packets: u64,
    pub response_payload_bytes: u64,
    pub queue_drops: u64,
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

    pub fn snapshot_and_reset(&self) -> UdpRelayStatsSnapshot {
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

impl Default for UdpRelayState {
    fn default() -> Self {
        Self::new()
    }
}

impl UdpRelayState {
    pub fn new() -> Self {
        Self {
            flow_ids: HashMap::new(),
            flows: HashMap::new(),
            last_seen: HashMap::new(),
            next_flow_id: 1,
        }
    }

    pub fn flow_id(&mut self, client: SocketAddr, target: SocketAddr) -> u64 {
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

    pub fn flow(&self, flow_id: u64) -> Option<UdpFlowKey> {
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
        context: ForwardContext,
        netstack_tx: UdpWriter,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        let mut shards = Vec::with_capacity(UDP_RELAY_SHARD_COUNT);
        let stats = Arc::new(UdpRelayStats::default());
        for shard_index in 0..UDP_RELAY_SHARD_COUNT {
            let (tx, rx) = mpsc::channel(UDP_RELAY_CHANNEL_SIZE);
            shards.push(tx);
            debug!("starting Android TUN UDP relay shard {shard_index}");
            spawn_guarded(
                "android tun udp relay",
                run_udp_relay(
                    context.clone(),
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
                debug!("Android TUN UDP relay queue is full; dropping packet");
            }
            Err(TrySendError::Closed(_)) => {
                debug!("Android TUN UDP relay is closed; dropping packet");
            }
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
    context: ForwardContext,
    netstack_tx: UdpWriter,
    mut rx: mpsc::Receiver<UdpRelayRequest>,
    shutdown: CancellationToken,
    stats: Arc<UdpRelayStats>,
) {
    let mut state = UdpRelayState::new();
    // 写入失败时保留当前请求，重建共享连接后优先重发，避免 Android VPN 首包直接丢失。
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

        let connected = connect_udp_relay_stream(&context).await;
        let proxy_io = match connected {
            Ok(proxy_io) => {
                reconnect_delay = Duration::from_millis(200);
                proxy_io
            }
            Err(e) => {
                warn!("Android TUN UDP relay connection failed; retrying");
                debug!(error = %e, "Android TUN UDP relay connection failure details");
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(reconnect_delay) => {}
                }
                reconnect_delay = (reconnect_delay * 2).min(Duration::from_secs(5));
                retry_request = Some(first_request);
                continue;
            }
        };
        debug!("Android TUN UDP relay connected");
        let (mut reader, mut writer) = tokio::io::split(proxy_io);
        let mut cleanup = tokio::time::interval(Duration::from_secs(60));
        cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let idle_sleep = tokio::time::sleep(UDP_RELAY_CONNECTION_IDLE);
        tokio::pin!(idle_sleep);
        retry_request = Some(first_request);
        // UdpRelayPacket adds flow/address metadata to the original UDP payload.
        // Keep one complete native-UDP message in a single AsyncRead call.
        let mut response_buf = vec![0u8; UDP_MAX_MESSAGE_SIZE];

        loop {
            if let Some(request) = retry_request.take() {
                if let Err((e, request)) =
                    send_udp_relay_request_batch(&mut writer, &mut state, request, &mut rx, &stats)
                        .await
                {
                    debug!("Android TUN UDP relay write failed: {e}");
                    retry_request = Some(request);
                    break;
                }
                idle_sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + UDP_RELAY_CONNECTION_IDLE);
                continue;
            }

            tokio::select! {
                _ = shutdown.cancelled() => {
                    let _ = writer.shutdown().await;
                    return;
                }
                _ = &mut idle_sleep => {
                    debug!("Android TUN UDP relay idle; closing connection");
                    let _ = writer.shutdown().await;
                    break;
                }
                _ = cleanup.tick() => {
                    state.cleanup_expired();
                    debug!(
                        "Android TUN UDP relay shard stats: active_flows={} tracked_flow_keys={}",
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
                        send_udp_relay_request_batch(&mut writer, &mut state, request, &mut rx, &stats).await
                    {
                        debug!("Android TUN UDP relay write failed: {e}");
                        retry_request = Some(request);
                        break;
                    }
                    idle_sleep.as_mut().reset(
                        tokio::time::Instant::now() + UDP_RELAY_CONNECTION_IDLE,
                    );
                }
                read = reader.read(&mut response_buf) => {
                    match read {
                        Ok(0) => {
                            debug!("Android TUN UDP relay closed");
                            break;
                        }
                        Ok(n) => {
                            match handle_udp_relay_response(
                                &netstack_tx,
                                &state,
                                &response_buf[..n],
                            ).await {
                                Ok(payload_bytes) => stats.record_response(payload_bytes),
                                Err(e) => debug!("Android TUN UDP relay response failed: {e}"),
                            }
                            idle_sleep.as_mut().reset(
                                tokio::time::Instant::now() + UDP_RELAY_CONNECTION_IDLE,
                            );
                        }
                        Err(e) => {
                            debug!("Android TUN UDP relay read failed: {e}");
                            break;
                        }
                    }
                }
            }
        }
    }

    debug!("Android TUN UDP relay exited");
}

mod relay_io;
pub use relay_io::send_udp_relay_request_batch;
use relay_io::*;
