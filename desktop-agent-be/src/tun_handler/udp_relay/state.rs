use std::collections::{HashMap, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use protocol::Address;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use common::spawn_guarded;

use crate::yamux_session::YamuxSessionManager;

use super::super::udp_writer::UdpWriter;
use super::{
    UDP_FLOW_TTL, UDP_RELAY_CHANNEL_SIZE, UDP_RELAY_SHARD_COUNT, run_udp_relay,
    spawn_udp_relay_stats_logger,
};

pub(in crate::tun_handler) struct UdpRelay {
    pub(super) shards: Vec<mpsc::Sender<UdpRelayRequest>>,
    pub(super) stats: Arc<UdpRelayStats>,
}

#[derive(Clone, Debug)]
pub struct UdpRelayRequest {
    pub client: SocketAddr,
    pub target: SocketAddr,
    pub address: Address,
    pub packet: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq)]
pub struct UdpFlowKey {
    pub client: SocketAddr,
    pub target: SocketAddr,
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

pub struct UdpRelayState {
    // (client,target) -> flow_id，保证同一 UDP flow 在 proxy 端对应同一个 UDP socket。
    pub(super) flow_ids: HashMap<UdpFlowKey, u64>,
    // flow_id -> (client,target)，用于把 proxy 响应写回正确的 netstack 方向。
    pub(super) flows: HashMap<u64, UdpFlowKey>,
    pub(super) last_seen: HashMap<u64, Instant>,
    pub(super) next_flow_id: u64,
}

#[derive(Debug, Default)]
pub struct UdpRelayStats {
    pub(super) sent_packets: AtomicU64,
    pub(super) sent_payload_bytes: AtomicU64,
    pub(super) send_batches: AtomicU64,
    pub(super) send_batched_packets: AtomicU64,
    pub(super) response_packets: AtomicU64,
    pub(super) response_payload_bytes: AtomicU64,
    pub(super) queue_drops: AtomicU64,
}

#[derive(Debug, Default)]
pub(super) struct UdpRelayStatsSnapshot {
    pub(super) sent_packets: u64,
    pub(super) sent_payload_bytes: u64,
    pub(super) send_batches: u64,
    pub(super) send_batched_packets: u64,
    pub(super) response_packets: u64,
    pub(super) response_payload_bytes: u64,
    pub(super) queue_drops: u64,
}

impl UdpRelayStats {
    pub fn record_sent_batch(&self, packets: usize, payload_bytes: usize) {
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

    pub fn record_response(&self, payload_bytes: usize) {
        self.response_packets.fetch_add(1, Ordering::Relaxed);
        self.response_payload_bytes
            .fetch_add(payload_bytes as u64, Ordering::Relaxed);
    }

    pub fn record_queue_drop(&self) {
        self.queue_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn snapshot_and_reset(&self) -> UdpRelayStatsSnapshot {
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

    pub(super) fn active_flows(&self) -> usize {
        self.flows.len()
    }

    pub(super) fn tracked_flow_keys(&self) -> usize {
        self.flow_ids.len()
    }

    pub(super) fn next_available_flow_id(&mut self) -> u64 {
        loop {
            let id = self.next_flow_id;
            self.next_flow_id = self.next_flow_id.wrapping_add(1).max(1);
            if !self.flows.contains_key(&id) {
                return id;
            }
        }
    }

    pub(super) fn cleanup_expired(&mut self) {
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
    pub(in crate::tun_handler) fn spawn(
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

    pub(in crate::tun_handler) fn send(
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
