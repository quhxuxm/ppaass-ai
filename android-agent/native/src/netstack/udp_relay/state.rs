use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const UDP_FLOW_TTL: Duration = Duration::from_secs(300);

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

    pub fn flow(&mut self, flow_id: u64) -> Option<UdpFlowKey> {
        self.flow_at(flow_id, Instant::now())
    }

    #[doc(hidden)]
    pub fn flow_at(&mut self, flow_id: u64, now: Instant) -> Option<UdpFlowKey> {
        let flow = self.flows.get(&flow_id).copied()?;
        // Downlink activity keeps a flow alive too. Otherwise a receive-heavy
        // UDP/QUIC flow loses its return mapping after the fixed TTL.
        self.last_seen.insert(flow_id, now);
        Some(flow)
    }

    pub(super) fn active_flows(&self) -> usize {
        self.flows.len()
    }

    pub(super) fn tracked_flow_keys(&self) -> usize {
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

    pub(super) fn cleanup_expired(&mut self) {
        self.cleanup_expired_at(Instant::now());
    }

    #[doc(hidden)]
    pub fn cleanup_expired_at(&mut self, now: Instant) {
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
