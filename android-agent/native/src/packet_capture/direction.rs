use super::*;

pub(super) fn explicit_proxy_direction(
    packet: &CapturedPacket,
    listen_port: Option<u16>,
) -> Option<&'static str> {
    let listen_port = listen_port?;
    if packet.protocol != "TCP" {
        return None;
    }
    if packet.destination_port == Some(listen_port) {
        Some("upload")
    } else if packet.source_port == Some(listen_port) {
        Some("download")
    } else {
        None
    }
}

#[derive(Default)]
pub(super) struct WindowDirectionTracker {
    pub(super) flows: HashMap<String, WindowDirectionState>,
}

pub(super) struct WindowDirectionState {
    pub(super) first_source: String,
    pub(super) retained_packets: usize,
}

impl WindowDirectionTracker {
    pub(super) fn observe(&mut self, packet: &CapturedPacket, flow_key: &str) -> &'static str {
        let source = endpoint(&packet.source, packet.source_port);
        let state =
            self.flows
                .entry(flow_key.to_string())
                .or_insert_with(|| WindowDirectionState {
                    first_source: source.clone(),
                    retained_packets: 0,
                });
        state.retained_packets += 1;
        if state.first_source == source {
            "upload"
        } else {
            "download"
        }
    }

    pub(super) fn release(&mut self, packet: &CapturedPacket, flow_key: &str) {
        let should_remove = self.flows.get_mut(flow_key).is_some_and(|state| {
            state.retained_packets = state.retained_packets.saturating_sub(1);
            state.retained_packets == 0
        });
        if should_remove {
            self.flows.remove(flow_key);
        }
        debug_assert!(packet.direction_tracked);
    }
}

pub(super) struct ProxyFlowState {
    pub(super) session_id: u64,
    pub(super) protocol: Option<String>,
    pub(super) upload_prefix: Vec<u8>,
    pub(super) upload_next_sequence: Option<u32>,
    pub(super) upload_syn_sequence: Option<u32>,
    pub(super) seen_packet: bool,
    pub(super) seen_upload_payload: bool,
    pub(super) upload_prefix_truncated: bool,
    pub(super) pending_upload_segments: Vec<ProxyPendingSegment>,
    pub(super) ended: bool,
}

#[derive(PartialEq, Eq)]
pub(super) struct ProxyPendingSegment {
    pub(super) sequence: u32,
    pub(super) end_sequence: u32,
    pub(super) payload_length: usize,
    pub(super) payload_prefix: Vec<u8>,
}

impl ProxyFlowState {
    pub(super) fn new(session_id: u64) -> Self {
        Self {
            session_id,
            protocol: None,
            upload_prefix: Vec::new(),
            upload_next_sequence: None,
            upload_syn_sequence: None,
            seen_packet: false,
            seen_upload_payload: false,
            upload_prefix_truncated: false,
            pending_upload_segments: Vec::new(),
            ended: false,
        }
    }
}

pub(super) struct ProxyFlowObservation {
    pub(super) session_id: u64,
    pub(super) protocol: Option<String>,
}
