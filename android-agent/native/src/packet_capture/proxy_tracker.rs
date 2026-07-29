use super::*;

pub(super) struct ProxyFlowTracker {
    pub(super) listen_port: Option<u16>,
    pub(super) flows: HashMap<String, ProxyFlowState>,
    pub(super) flow_order: VecDeque<String>,
    pub(super) session_protocols: HashMap<u64, String>,
    pub(super) session_order: VecDeque<u64>,
    pub(super) next_session_id: u64,
}

impl ProxyFlowTracker {
    pub(super) fn new(listen_port: Option<u16>) -> Self {
        Self {
            listen_port,
            flows: HashMap::new(),
            flow_order: VecDeque::new(),
            session_protocols: HashMap::new(),
            session_order: VecDeque::new(),
            next_session_id: 1,
        }
    }

    pub(super) fn observe(
        &mut self,
        packet: &CapturedPacket,
        flow_key: &str,
    ) -> Option<ProxyFlowObservation> {
        let listen_port = self.listen_port?;
        if packet.protocol != "TCP" || !packet_uses_port(packet, listen_port) {
            return None;
        }

        if !self.flows.contains_key(flow_key) {
            self.insert_flow(flow_key);
        }
        let is_upload = packet.destination_port == Some(listen_port);
        let starts_new_session = {
            let state = self.flows.get(flow_key).expect("proxy flow was inserted");
            let new_syn = is_upload
                && tcp_has_flag(packet, TCP_FLAG_SYN)
                && state.seen_packet
                && (state.ended || state.upload_syn_sequence != packet.tcp_sequence);
            // Legacy synthetic captures have neither SYN/FIN nor network
            // retransmissions. Their upload sequence always starts at 1, so
            // another sequence-1 payload is an unconditional tuple-reuse
            // boundary unless the preceding segment naturally wrapped and
            // made 1 the expected continuation.
            let sequence_one_boundary = is_upload
                && packet.tcp_sequence == Some(1)
                && packet.payload_length > 0
                && state.seen_upload_payload
                && state.upload_next_sequence != Some(1);
            new_syn || sequence_one_boundary
        };
        if starts_new_session {
            let session_id = self.allocate_session_id();
            self.flows
                .insert(flow_key.to_string(), ProxyFlowState::new(session_id));
        }

        let state = self
            .flows
            .get_mut(flow_key)
            .expect("proxy flow was inserted");
        let mut stream_protocol = None;
        if is_upload && tcp_has_flag(packet, TCP_FLAG_SYN) {
            state.upload_syn_sequence = packet.tcp_sequence;
            if state.upload_next_sequence.is_none() {
                state.upload_next_sequence =
                    packet.tcp_sequence.map(|sequence| sequence.wrapping_add(1));
            }
        }
        if is_upload && packet.payload_length > 0 {
            append_proxy_upload_prefix(state, packet);
            state.seen_upload_payload = true;
            if state.protocol.is_none() {
                stream_protocol = detected_proxy_protocol_in_payload(packet, &state.upload_prefix);
            }
        }

        if state.protocol.is_none() {
            state.protocol = is_upload
                .then(|| detected_proxy_protocol(packet))
                .flatten()
                .or(stream_protocol)
                .map(str::to_string);
        }
        if state.protocol.is_some() {
            state.upload_prefix.clear();
            state.pending_upload_segments.clear();
        }
        state.seen_packet = true;
        state.ended |= tcp_has_flag(packet, TCP_FLAG_FIN) || tcp_has_flag(packet, TCP_FLAG_RST);
        let observation = ProxyFlowObservation {
            session_id: state.session_id,
            protocol: state.protocol.clone(),
        };
        let learned_protocol = state
            .protocol
            .as_ref()
            .map(|protocol| (state.session_id, protocol.clone()));
        if let Some((session_id, protocol)) = learned_protocol {
            self.remember_session_protocol(session_id, protocol);
        }
        Some(observation)
    }

    pub(super) fn insert_flow(&mut self, flow_key: &str) {
        while self.flows.len() >= MAX_PROXY_FLOW_STATES {
            let Some(oldest) = self.flow_order.pop_front() else {
                break;
            };
            self.flows.remove(&oldest);
        }
        let session_id = self.allocate_session_id();
        self.flows
            .insert(flow_key.to_string(), ProxyFlowState::new(session_id));
        self.flow_order.push_back(flow_key.to_string());
    }

    pub(super) fn allocate_session_id(&mut self) -> u64 {
        let session_id = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1).max(1);
        session_id
    }

    pub(super) fn remember_session_protocol(&mut self, session_id: u64, protocol: String) {
        if self.session_protocols.contains_key(&session_id) {
            return;
        }
        while self.session_protocols.len() >= MAX_PROXY_SESSION_LABELS {
            let Some(oldest) = self.session_order.pop_front() else {
                break;
            };
            self.session_protocols.remove(&oldest);
        }
        self.session_protocols.insert(session_id, protocol);
        self.session_order.push_back(session_id);
    }

    pub(super) fn protocol_for_session(&self, session_id: u64) -> Option<&str> {
        self.session_protocols.get(&session_id).map(String::as_str)
    }
}

pub(super) fn append_proxy_upload_prefix(state: &mut ProxyFlowState, packet: &CapturedPacket) {
    if state.upload_prefix_truncated {
        return;
    }
    let Some(sequence) = tcp_payload_sequence(packet) else {
        return;
    };
    let segment = ProxyPendingSegment {
        sequence,
        end_sequence: packet
            .tcp_sequence
            .unwrap_or(sequence)
            .wrapping_add(tcp_sequence_span(packet)),
        payload_length: packet.payload_length,
        payload_prefix: packet.payload.clone(),
    };
    if !append_proxy_segment(state, &segment) {
        remember_pending_proxy_segment(state, segment);
        return;
    }
    drain_pending_proxy_segments(state);
}

pub(super) fn append_proxy_segment(
    state: &mut ProxyFlowState,
    segment: &ProxyPendingSegment,
) -> bool {
    let append_from = match state.upload_next_sequence {
        None => 0,
        Some(expected) => {
            let relative = segment.sequence.wrapping_sub(expected) as i32;
            if relative > 0 {
                return false;
            }
            expected.wrapping_sub(segment.sequence) as usize
        }
    };
    if append_from >= segment.payload_length {
        if state
            .upload_next_sequence
            .is_some_and(|expected| segment.end_sequence.wrapping_sub(expected) as i32 > 0)
        {
            state.upload_next_sequence = Some(segment.end_sequence);
        }
        return true;
    }
    if append_from >= segment.payload_prefix.len() {
        state.upload_prefix_truncated = true;
        return true;
    }

    let true_remaining = segment.payload_length - append_from;
    let available = &segment.payload_prefix[append_from..];
    let append_length = available
        .len()
        .min(true_remaining)
        .min(PROXY_HANDSHAKE_PREFIX_LEN.saturating_sub(state.upload_prefix.len()));
    state
        .upload_prefix
        .extend_from_slice(&available[..append_length]);
    if append_length < true_remaining {
        state.upload_prefix_truncated = true;
    }
    state.upload_next_sequence = Some(segment.end_sequence);
    true
}

pub(super) fn remember_pending_proxy_segment(
    state: &mut ProxyFlowState,
    segment: ProxyPendingSegment,
) {
    if state.pending_upload_segments.contains(&segment) {
        return;
    }
    let retained_bytes: usize = state
        .pending_upload_segments
        .iter()
        .map(|pending| pending.payload_prefix.len())
        .sum();
    if state.pending_upload_segments.len() >= MAX_PROXY_PENDING_SEGMENTS
        || retained_bytes.saturating_add(segment.payload_prefix.len()) > PROXY_HANDSHAKE_PREFIX_LEN
    {
        state.upload_prefix_truncated = true;
        state.pending_upload_segments.clear();
        return;
    }
    state.pending_upload_segments.push(segment);
}

pub(super) fn drain_pending_proxy_segments(state: &mut ProxyFlowState) {
    while !state.upload_prefix_truncated {
        let Some(expected) = state.upload_next_sequence else {
            return;
        };
        state
            .pending_upload_segments
            .retain(|segment| segment.end_sequence.wrapping_sub(expected) as i32 > 0);
        let Some(index) = state
            .pending_upload_segments
            .iter()
            .position(|segment| segment.sequence.wrapping_sub(expected) as i32 <= 0)
        else {
            return;
        };
        let segment = state.pending_upload_segments.swap_remove(index);
        if !append_proxy_segment(state, &segment) {
            state.pending_upload_segments.push(segment);
            return;
        }
    }
}

pub(super) fn packet_uses_port(packet: &CapturedPacket, port: u16) -> bool {
    packet.source_port == Some(port) || packet.destination_port == Some(port)
}

pub(super) fn restrict_socks5_tcp_detection(packet: &mut CapturedPacket, listen_port: Option<u16>) {
    if packet.protocol != "TCP" || packet.sub_protocol.as_deref() != Some("SOCKS5") {
        return;
    }
    if packet.proxy_marker.is_some() {
        return;
    }
    if listen_port.is_some_and(|port| packet_uses_port(packet, port)) {
        return;
    }
    clear_socks5_detection(packet);
}

pub(super) fn suppress_conflicting_socks5_detection(packet: &mut CapturedPacket) {
    if packet.sub_protocol.as_deref() == Some("SOCKS5")
        && packet
            .proxy_protocol
            .as_deref()
            .is_some_and(|protocol| protocol != "SOCKS5")
    {
        clear_socks5_detection(packet);
    }
}

pub(super) fn clear_socks5_detection(packet: &mut CapturedPacket) {
    packet.sub_protocol = None;
    packet
        .protocol_layers
        .retain(|layer| layer.name != "SOCKS Version 5");
}

pub(super) fn detected_proxy_protocol(packet: &CapturedPacket) -> Option<&str> {
    match packet.sub_protocol.as_deref() {
        Some(protocol @ ("HTTP" | "SOCKS5")) => Some(protocol),
        _ => None,
    }
}

pub(super) fn detected_proxy_protocol_in_payload(
    packet: &CapturedPacket,
    payload: &[u8],
) -> Option<&'static str> {
    let layer = analyze_application("TCP", packet.source_port, packet.destination_port, payload)?;
    match layer.name.as_str() {
        "Hypertext Transfer Protocol" => Some("HTTP"),
        "SOCKS Version 5" => Some("SOCKS5"),
        _ => None,
    }
}

pub(super) fn flow_key(packet: &CapturedPacket) -> String {
    let left = endpoint(&packet.source, packet.source_port);
    let right = endpoint(&packet.destination, packet.destination_port);
    if left <= right {
        format!("{}|{left}|{right}", packet.protocol)
    } else {
        format!("{}|{right}|{left}", packet.protocol)
    }
}
