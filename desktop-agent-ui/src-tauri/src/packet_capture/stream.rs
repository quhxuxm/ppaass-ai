use super::*;

pub(crate) fn analyze_reassembled_tcp_streams(packets: &mut [CapturedPacket]) {
    let mut streams = HashMap::<String, Vec<Vec<usize>>>::new();
    for (index, packet) in packets.iter().enumerate() {
        let Some(sequence) = packet
            .tcp_sequence
            .filter(|_| !packet.payload_bytes.is_empty())
        else {
            continue;
        };
        let sessions = streams
            .entry(format!(
                "{}:{}>{}:{}",
                packet.source,
                packet.source_port.unwrap_or_default(),
                packet.destination,
                packet.destination_port.unwrap_or_default()
            ))
            .or_default();
        let starts_new_session = sessions
            .last()
            .and_then(|session| session.last())
            .is_some_and(|previous_index| {
                let previous = &packets[*previous_index];
                let previous_end = previous
                    .tcp_sequence
                    .unwrap_or_default()
                    .wrapping_add(previous.payload_length as u32);
                sequence < previous_end
            });
        if sessions.is_empty() || starts_new_session {
            sessions.push(Vec::new());
        }
        sessions
            .last_mut()
            .expect("a TCP stream session was just created")
            .push(index);
    }

    for mut indices in streams.into_values().flatten() {
        indices.sort_by_key(|index| packets[*index].tcp_sequence.unwrap_or_default());
        let Some(start_sequence) = indices
            .first()
            .and_then(|index| packets[*index].tcp_sequence)
        else {
            continue;
        };
        let mut assembled = Vec::<u8>::new();
        let mut packet_count = 0usize;
        let mut terminal_index = indices[0];
        let mut has_gap = false;
        for index in indices {
            let packet = &packets[index];
            let offset = packet
                .tcp_sequence
                .unwrap_or(start_sequence)
                .wrapping_sub(start_sequence) as usize;
            if offset > assembled.len() {
                has_gap = true;
                break;
            }
            if offset < assembled.len() {
                let overlap = assembled.len() - offset;
                if overlap < packet.payload_bytes.len() {
                    assembled.extend_from_slice(&packet.payload_bytes[overlap..]);
                }
            } else {
                assembled.extend_from_slice(&packet.payload_bytes);
            }
            packet_count += 1;
            terminal_index = index;
        }
        if packet_count < 2 {
            continue;
        }

        let source_port = packets[terminal_index].source_port;
        let destination_port = packets[terminal_index].destination_port;
        packets[terminal_index].protocol_layers.push(protocol_layer(
            "Reassembled TCP Stream",
            format!("{packet_count} segments, {} bytes", assembled.len()),
            [
                ("Segments", packet_count.to_string()),
                ("Reassembled length", format!("{} bytes", assembled.len())),
                (
                    "Sequence range",
                    format!(
                        "{}–{}",
                        start_sequence,
                        start_sequence.wrapping_add(assembled.len() as u32)
                    ),
                ),
                (
                    "Status",
                    if has_gap {
                        "Stopped at a missing segment"
                    } else {
                        "Contiguous"
                    }
                    .to_string(),
                ),
            ],
        ));
        if let Some(mut layer) =
            analyze_application_protocol("TCP", source_port, destination_port, &assembled)
        {
            packets[terminal_index].sub_protocol = Some(application_protocol_name(&layer));
            layer.summary = format!(
                "{} · reassembled from {packet_count} segments",
                layer.summary
            );
            packets[terminal_index].protocol_layers.push(layer);
        }
    }

    for packet in packets {
        packet.payload_bytes.clear();
        packet.payload_bytes.shrink_to_fit();
    }
}

pub(crate) fn explicit_proxy_direction(
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
pub(crate) struct ProxyFlowState {
    protocol: Option<String>,
    next_sequences: HashMap<String, u32>,
    payload_prefixes: HashMap<String, Vec<u8>>,
}

pub(crate) struct ProxyFlowTracker {
    listen_port: Option<u16>,
    flows: HashMap<String, ProxyFlowState>,
}

impl ProxyFlowTracker {
    pub(crate) fn new(listen_port: Option<u16>) -> Self {
        Self {
            listen_port,
            flows: HashMap::new(),
        }
    }

    pub(crate) fn observe(&mut self, packet: &CapturedPacket, flow_key: &str) -> Option<String> {
        let listen_port = self.listen_port?;
        if !packet_is_proxy_entry(packet, listen_port) {
            return None;
        }

        let state = self.flows.entry(flow_key.to_string()).or_default();
        let mut stream_protocol = None;
        if let Some(sequence) = packet.tcp_sequence.filter(|_| packet.payload_length > 0) {
            let direction = endpoint(&packet.source, packet.source_port);
            if state
                .next_sequences
                .get(&direction)
                .is_some_and(|next_sequence| sequence < *next_sequence)
            {
                *state = ProxyFlowState::default();
            }
            let expected_sequence = state.next_sequences.get(&direction).copied();
            let payload_prefix = state.payload_prefixes.entry(direction.clone()).or_default();
            if expected_sequence.is_some_and(|expected| sequence != expected) {
                payload_prefix.clear();
            }
            let remaining = PROXY_HANDSHAKE_PREFIX_LEN.saturating_sub(payload_prefix.len());
            payload_prefix.extend_from_slice(
                &packet.payload_bytes[..packet.payload_bytes.len().min(remaining)],
            );
            if state.protocol.is_none() {
                stream_protocol = detected_proxy_protocol_in_payload(packet, payload_prefix);
            }
            state.next_sequences.insert(
                direction,
                sequence.wrapping_add(packet.payload_length as u32),
            );
        }

        if state.protocol.is_none() {
            state.protocol = detected_proxy_protocol(packet)
                .or(stream_protocol)
                .map(str::to_string);
        }
        if state.protocol.is_some() {
            state.payload_prefixes.clear();
        }
        state.protocol.clone()
    }
}

pub(crate) fn packet_uses_port(packet: &CapturedPacket, port: u16) -> bool {
    packet.source_port == Some(port) || packet.destination_port == Some(port)
}

pub(crate) fn packet_is_proxy_entry(packet: &CapturedPacket, listen_port: u16) -> bool {
    packet_uses_port(packet, listen_port)
        || (packet.protocol == "UDP" && packet.sub_protocol.as_deref() == Some("SOCKS5"))
}

pub(crate) fn restrict_socks5_tcp_detection(packet: &mut CapturedPacket, listen_port: Option<u16>) {
    if packet.protocol != "TCP" || packet.sub_protocol.as_deref() != Some("SOCKS5") {
        return;
    }
    if listen_port.is_some_and(|port| packet_uses_port(packet, port)) {
        return;
    }
    clear_socks5_detection(packet);
}

pub(crate) fn suppress_conflicting_socks5_detection(packet: &mut CapturedPacket) {
    if packet.sub_protocol.as_deref() == Some("SOCKS5")
        && packet
            .proxy_protocol
            .as_deref()
            .is_some_and(|protocol| protocol != "SOCKS5")
    {
        clear_socks5_detection(packet);
    }
}

pub(crate) fn clear_socks5_detection(packet: &mut CapturedPacket) {
    packet.sub_protocol = None;
    packet.protocol_layers.retain(|layer| {
        layer.name != "SOCKS Version 5" && layer.name != "SOCKS Version 5 UDP Datagram"
    });
}

pub(crate) fn detected_proxy_protocol(packet: &CapturedPacket) -> Option<&str> {
    match packet.sub_protocol.as_deref() {
        Some(protocol @ ("HTTP" | "SOCKS5")) => Some(protocol),
        _ => None,
    }
}

pub(crate) fn detected_proxy_protocol_in_payload(
    packet: &CapturedPacket,
    payload: &[u8],
) -> Option<&'static str> {
    let layer =
        analyze_application_protocol("TCP", packet.source_port, packet.destination_port, payload)?;
    match layer.name.as_str() {
        "Hypertext Transfer Protocol" => Some("HTTP"),
        "SOCKS Version 5" => Some("SOCKS5"),
        _ => None,
    }
}

pub(crate) fn flow_key(packet: &CapturedPacket) -> String {
    let left = endpoint(&packet.source, packet.source_port);
    let right = endpoint(&packet.destination, packet.destination_port);
    if left <= right {
        format!("{}|{left}|{right}", packet.protocol)
    } else {
        format!("{}|{right}|{left}", packet.protocol)
    }
}
