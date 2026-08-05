use super::*;

#[derive(Default)]
pub(super) struct TcpReassemblySession {
    pub(super) indices: Vec<usize>,
    pub(super) syn_sequence: Option<u32>,
    pub(super) last_payload_end_sequence: Option<u32>,
    pub(super) has_payload: bool,
    pub(super) closed: bool,
}

pub(super) fn reassemble_tcp(packets: &mut [CapturedPacket]) {
    let mut streams = HashMap::<String, Vec<TcpReassemblySession>>::new();
    for (index, packet) in packets.iter().enumerate() {
        let Some(sequence) = packet.tcp_sequence else {
            continue;
        };
        let has_syn = tcp_has_flag(packet, TCP_FLAG_SYN);
        let has_terminal_flag =
            tcp_has_flag(packet, TCP_FLAG_FIN) || tcp_has_flag(packet, TCP_FLAG_RST);
        if packet.payload_length == 0 && !has_syn && !has_terminal_flag {
            continue;
        }

        let sessions = streams
            .entry(format!(
                "{}:{}>{}:{}",
                packet.source,
                packet.source_port.unwrap_or_default(),
                packet.destination,
                packet.destination_port.unwrap_or_default()
            ))
            .or_default();
        let starts_new_session = sessions.last().is_some_and(|session| {
            let exact_retransmission = session
                .indices
                .iter()
                .any(|prior| same_tcp_segment(&packets[*prior], packet));
            if has_syn && session.closed {
                true
            } else if has_syn || session.closed {
                !exact_retransmission
            } else {
                // Synthetic captures historically had no SYN/FIN. Sequence 1
                // is their sole backward-compatible session boundary; other
                // lower sequences are retransmission or out-of-order traffic.
                // Keep a natural 32-bit wrap only while 1 is the current
                // chronological continuation, rather than matching any stale
                // segment from earlier in the session.
                sequence == 1
                    && packet.payload_length > 0
                    && session.has_payload
                    && session.last_payload_end_sequence != Some(1)
            }
        });
        if sessions.is_empty() || starts_new_session {
            sessions.push(TcpReassemblySession {
                syn_sequence: has_syn.then_some(sequence),
                ..TcpReassemblySession::default()
            });
        }
        let session = sessions
            .last_mut()
            .expect("a TCP stream session was just created");
        if has_syn && session.syn_sequence.is_none() {
            session.syn_sequence = Some(sequence);
        }
        session.indices.push(index);
        session.has_payload |= packet.payload_length > 0;
        if packet.payload_length > 0 {
            session.last_payload_end_sequence = packet
                .tcp_sequence
                .map(|sequence| sequence.wrapping_add(tcp_sequence_span(packet)));
        }
        session.closed |= has_terminal_flag;
    }

    for session in streams.into_values().flatten() {
        reassemble_tcp_session(packets, session);
    }
}

pub(super) fn reassemble_tcp_session(
    packets: &mut [CapturedPacket],
    session: TcpReassemblySession,
) {
    let mut payload_indices: Vec<_> = session
        .indices
        .iter()
        .copied()
        .filter(|index| packets[*index].payload_length > 0)
        .collect();
    if payload_indices.is_empty() {
        return;
    }
    let start = session
        .syn_sequence
        .map(|sequence| sequence.wrapping_add(1))
        .or_else(|| {
            payload_indices
                .iter()
                .filter_map(|index| tcp_payload_sequence(&packets[*index]))
                .reduce(|start, sequence| {
                    if (sequence.wrapping_sub(start) as i32) < 0 {
                        sequence
                    } else {
                        start
                    }
                })
        })
        .expect("payload packets have TCP sequence numbers");
    payload_indices.sort_by_key(|index| {
        tcp_payload_sequence(&packets[*index])
            .unwrap_or(start)
            .wrapping_sub(start)
    });

    let available_segment_count = payload_indices.len();
    let mut assembled = Vec::new();
    let mut contiguous_true_length = 0usize;
    let mut truncation_reason = None;
    let mut processed_count = 0usize;
    let mut last_processed = None;
    let mut diagnostic_terminal = payload_indices[0];
    for index in &payload_indices {
        let packet = &packets[*index];
        let sequence = tcp_payload_sequence(packet).unwrap_or(start);
        let offset = sequence.wrapping_sub(start) as usize;
        if offset > contiguous_true_length {
            diagnostic_terminal = last_processed.unwrap_or(*index);
            truncation_reason = Some(format!(
                "Sequence gap before packet {} (expected {}, received {})",
                packet.number,
                start.wrapping_add(contiguous_true_length as u32),
                sequence
            ));
            break;
        }

        let overlap = contiguous_true_length.saturating_sub(offset);
        if overlap >= packet.payload_length {
            processed_count += 1;
            last_processed = Some(last_processed.map_or(*index, |prior: usize| prior.max(*index)));
            continue;
        }
        let remaining_true_length = packet.payload_length - overlap;
        if overlap >= packet.payload.len() {
            diagnostic_terminal = last_processed.unwrap_or(*index);
            truncation_reason = Some(format!(
                "Packet {} payload is retained only as a bounded prefix",
                packet.number
            ));
            break;
        }
        let available = &packet.payload[overlap..];
        let append_length = available
            .len()
            .min(remaining_true_length)
            .min(MAX_REASSEMBLED_TCP_BYTES.saturating_sub(assembled.len()));
        assembled.extend_from_slice(&available[..append_length]);
        if append_length > 0 {
            processed_count += 1;
            last_processed = Some(last_processed.map_or(*index, |prior: usize| prior.max(*index)));
            diagnostic_terminal = last_processed.expect("the current packet was processed");
        }
        if append_length < remaining_true_length {
            truncation_reason = Some(if assembled.len() >= MAX_REASSEMBLED_TCP_BYTES {
                format!(
                    "Reassembly reached the {} byte analysis limit",
                    MAX_REASSEMBLED_TCP_BYTES
                )
            } else {
                format!(
                    "Packet {} payload is retained only as a bounded prefix",
                    packet.number
                )
            });
            break;
        }
        contiguous_true_length = contiguous_true_length.max(offset + packet.payload_length);
    }

    let is_truncated = truncation_reason.is_some();
    let terminal = if is_truncated {
        diagnostic_terminal
    } else {
        last_processed.unwrap_or(payload_indices[0])
    };
    if available_segment_count > 1 || is_truncated {
        let mut fields = vec![
            field("Captured payload segments", available_segment_count),
            field("Analyzed payload segments", processed_count),
            field("Sequence start", start),
        ];
        let summary = if let Some(reason) = truncation_reason {
            fields.push(field(
                "Analyzed prefix",
                format!("{} bytes", assembled.len()),
            ));
            fields.push(field("Reassembly truncated", true));
            fields.push(field("Truncation reason", reason));
            format!(
                "Analyzed prefix from {processed_count} of {available_segment_count} segments, {} bytes",
                assembled.len()
            )
        } else {
            fields.push(field(
                "Reassembled length",
                format!("{} bytes", assembled.len()),
            ));
            fields.push(field("Reassembly truncated", false));
            format!(
                "{available_segment_count} segments, {} bytes",
                assembled.len()
            )
        };
        packets[terminal]
            .protocol_layers
            .push(layer("Reassembled TCP Stream", summary, fields));

        if processed_count > 1
            && !assembled.is_empty()
            && let Some(mut application) = analyze_application(
                "TCP",
                packets[terminal].source_port,
                packets[terminal].destination_port,
                &assembled,
            )
        {
            packets[terminal].sub_protocol = Some(short_protocol(&application.name));
            application.summary = if is_truncated {
                format!(
                    "{} · analyzed reassembly prefix from {processed_count} of {available_segment_count} segments",
                    application.summary
                )
            } else {
                format!(
                    "{} · reassembled from {available_segment_count} segments",
                    application.summary
                )
            };
            packets[terminal].protocol_layers.push(application);
        }
    }
}

pub fn tcp_has_flag(packet: &CapturedPacket, flag: u8) -> bool {
    packet.tcp_flags.is_some_and(|flags| flags & flag != 0)
}

pub fn tcp_payload_sequence(packet: &CapturedPacket) -> Option<u32> {
    packet
        .tcp_sequence
        .map(|sequence| sequence.wrapping_add(u32::from(tcp_has_flag(packet, TCP_FLAG_SYN))))
}

pub fn tcp_sequence_span(packet: &CapturedPacket) -> u32 {
    (packet.payload_length as u32)
        .wrapping_add(u32::from(tcp_has_flag(packet, TCP_FLAG_SYN)))
        .wrapping_add(u32::from(tcp_has_flag(packet, TCP_FLAG_FIN)))
}

pub(super) fn same_tcp_segment(left: &CapturedPacket, right: &CapturedPacket) -> bool {
    left.tcp_sequence == right.tcp_sequence
        && left
            .tcp_flags
            .map(|flags| flags & (TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_RST))
            == right
                .tcp_flags
                .map(|flags| flags & (TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_RST))
        && left.payload_length == right.payload_length
        && left.payload == right.payload
        && left.analysis_payload_truncated == right.analysis_payload_truncated
}
