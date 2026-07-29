use super::*;

pub(crate) fn parse_ip_packet(
    number: usize,
    timestamp_ms: u64,
    length: usize,
    packet: &[u8],
) -> Option<CapturedPacket> {
    match packet.first()? >> 4 {
        4 => parse_ipv4_packet(number, timestamp_ms, length, packet),
        6 => parse_ipv6_packet(number, timestamp_ms, length, packet),
        _ => None,
    }
}

pub(crate) fn parse_ipv4_packet(
    number: usize,
    timestamp_ms: u64,
    length: usize,
    packet: &[u8],
) -> Option<CapturedPacket> {
    if packet.len() < 20 {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || header_len > packet.len() {
        return None;
    }
    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]).to_string();
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]).to_string();
    Some(build_packet(
        number,
        timestamp_ms,
        4,
        packet[9],
        source,
        destination,
        length,
        &packet[header_len..],
    ))
}

pub(crate) fn parse_ipv6_packet(
    number: usize,
    timestamp_ms: u64,
    length: usize,
    packet: &[u8],
) -> Option<CapturedPacket> {
    if packet.len() < 40 {
        return None;
    }
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?).to_string();
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?).to_string();
    Some(build_packet(
        number,
        timestamp_ms,
        6,
        packet[6],
        source,
        destination,
        length,
        &packet[40..],
    ))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_packet(
    number: usize,
    timestamp_ms: u64,
    ip_version: u8,
    protocol_number: u8,
    source: String,
    destination: String,
    length: usize,
    transport: &[u8],
) -> CapturedPacket {
    let mut protocol_layers = vec![
        protocol_layer(
            "Frame",
            format!("{length} bytes on DLT_RAW"),
            [
                ("Packet number", number.to_string()),
                ("Timestamp", format!("{timestamp_ms} ms")),
                ("Frame length", format!("{length} bytes")),
                ("Link type", "Raw IP (DLT_RAW)".to_string()),
            ],
        ),
        protocol_layer(
            format!("Internet Protocol Version {ip_version}"),
            format!("{source} → {destination}"),
            [
                ("Version", ip_version.to_string()),
                ("Source address", source.clone()),
                ("Destination address", destination.clone()),
                ("Protocol number", protocol_number.to_string()),
                ("Packet length", format!("{length} bytes")),
            ],
        ),
    ];
    let (protocol, source_port, destination_port, summary, payload, transport_layer, tcp_sequence) =
        match protocol_number {
            6 if transport.len() >= 20 => {
                let source_port = u16::from_be_bytes([transport[0], transport[1]]);
                let destination_port = u16::from_be_bytes([transport[2], transport[3]]);
                let header_len = usize::from(transport[12] >> 4) * 4;
                let flags = tcp_flags(transport[13]);
                let payload = transport.get(header_len..).unwrap_or_default();
                (
                    "TCP".to_string(),
                    Some(source_port),
                    Some(destination_port),
                    format!("{source_port} → {destination_port} [{flags}]"),
                    payload,
                    protocol_layer(
                        "Transmission Control Protocol",
                        format!("{source_port} → {destination_port} [{flags}]"),
                        [
                            ("Source port", source_port.to_string()),
                            ("Destination port", destination_port.to_string()),
                            (
                                "Sequence number",
                                u32::from_be_bytes([
                                    transport[4],
                                    transport[5],
                                    transport[6],
                                    transport[7],
                                ])
                                .to_string(),
                            ),
                            (
                                "Acknowledgment number",
                                u32::from_be_bytes([
                                    transport[8],
                                    transport[9],
                                    transport[10],
                                    transport[11],
                                ])
                                .to_string(),
                            ),
                            ("Header length", format!("{header_len} bytes")),
                            ("Flags", format!("0x{:02x} ({flags})", transport[13])),
                            (
                                "Window size",
                                u16::from_be_bytes([transport[14], transport[15]]).to_string(),
                            ),
                            (
                                "Checksum",
                                format!(
                                    "0x{:04x}",
                                    u16::from_be_bytes([transport[16], transport[17]])
                                ),
                            ),
                            (
                                "Urgent pointer",
                                u16::from_be_bytes([transport[18], transport[19]]).to_string(),
                            ),
                            ("Payload length", format!("{} bytes", payload.len())),
                        ],
                    ),
                    Some(u32::from_be_bytes([
                        transport[4],
                        transport[5],
                        transport[6],
                        transport[7],
                    ])),
                )
            }
            17 if transport.len() >= 8 => {
                let source_port = u16::from_be_bytes([transport[0], transport[1]]);
                let destination_port = u16::from_be_bytes([transport[2], transport[3]]);
                let payload = &transport[8..];
                (
                    "UDP".to_string(),
                    Some(source_port),
                    Some(destination_port),
                    format!("{source_port} → {destination_port}"),
                    payload,
                    protocol_layer(
                        "User Datagram Protocol",
                        format!("{source_port} → {destination_port}"),
                        [
                            ("Source port", source_port.to_string()),
                            ("Destination port", destination_port.to_string()),
                            (
                                "Length",
                                format!(
                                    "{} bytes",
                                    u16::from_be_bytes([transport[4], transport[5]])
                                ),
                            ),
                            (
                                "Checksum",
                                format!(
                                    "0x{:04x}",
                                    u16::from_be_bytes([transport[6], transport[7]])
                                ),
                            ),
                            ("Payload length", format!("{} bytes", payload.len())),
                        ],
                    ),
                    None,
                )
            }
            1 => (
                "ICMP".to_string(),
                None,
                None,
                format!("type {}", transport.first().copied().unwrap_or_default()),
                transport.get(8..).unwrap_or_default(),
                icmp_layer("Internet Control Message Protocol", transport),
                None,
            ),
            58 => (
                "ICMPv6".to_string(),
                None,
                None,
                format!("type {}", transport.first().copied().unwrap_or_default()),
                transport.get(8..).unwrap_or_default(),
                icmp_layer("Internet Control Message Protocol v6", transport),
                None,
            ),
            other => (
                format!("IP/{other}"),
                None,
                None,
                format!("IP protocol {other}"),
                transport,
                protocol_layer(
                    format!("IP Protocol {other}"),
                    format!("{} bytes", transport.len()),
                    [("Payload length", format!("{} bytes", transport.len()))],
                ),
                None,
            ),
        };
    protocol_layers.push(transport_layer);
    let application_layer =
        analyze_application_protocol(&protocol, source_port, destination_port, payload);
    let sub_protocol = application_layer.as_ref().map(application_protocol_name);
    if let Some(application_layer) = application_layer {
        protocol_layers.push(application_layer);
    }
    CapturedPacket {
        number,
        timestamp_ms,
        direction: "upload",
        ip_version,
        protocol,
        sub_protocol,
        proxy_protocol: None,
        source,
        source_port,
        destination,
        destination_port,
        length,
        summary,
        payload_length: payload.len(),
        payload_hex: payload
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" "),
        payload_text: payload
            .iter()
            .map(|byte| {
                if byte.is_ascii_graphic() || *byte == b' ' {
                    char::from(*byte)
                } else {
                    '.'
                }
            })
            .collect(),
        protocol_layers,
        tcp_sequence,
        payload_bytes: payload.to_vec(),
    }
}
