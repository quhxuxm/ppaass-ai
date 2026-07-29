use super::*;

pub(super) fn parse_ip_packet(
    number: usize,
    timestamp_ms: u64,
    length: usize,
    packet: &[u8],
) -> Option<CapturedPacket> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => {
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            build_packet(
                number,
                timestamp_ms,
                4,
                packet[9],
                (
                    Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]).to_string(),
                    Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]).to_string(),
                ),
                length,
                packet.get(header_len..)?,
            )
        }
        6 if packet.len() >= 40 => build_packet(
            number,
            timestamp_ms,
            6,
            packet[6],
            (
                Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?).to_string(),
                Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?).to_string(),
            ),
            length,
            &packet[40..],
        ),
        _ => None,
    }
}

pub(super) fn build_packet(
    number: usize,
    timestamp_ms: u64,
    ip_version: u8,
    protocol_number: u8,
    addresses: (String, String),
    length: usize,
    transport: &[u8],
) -> Option<CapturedPacket> {
    let (source, destination) = addresses;
    let (
        protocol,
        source_port,
        destination_port,
        summary,
        payload,
        tcp_sequence,
        tcp_flags,
        mut transport_fields,
        proxy_marker,
    ) = match protocol_number {
        6 if transport.len() >= 20 => {
            let source_port = u16::from_be_bytes([transport[0], transport[1]]);
            let destination_port = u16::from_be_bytes([transport[2], transport[3]]);
            let header_len = usize::from(transport[12] >> 4) * 4;
            if !(TCP_HEADER_LEN..=transport.len()).contains(&header_len) {
                return None;
            }
            let flags = tcp_flags(transport[13]);
            let payload = &transport[header_len..];
            let proxy_marker =
                parse_proxy_capture_tcp_option(&transport[TCP_HEADER_LEN..header_len]);
            (
                "TCP".to_string(),
                Some(source_port),
                Some(destination_port),
                format!("{source_port} → {destination_port} [{flags}]"),
                payload,
                Some(u32::from_be_bytes(transport[4..8].try_into().unwrap())),
                Some(transport[13]),
                vec![
                    field("Source port", source_port),
                    field("Destination port", destination_port),
                    field(
                        "Sequence number",
                        u32::from_be_bytes(transport[4..8].try_into().unwrap()),
                    ),
                    field(
                        "Acknowledgment number",
                        u32::from_be_bytes(transport[8..12].try_into().unwrap()),
                    ),
                    field("Header length", format!("{header_len} bytes")),
                    field("Flags", format!("0x{:02x} ({flags})", transport[13])),
                    field(
                        "Window size",
                        u16::from_be_bytes([transport[14], transport[15]]),
                    ),
                    field("Payload length", format!("{} bytes", payload.len())),
                ],
                proxy_marker,
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
                None,
                None,
                vec![
                    field("Source port", source_port),
                    field("Destination port", destination_port),
                    field("Length", u16::from_be_bytes([transport[4], transport[5]])),
                    field("Payload length", format!("{} bytes", payload.len())),
                ],
                None,
            )
        }
        1 => (
            "ICMP".to_string(),
            None,
            None,
            format!("type {}", transport.first().copied().unwrap_or_default()),
            transport.get(8..).unwrap_or_default(),
            None,
            None,
            vec![
                field("Type", transport.first().copied().unwrap_or_default()),
                field("Code", transport.get(1).copied().unwrap_or_default()),
            ],
            None,
        ),
        58 => (
            "ICMPv6".to_string(),
            None,
            None,
            format!("type {}", transport.first().copied().unwrap_or_default()),
            transport.get(8..).unwrap_or_default(),
            None,
            None,
            vec![
                field("Type", transport.first().copied().unwrap_or_default()),
                field("Code", transport.get(1).copied().unwrap_or_default()),
            ],
            None,
        ),
        other => (
            format!("IP/{other}"),
            None,
            None,
            format!("IP protocol {other}"),
            transport,
            None,
            None,
            vec![field("Protocol number", other)],
            None,
        ),
    };
    if let Some(marker) = proxy_marker {
        transport_fields.push(field(
            "Explicit proxy ingress",
            marker.protocol.report_name(),
        ));
        transport_fields.push(field(
            "Explicit proxy direction",
            marker.direction.report_name(),
        ));
    }
    let payload_length = payload.len();
    let analysis_payload_length = payload_length.min(MAX_PACKET_ANALYSIS_BYTES);
    let analysis_payload = &payload[..analysis_payload_length];
    let analysis_payload_truncated = analysis_payload_length < payload_length;
    if analysis_payload_truncated {
        transport_fields.push(field(
            "Analyzed payload prefix",
            format!("{analysis_payload_length} of {payload_length} bytes"),
        ));
    }
    let application =
        analyze_application(&protocol, source_port, destination_port, analysis_payload);
    let sub_protocol = application
        .as_ref()
        .map(|layer| short_protocol(&layer.name));
    let transport_name = match protocol.as_str() {
        "TCP" => "Transmission Control Protocol",
        "UDP" => "User Datagram Protocol",
        value => value,
    };
    let mut protocol_layers = vec![
        layer(
            "Frame",
            format!("{length} bytes on DLT_RAW"),
            vec![
                field("Packet number", number),
                field("Frame length", format!("{length} bytes")),
            ],
        ),
        layer(
            format!("Internet Protocol Version {ip_version}"),
            format!("{source} → {destination}"),
            vec![
                field("Version", ip_version),
                field("Source address", source.clone()),
                field("Destination address", destination.clone()),
                field("Protocol number", protocol_number),
            ],
        ),
        layer(transport_name, summary.clone(), transport_fields),
    ];
    if let Some(application) = application {
        protocol_layers.push(application);
    }
    Some(CapturedPacket {
        number,
        timestamp_ms,
        direction: proxy_marker
            .map(|marker| marker.direction.report_name())
            .unwrap_or("upload"),
        ip_version,
        protocol,
        sub_protocol,
        proxy_protocol: proxy_marker.map(|marker| marker.protocol.report_name().to_string()),
        source,
        source_port,
        destination,
        destination_port,
        length,
        summary,
        payload_length,
        payload_preview_length: 0,
        payload_truncated: false,
        payload_hex: String::new(),
        payload_text: String::new(),
        protocol_layers,
        tcp_sequence,
        tcp_flags,
        payload: analysis_payload.to_vec(),
        analysis_payload_truncated,
        proxy_marker,
        legacy_proxy_session: None,
        direction_tracked: false,
    })
}

pub(super) fn parse_proxy_capture_tcp_option(options: &[u8]) -> Option<ProxyPacketMarker> {
    let mut offset = 0usize;
    while offset < options.len() {
        match options[offset] {
            0 => break,
            1 => offset += 1,
            kind => {
                let option_len = usize::from(*options.get(offset + 1)?);
                if option_len < 2 || offset + option_len > options.len() {
                    break;
                }
                let option = &options[offset..offset + option_len];
                if kind == PROXY_CAPTURE_TCP_OPTION_KIND
                    && option_len == PROXY_CAPTURE_TCP_OPTION_LEN
                    && option[2..6] == PROXY_CAPTURE_TCP_OPTION_EXPERIMENT_ID
                {
                    return Some(ProxyPacketMarker {
                        protocol: ProxyIngressProtocol::from_marker(option[6])?,
                        direction: ProxyPacketDirection::from_marker(option[7])?,
                    });
                }
                offset += option_len;
            }
        }
    }
    None
}
