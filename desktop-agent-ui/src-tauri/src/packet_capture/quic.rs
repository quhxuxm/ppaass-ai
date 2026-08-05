use super::*;

pub(crate) fn analyze_quic(payload: &[u8]) -> ProtocolLayer {
    let first = payload[0];
    let long_header = first & 0x80 != 0;
    let mut fields = vec![
        (
            "Header form".to_string(),
            if long_header { "Long" } else { "Short" }.to_string(),
        ),
        ("Fixed bit".to_string(), ((first & 0x40) != 0).to_string()),
        ("First byte".to_string(), format!("0x{first:02x}")),
    ];
    let summary = if long_header {
        let packet_type = match (first >> 4) & 0x03 {
            0 => "Initial",
            1 => "0-RTT",
            2 => "Handshake",
            3 => "Retry",
            _ => "Unknown",
        };
        fields.push(("Packet type".to_string(), packet_type.to_string()));
        if payload.len() >= 6 {
            fields.push((
                "Version".to_string(),
                format!(
                    "0x{:08x}",
                    u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]])
                ),
            ));
            let destination_length = usize::from(payload[5]);
            fields.push((
                "Destination Connection ID length".to_string(),
                destination_length.to_string(),
            ));
            if let Some(destination_id) = payload.get(6..6 + destination_length) {
                fields.push((
                    "Destination Connection ID".to_string(),
                    hex_bytes(destination_id),
                ));
                let source_length_offset = 6 + destination_length;
                if let Some(source_length) = payload.get(source_length_offset).copied() {
                    let source_length = usize::from(source_length);
                    fields.push((
                        "Source Connection ID length".to_string(),
                        source_length.to_string(),
                    ));
                    if let Some(source_id) = payload
                        .get(source_length_offset + 1..source_length_offset + 1 + source_length)
                    {
                        fields.push(("Source Connection ID".to_string(), hex_bytes(source_id)));
                    }
                }
            }
        }
        packet_type
    } else {
        fields.push(("Spin bit".to_string(), ((first & 0x20) != 0).to_string()));
        fields.push((
            "Protected fields".to_string(),
            "Packet number and payload require QUIC keys".to_string(),
        ));
        "Short Header"
    };
    fields.push((
        "Protected payload".to_string(),
        format!("{} bytes", payload.len()),
    ));
    protocol_layer("QUIC", summary, fields)
}

pub(crate) fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn application_protocol_name(layer: &ProtocolLayer) -> String {
    match layer.name.as_str() {
        "Domain Name System" => "DNS",
        "Transport Layer Security" => "TLS",
        "Hypertext Transfer Protocol" => "HTTP",
        "SOCKS Version 5" | "SOCKS Version 5 UDP Datagram" => "SOCKS5",
        name => name,
    }
    .to_string()
}

pub(crate) fn tcp_flags(flags: u8) -> String {
    let mut names = Vec::new();
    for (mask, name) in [
        (0x01, "FIN"),
        (0x02, "SYN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x10, "ACK"),
        (0x20, "URG"),
        (0x40, "ECE"),
        (0x80, "CWR"),
    ] {
        if flags & mask != 0 {
            names.push(name);
        }
    }
    if names.is_empty() {
        "NONE".to_string()
    } else {
        names.join(", ")
    }
}

pub(crate) fn endpoint(address: &str, port: Option<u16>) -> String {
    match port {
        Some(port) => format!("{address}:{port}"),
        None => address.to_string(),
    }
}
