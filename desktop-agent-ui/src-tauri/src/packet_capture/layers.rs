use super::*;

pub(crate) fn protocol_layer(
    name: impl Into<String>,
    summary: impl Into<String>,
    fields: impl IntoIterator<Item = (impl Into<String>, String)>,
) -> ProtocolLayer {
    ProtocolLayer {
        name: name.into(),
        summary: summary.into(),
        fields: fields
            .into_iter()
            .map(|(name, value)| ProtocolField {
                name: name.into(),
                value,
            })
            .collect(),
    }
}

pub(crate) fn icmp_layer(name: &str, transport: &[u8]) -> ProtocolLayer {
    protocol_layer(
        name,
        format!(
            "Type {}, Code {}",
            transport.first().copied().unwrap_or_default(),
            transport.get(1).copied().unwrap_or_default()
        ),
        [
            (
                "Type",
                transport.first().copied().unwrap_or_default().to_string(),
            ),
            (
                "Code",
                transport.get(1).copied().unwrap_or_default().to_string(),
            ),
            (
                "Checksum",
                transport
                    .get(2..4)
                    .map(|bytes| format!("0x{:04x}", u16::from_be_bytes([bytes[0], bytes[1]])))
                    .unwrap_or_else(|| "Unavailable".to_string()),
            ),
            (
                "Payload length",
                format!("{} bytes", transport.len().saturating_sub(8)),
            ),
        ],
    )
}

pub(crate) fn analyze_application_protocol(
    protocol: &str,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    payload: &[u8],
) -> Option<ProtocolLayer> {
    if payload.is_empty() {
        return None;
    }
    if source_port == Some(53) || destination_port == Some(53) {
        return analyze_dns(protocol, payload);
    }
    if protocol == "UDP" && (source_port == Some(443) || destination_port == Some(443)) {
        return Some(analyze_quic(payload));
    }
    if payload.len() >= 5 && matches!(payload[0], 20..=23) && payload[1] == 3 {
        return Some(analyze_tls(payload));
    }
    if protocol == "TCP" && payload.first() == Some(&5) {
        return Some(analyze_socks5_tcp(payload));
    }
    if protocol == "UDP" {
        if let Some(header_len) = socks5_udp_header_len(payload) {
            return Some(analyze_socks5_udp(payload, header_len));
        }
    }
    let first_line = payload
        .split(|byte| *byte == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .map(str::trim);
    if let Some(line) = first_line.filter(|line| {
        line.starts_with("HTTP/")
            || [
                "GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ", "OPTIONS ", "CONNECT ",
                "TRACE ",
            ]
            .iter()
            .any(|method| line.starts_with(method))
    }) {
        return Some(analyze_http(payload, line));
    }
    None
}

pub(crate) fn analyze_socks5_tcp(payload: &[u8]) -> ProtocolLayer {
    let mut fields = vec![
        ("Version".to_string(), "5".to_string()),
        (
            "Captured length".to_string(),
            format!("{} bytes", payload.len()),
        ),
    ];
    let summary = if payload.len() >= 4
        && payload[2] == 0
        && matches!(payload[1], 1..=3)
        && matches!(payload[3], 1 | 3 | 4)
    {
        let command = match payload[1] {
            1 => "CONNECT",
            2 => "BIND",
            3 => "UDP ASSOCIATE",
            _ => "Unknown",
        };
        let address_type = socks5_address_type(payload[3]);
        fields.push(("Message type".to_string(), "Command request".to_string()));
        fields.push(("Command".to_string(), command.to_string()));
        fields.push(("Address type".to_string(), address_type.to_string()));
        format!("{command} · {address_type}")
    } else if payload.len() >= 2 && payload[1] > 0 && payload.len() >= 2 + usize::from(payload[1]) {
        let method_count = payload[1];
        fields.push((
            "Message type".to_string(),
            "Authentication method negotiation".to_string(),
        ));
        fields.push(("Method count".to_string(), method_count.to_string()));
        format!("{method_count} authentication method(s)")
    } else {
        let method_or_status = payload.get(1).copied().unwrap_or_default();
        fields.push((
            "Message type".to_string(),
            "Server response or partial message".to_string(),
        ));
        fields.push((
            "Method / status".to_string(),
            format!("0x{method_or_status:02x}"),
        ));
        "Server response or partial message".to_string()
    };
    protocol_layer("SOCKS Version 5", summary, fields)
}

pub(crate) fn socks5_udp_header_len(payload: &[u8]) -> Option<usize> {
    if payload.len() < 4 || payload[0] != 0 || payload[1] != 0 {
        return None;
    }
    match payload[3] {
        1 if payload.len() >= 10 => Some(10),
        3 if payload.len() >= 7 => {
            let host_len = usize::from(payload[4]);
            let header_len = 7 + host_len;
            (payload.len() >= header_len).then_some(header_len)
        }
        4 if payload.len() >= 22 => Some(22),
        _ => None,
    }
}

pub(crate) fn analyze_socks5_udp(payload: &[u8], header_len: usize) -> ProtocolLayer {
    let address_type = socks5_address_type(payload[3]);
    protocol_layer(
        "SOCKS Version 5 UDP Datagram",
        format!(
            "{address_type} · {} bytes",
            payload.len().saturating_sub(header_len)
        ),
        [
            (
                "Reserved",
                format!("0x{:02x}{:02x}", payload[0], payload[1]),
            ),
            ("Fragment", payload[2].to_string()),
            ("Address type", address_type.to_string()),
            ("Header length", format!("{header_len} bytes")),
            (
                "Data length",
                format!("{} bytes", payload.len().saturating_sub(header_len)),
            ),
        ],
    )
}

pub(crate) fn socks5_address_type(value: u8) -> &'static str {
    match value {
        1 => "IPv4",
        3 => "Domain",
        4 => "IPv6",
        _ => "Unknown",
    }
}
