use super::*;

pub(super) fn analyze_application(
    protocol: &str,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    payload: &[u8],
) -> Option<ProtocolLayer> {
    if payload.is_empty() {
        return None;
    }
    if source_port == Some(53) || destination_port == Some(53) {
        let bytes = if protocol == "TCP" {
            payload.get(2..)?
        } else {
            payload
        };
        if bytes.len() < 12 {
            return None;
        }
        let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
        let mut fields = vec![
            field(
                "Transaction ID",
                format!("0x{:04x}", u16::from_be_bytes([bytes[0], bytes[1]])),
            ),
            field("Flags", format!("0x{flags:04x}")),
            field(
                "Message type",
                if flags & 0x8000 == 0 {
                    "Query"
                } else {
                    "Response"
                },
            ),
            field("Questions", u16::from_be_bytes([bytes[4], bytes[5]])),
            field("Answer RRs", u16::from_be_bytes([bytes[6], bytes[7]])),
            field("Authority RRs", u16::from_be_bytes([bytes[8], bytes[9]])),
            field("Additional RRs", u16::from_be_bytes([bytes[10], bytes[11]])),
        ];
        if let Some((name, offset)) = dns_name(bytes, 12, 0)
            && offset + 4 <= bytes.len()
        {
            fields.push(field("Query name", name));
            fields.push(field(
                "Query type",
                u16::from_be_bytes([bytes[offset], bytes[offset + 1]]),
            ));
            fields.push(field(
                "Query class",
                u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]),
            ));
        }
        return Some(layer(
            "Domain Name System",
            if flags & 0x8000 == 0 {
                "Query"
            } else {
                "Response"
            },
            fields,
        ));
    }
    if protocol == "UDP" && (source_port == Some(443) || destination_port == Some(443)) {
        let first = payload[0];
        let long = first & 0x80 != 0;
        let mut fields = vec![
            field("Header form", if long { "Long" } else { "Short" }),
            field("Fixed bit", first & 0x40 != 0),
            field("First byte", format!("0x{first:02x}")),
        ];
        if long && payload.len() >= 6 {
            fields.push(field(
                "Packet type",
                match (first >> 4) & 3 {
                    0 => "Initial",
                    1 => "0-RTT",
                    2 => "Handshake",
                    _ => "Retry",
                },
            ));
            fields.push(field(
                "Version",
                format!(
                    "0x{:08x}",
                    u32::from_be_bytes(payload[1..5].try_into().unwrap())
                ),
            ));
            let dcid_len = usize::from(payload[5]);
            fields.push(field("DCID length", dcid_len));
            if let Some(dcid) = payload.get(6..6 + dcid_len) {
                fields.push(field("DCID", hex(dcid)));
            }
        } else if !long {
            fields.push(field(
                "Protected fields",
                "Packet number and payload require QUIC keys",
            ));
        }
        return Some(layer(
            "QUIC",
            if long { "Long Header" } else { "Short Header" },
            fields,
        ));
    }
    if payload.len() >= 5 && matches!(payload[0], 20..=23) && payload[1] == 3 {
        let content = match payload[0] {
            20 => "Change Cipher Spec",
            21 => "Alert",
            22 => "Handshake",
            23 => "Application Data",
            _ => "Unknown",
        };
        let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
        let mut fields = vec![
            field("Content type", format!("{} ({content})", payload[0])),
            field("Legacy version", format!("{}.{}", payload[1], payload[2])),
            field("Record length", format!("{record_len} bytes")),
            field(
                "Captured record bytes",
                format!(
                    "{} of {record_len} bytes",
                    payload.len().saturating_sub(5).min(record_len)
                ),
            ),
        ];
        if payload[0] == 22 && payload.len() >= 9 {
            fields.push(field("Handshake type", payload[5]));
            fields.push(field(
                "Handshake length",
                (usize::from(payload[6]) << 16)
                    | (usize::from(payload[7]) << 8)
                    | usize::from(payload[8]),
            ));
        } else if payload[0] == 23 {
            fields.push(field(
                "Payload state",
                "Encrypted; TLS session keys are required",
            ));
        }
        return Some(layer("Transport Layer Security", content, fields));
    }
    if protocol == "TCP" && payload.first() == Some(&5) {
        return Some(analyze_socks5_tcp(payload));
    }
    analyze_http(payload)
}

pub(super) fn analyze_http(payload: &[u8]) -> Option<ProtocolLayer> {
    let first_line_end = payload
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(payload.len());
    let first_line_bytes = payload[..first_line_end]
        .strip_suffix(b"\r")
        .unwrap_or(&payload[..first_line_end]);
    let is_response = first_line_bytes.starts_with(b"HTTP/");
    let is_request = [
        b"GET ".as_slice(),
        b"POST ".as_slice(),
        b"PUT ".as_slice(),
        b"PATCH ".as_slice(),
        b"DELETE ".as_slice(),
        b"HEAD ".as_slice(),
        b"OPTIONS ".as_slice(),
        b"CONNECT ".as_slice(),
        b"TRACE ".as_slice(),
    ]
    .iter()
    .any(|method| first_line_bytes.starts_with(method));
    if !is_response && !is_request {
        return None;
    }

    let first_line = bounded_lossy(first_line_bytes, MAX_HTTP_START_LINE_BYTES);
    let mut fields = vec![field("Start line", &first_line)];
    let parts: Vec<_> = first_line.split_whitespace().collect();
    if is_response {
        if let Some(value) = parts.first() {
            fields.push(field("Version", *value));
        }
        if let Some(value) = parts.get(1) {
            fields.push(field("Status code", *value));
        }
    } else {
        if let Some(value) = parts.first() {
            fields.push(field("Method", *value));
        }
        if let Some(value) = parts.get(1) {
            fields.push(field("Request URI", *value));
        }
        if let Some(value) = parts.get(2) {
            fields.push(field("Version", *value));
        }
    }

    for line in payload
        .split(|byte| *byte == b'\n')
        .skip(1)
        .take(MAX_HTTP_HEADER_FIELDS)
    {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        if let Some(colon) = line.iter().position(|byte| *byte == b':') {
            let name = bounded_lossy(&line[..colon], MAX_HTTP_HEADER_NAME_BYTES);
            let value = bounded_lossy(&line[colon + 1..], MAX_HTTP_HEADER_VALUE_BYTES);
            fields.push(field(
                format!("Header: {}", name.trim()),
                value.trim().to_string(),
            ));
        }
    }
    Some(layer("Hypertext Transfer Protocol", &first_line, fields))
}

pub(super) fn bounded_lossy(bytes: &[u8], maximum_bytes: usize) -> String {
    let was_truncated = bytes.len() > maximum_bytes;
    let mut value = String::from_utf8_lossy(&bytes[..bytes.len().min(maximum_bytes)]).into_owned();
    if was_truncated {
        value.push('…');
    }
    value
}

pub(super) fn analyze_socks5_tcp(payload: &[u8]) -> ProtocolLayer {
    let mut fields = vec![
        field("Version", 5),
        field("Captured length", format!("{} bytes", payload.len())),
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
        fields.push(field("Message type", "Command request"));
        fields.push(field("Command", command));
        fields.push(field("Address type", address_type));
        format!("{command} · {address_type}")
    } else if payload.len() >= 2 && payload[1] > 0 && payload.len() >= 2 + usize::from(payload[1]) {
        let method_count = payload[1];
        fields.push(field("Message type", "Authentication method negotiation"));
        fields.push(field("Method count", method_count));
        format!("{method_count} authentication method(s)")
    } else {
        let method_or_status = payload.get(1).copied().unwrap_or_default();
        fields.push(field("Message type", "Server response or partial message"));
        fields.push(field(
            "Method / status",
            format!("0x{method_or_status:02x}"),
        ));
        "Server response or partial message".to_string()
    };
    layer("SOCKS Version 5", summary, fields)
}

pub(super) fn socks5_address_type(value: u8) -> &'static str {
    match value {
        1 => "IPv4",
        3 => "Domain",
        4 => "IPv6",
        _ => "Unknown",
    }
}
