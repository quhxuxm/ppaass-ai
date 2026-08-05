use super::*;

pub(crate) fn analyze_http(payload: &[u8], first_line: &str) -> ProtocolLayer {
    let mut fields = vec![("Start line".to_string(), first_line.to_string())];
    let parts: Vec<_> = first_line.split_whitespace().collect();
    if first_line.starts_with("HTTP/") {
        if let Some(version) = parts.first() {
            fields.push(("Version".to_string(), (*version).to_string()));
        }
        if let Some(status) = parts.get(1) {
            fields.push(("Status code".to_string(), (*status).to_string()));
        }
        if parts.len() > 2 {
            fields.push(("Reason phrase".to_string(), parts[2..].join(" ")));
        }
    } else {
        if let Some(method) = parts.first() {
            fields.push(("Method".to_string(), (*method).to_string()));
        }
        if let Some(uri) = parts.get(1) {
            fields.push(("Request URI".to_string(), (*uri).to_string()));
        }
        if let Some(version) = parts.get(2) {
            fields.push(("Version".to_string(), (*version).to_string()));
        }
    }
    let header_end = payload
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .or_else(|| {
            payload
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|position| position + 2)
        });
    if let Ok(headers) = std::str::from_utf8(&payload[..header_end.unwrap_or(payload.len())]) {
        for line in headers.lines().skip(1).take(100) {
            if let Some((name, value)) = line.trim_end_matches('\r').split_once(':') {
                fields.push((format!("Header: {}", name.trim()), value.trim().to_string()));
            }
        }
    }
    fields.push((
        "Header length".to_string(),
        format!("{} bytes", header_end.unwrap_or(payload.len())),
    ));
    fields.push((
        "Body length".to_string(),
        format!(
            "{} bytes",
            header_end
                .map(|offset| payload.len().saturating_sub(offset))
                .unwrap_or_default()
        ),
    ));
    protocol_layer("Hypertext Transfer Protocol", first_line, fields)
}

pub(crate) fn analyze_tls(payload: &[u8]) -> ProtocolLayer {
    let content_type = match payload[0] {
        20 => "Change Cipher Spec",
        21 => "Alert",
        22 => "Handshake",
        23 => "Application Data",
        _ => "Unknown",
    };
    let record_length = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    let available_record_bytes = payload.len().saturating_sub(5).min(record_length);
    let mut fields = vec![
        (
            "Content type".to_string(),
            format!("{} ({content_type})", payload[0]),
        ),
        (
            "Legacy record version".to_string(),
            tls_version(payload[1], payload[2]),
        ),
        (
            "Record length".to_string(),
            format!("{record_length} bytes"),
        ),
        (
            "Captured record bytes".to_string(),
            format!("{available_record_bytes} of {record_length} bytes"),
        ),
    ];
    let following_bytes = payload.len().saturating_sub(5 + record_length);
    if following_bytes > 0 {
        fields.push((
            "Following TLS data".to_string(),
            format!("{following_bytes} bytes after this record"),
        ));
    }
    if payload[0] == 22 && payload.len() >= 9 {
        let handshake_type = payload[5];
        let handshake_length = (usize::from(payload[6]) << 16)
            | (usize::from(payload[7]) << 8)
            | usize::from(payload[8]);
        fields.push((
            "Handshake type".to_string(),
            format!("{handshake_type} ({})", tls_handshake_type(handshake_type)),
        ));
        fields.push((
            "Handshake length".to_string(),
            format!("{handshake_length} bytes"),
        ));
        if handshake_type == 1 {
            analyze_tls_client_hello(payload, &mut fields);
        } else if handshake_type == 2 {
            analyze_tls_server_hello(payload, &mut fields);
        }
    } else if payload[0] == 23 {
        fields.push((
            "Payload state".to_string(),
            "Encrypted application data; TLS session keys are required for inner fields"
                .to_string(),
        ));
    }
    protocol_layer("Transport Layer Security", content_type, fields)
}

pub(crate) fn analyze_tls_client_hello(payload: &[u8], fields: &mut Vec<(String, String)>) {
    if payload.len() < 44 {
        return;
    }
    fields.push((
        "Client version".to_string(),
        tls_version(payload[9], payload[10]),
    ));
    fields.push(("Random".to_string(), hex_bytes(&payload[11..43])));
    let session_id_length = usize::from(payload[43]);
    fields.push((
        "Session ID length".to_string(),
        session_id_length.to_string(),
    ));
    let mut offset = 44 + session_id_length;
    let Some(cipher_length_bytes) = payload.get(offset..offset + 2) else {
        return;
    };
    let cipher_length =
        u16::from_be_bytes([cipher_length_bytes[0], cipher_length_bytes[1]]) as usize;
    offset += 2;
    let Some(cipher_bytes) = payload.get(offset..offset + cipher_length) else {
        return;
    };
    fields.push((
        "Cipher suites".to_string(),
        cipher_bytes
            .chunks_exact(2)
            .map(|suite| format!("0x{:04x}", u16::from_be_bytes([suite[0], suite[1]])))
            .collect::<Vec<_>>()
            .join(", "),
    ));
    offset += cipher_length;
    let Some(compression_length) = payload.get(offset).copied() else {
        return;
    };
    offset += 1 + usize::from(compression_length);
    analyze_tls_extensions(payload, offset, fields);
}

pub(crate) fn analyze_tls_server_hello(payload: &[u8], fields: &mut Vec<(String, String)>) {
    if payload.len() < 44 {
        return;
    }
    fields.push((
        "Server version".to_string(),
        tls_version(payload[9], payload[10]),
    ));
    fields.push(("Random".to_string(), hex_bytes(&payload[11..43])));
    let session_id_length = usize::from(payload[43]);
    fields.push((
        "Session ID length".to_string(),
        session_id_length.to_string(),
    ));
    let offset = 44 + session_id_length;
    if let Some(bytes) = payload.get(offset..offset + 2) {
        fields.push((
            "Cipher suite".to_string(),
            format!("0x{:04x}", u16::from_be_bytes([bytes[0], bytes[1]])),
        ));
    }
    if let Some(compression) = payload.get(offset + 2) {
        fields.push(("Compression method".to_string(), compression.to_string()));
    }
    analyze_tls_extensions(payload, offset + 3, fields);
}

pub(crate) fn analyze_tls_extensions(
    payload: &[u8],
    offset: usize,
    fields: &mut Vec<(String, String)>,
) {
    let Some(length_bytes) = payload.get(offset..offset + 2) else {
        return;
    };
    let extensions_length = u16::from_be_bytes([length_bytes[0], length_bytes[1]]) as usize;
    fields.push((
        "Extensions length".to_string(),
        format!("{extensions_length} bytes"),
    ));
    let mut cursor = offset + 2;
    let end = cursor.saturating_add(extensions_length).min(payload.len());
    let mut extension_names = Vec::new();
    while cursor + 4 <= end {
        let extension_type = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]);
        let extension_length =
            u16::from_be_bytes([payload[cursor + 2], payload[cursor + 3]]) as usize;
        cursor += 4;
        let Some(data) = payload.get(cursor..cursor + extension_length) else {
            break;
        };
        extension_names.push(format!(
            "{} ({extension_type})",
            tls_extension_name(extension_type)
        ));
        if extension_type == 0 && data.len() >= 5 {
            let name_length = u16::from_be_bytes([data[3], data[4]]) as usize;
            if let Some(name) = data.get(5..5 + name_length) {
                fields.push((
                    "Server Name (SNI)".to_string(),
                    String::from_utf8_lossy(name).into_owned(),
                ));
            }
        } else if extension_type == 16 && data.len() >= 3 {
            let name_length = usize::from(data[2]);
            if let Some(name) = data.get(3..3 + name_length) {
                fields.push((
                    "Application protocol (ALPN)".to_string(),
                    String::from_utf8_lossy(name).into_owned(),
                ));
            }
        } else if extension_type == 43 && data.len() >= 2 {
            let version = if data.len() == 2 {
                tls_version(data[0], data[1])
            } else if data.len() >= 3 {
                tls_version(data[1], data[2])
            } else {
                "Unknown".to_string()
            };
            fields.push(("Supported/selected version".to_string(), version));
        }
        cursor += extension_length;
    }
    if !extension_names.is_empty() {
        fields.push(("Extensions".to_string(), extension_names.join(", ")));
    }
}

pub(crate) fn tls_version(major: u8, minor: u8) -> String {
    let name = match (major, minor) {
        (3, 0) => "SSL 3.0",
        (3, 1) => "TLS 1.0",
        (3, 2) => "TLS 1.1",
        (3, 3) => "TLS 1.2 / TLS 1.3 legacy",
        (3, 4) => "TLS 1.3",
        _ => "Unknown",
    };
    format!("{major}.{minor} ({name})")
}

pub(crate) fn tls_handshake_type(value: u8) -> &'static str {
    match value {
        1 => "Client Hello",
        2 => "Server Hello",
        4 => "New Session Ticket",
        8 => "Encrypted Extensions",
        11 => "Certificate",
        13 => "Certificate Request",
        15 => "Certificate Verify",
        20 => "Finished",
        _ => "Unknown",
    }
}

pub(crate) fn tls_extension_name(value: u16) -> &'static str {
    match value {
        0 => "server_name",
        5 => "status_request",
        10 => "supported_groups",
        11 => "ec_point_formats",
        13 => "signature_algorithms",
        16 => "application_layer_protocol_negotiation",
        18 => "signed_certificate_timestamp",
        23 => "extended_master_secret",
        27 => "compress_certificate",
        35 => "session_ticket",
        43 => "supported_versions",
        45 => "psk_key_exchange_modes",
        51 => "key_share",
        _ => "unknown",
    }
}
