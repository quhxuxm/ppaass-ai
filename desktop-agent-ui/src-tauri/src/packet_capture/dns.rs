use super::*;

pub(crate) fn analyze_dns(protocol: &str, payload: &[u8]) -> Option<ProtocolLayer> {
    let dns_payload = if protocol == "TCP" {
        payload.get(2..)?
    } else {
        payload
    };
    if dns_payload.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([dns_payload[2], dns_payload[3]]);
    let question_count = u16::from_be_bytes([dns_payload[4], dns_payload[5]]) as usize;
    let answer_count = u16::from_be_bytes([dns_payload[6], dns_payload[7]]) as usize;
    let mut fields = vec![
        (
            "Transport".to_string(),
            if protocol == "TCP" { "TCP" } else { "UDP" }.to_string(),
        ),
        (
            "Transaction ID".to_string(),
            format!(
                "0x{:04x}",
                u16::from_be_bytes([dns_payload[0], dns_payload[1]])
            ),
        ),
        ("Flags".to_string(), format!("0x{flags:04x}")),
        (
            "Message type".to_string(),
            if flags & 0x8000 == 0 {
                "Query"
            } else {
                "Response"
            }
            .to_string(),
        ),
        ("Opcode".to_string(), ((flags >> 11) & 0x0f).to_string()),
        (
            "Authoritative answer".to_string(),
            ((flags & 0x0400) != 0).to_string(),
        ),
        ("Truncated".to_string(), ((flags & 0x0200) != 0).to_string()),
        (
            "Recursion desired".to_string(),
            ((flags & 0x0100) != 0).to_string(),
        ),
        (
            "Recursion available".to_string(),
            ((flags & 0x0080) != 0).to_string(),
        ),
        ("Response code".to_string(), (flags & 0x000f).to_string()),
        ("Questions".to_string(), question_count.to_string()),
        ("Answer RRs".to_string(), answer_count.to_string()),
        (
            "Authority RRs".to_string(),
            u16::from_be_bytes([dns_payload[8], dns_payload[9]]).to_string(),
        ),
        (
            "Additional RRs".to_string(),
            u16::from_be_bytes([dns_payload[10], dns_payload[11]]).to_string(),
        ),
    ];
    let mut offset = 12usize;
    for question_index in 0..question_count.min(16) {
        let (name, next_offset) = decode_dns_name(dns_payload, offset, 0)?;
        if next_offset + 4 > dns_payload.len() {
            break;
        }
        let record_type =
            u16::from_be_bytes([dns_payload[next_offset], dns_payload[next_offset + 1]]);
        let class =
            u16::from_be_bytes([dns_payload[next_offset + 2], dns_payload[next_offset + 3]]);
        fields.push((format!("Query {} name", question_index + 1), name));
        fields.push((
            format!("Query {} type", question_index + 1),
            format!("{record_type} ({})", dns_record_type(record_type)),
        ));
        fields.push((
            format!("Query {} class", question_index + 1),
            class.to_string(),
        ));
        offset = next_offset + 4;
    }
    for answer_index in 0..answer_count.min(32) {
        let Some((name, next_offset)) = decode_dns_name(dns_payload, offset, 0) else {
            break;
        };
        if next_offset + 10 > dns_payload.len() {
            break;
        }
        let record_type =
            u16::from_be_bytes([dns_payload[next_offset], dns_payload[next_offset + 1]]);
        let class =
            u16::from_be_bytes([dns_payload[next_offset + 2], dns_payload[next_offset + 3]]);
        let ttl = u32::from_be_bytes([
            dns_payload[next_offset + 4],
            dns_payload[next_offset + 5],
            dns_payload[next_offset + 6],
            dns_payload[next_offset + 7],
        ]);
        let data_length =
            u16::from_be_bytes([dns_payload[next_offset + 8], dns_payload[next_offset + 9]])
                as usize;
        let data_offset = next_offset + 10;
        let Some(data) = dns_payload.get(data_offset..data_offset + data_length) else {
            break;
        };
        fields.push((format!("Answer {} name", answer_index + 1), name));
        fields.push((
            format!("Answer {} type", answer_index + 1),
            format!("{record_type} ({})", dns_record_type(record_type)),
        ));
        fields.push((
            format!("Answer {} class", answer_index + 1),
            class.to_string(),
        ));
        fields.push((
            format!("Answer {} TTL", answer_index + 1),
            format!("{ttl} s"),
        ));
        fields.push((
            format!("Answer {} data", answer_index + 1),
            dns_record_data(dns_payload, data_offset, record_type, data),
        ));
        offset = data_offset + data_length;
    }
    Some(protocol_layer(
        "Domain Name System",
        if flags & 0x8000 == 0 {
            "Query"
        } else {
            "Response"
        },
        fields,
    ))
}

pub(crate) fn decode_dns_name(data: &[u8], start: usize, depth: usize) -> Option<(String, usize)> {
    if depth > 8 || start >= data.len() {
        return None;
    }
    let mut labels = Vec::new();
    let mut offset = start;
    loop {
        let length = *data.get(offset)?;
        if length == 0 {
            return Some((
                if labels.is_empty() {
                    ".".to_string()
                } else {
                    labels.join(".")
                },
                offset + 1,
            ));
        }
        if length & 0xc0 == 0xc0 {
            let low = *data.get(offset + 1)?;
            let pointer = (usize::from(length & 0x3f) << 8) | usize::from(low);
            let (suffix, _) = decode_dns_name(data, pointer, depth + 1)?;
            labels.push(suffix);
            return Some((labels.join("."), offset + 2));
        }
        let label_length = usize::from(length);
        if label_length > 63 {
            return None;
        }
        let label = data.get(offset + 1..offset + 1 + label_length)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        offset += label_length + 1;
    }
}

pub(crate) fn dns_record_type(record_type: u16) -> &'static str {
    match record_type {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        41 => "OPT",
        65 => "HTTPS",
        _ => "Unknown",
    }
}

pub(crate) fn dns_record_data(
    packet: &[u8],
    offset: usize,
    record_type: u16,
    data: &[u8],
) -> String {
    match (record_type, data.len()) {
        (1, 4) => Ipv4Addr::new(data[0], data[1], data[2], data[3]).to_string(),
        (28, 16) => <[u8; 16]>::try_from(data)
            .map(Ipv6Addr::from)
            .map(|address| address.to_string())
            .unwrap_or_else(|_| hex_bytes(data)),
        (2 | 5 | 12, _) => decode_dns_name(packet, offset, 0)
            .map(|(name, _)| name)
            .unwrap_or_else(|| hex_bytes(data)),
        _ => hex_bytes(data),
    }
}
