use super::*;

pub(super) fn dns_name(data: &[u8], start: usize, depth: usize) -> Option<(String, usize)> {
    if depth > 8 {
        return None;
    }
    let mut labels = Vec::new();
    let mut offset = start;
    loop {
        let len = *data.get(offset)?;
        if len == 0 {
            return Some((
                if labels.is_empty() {
                    ".".to_string()
                } else {
                    labels.join(".")
                },
                offset + 1,
            ));
        }
        if len & 0xc0 == 0xc0 {
            let pointer = (usize::from(len & 0x3f) << 8) | usize::from(*data.get(offset + 1)?);
            labels.push(dns_name(data, pointer, depth + 1)?.0);
            return Some((labels.join("."), offset + 2));
        }
        let label = data.get(offset + 1..offset + 1 + usize::from(len))?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        offset += usize::from(len) + 1;
    }
}

pub(super) fn field(name: impl Into<String>, value: impl ToString) -> ProtocolField {
    ProtocolField {
        name: name.into(),
        value: value.to_string(),
    }
}

pub(super) fn layer(
    name: impl Into<String>,
    summary: impl Into<String>,
    fields: Vec<ProtocolField>,
) -> ProtocolLayer {
    ProtocolLayer {
        name: name.into(),
        summary: summary.into(),
        fields,
    }
}

pub(super) fn short_protocol(name: &str) -> String {
    match name {
        "Domain Name System" => "DNS",
        "Transport Layer Security" => "TLS",
        "Hypertext Transfer Protocol" => "HTTP",
        "SOCKS Version 5" => "SOCKS5",
        value => value,
    }
    .to_string()
}

pub(super) fn finalize_payload_preview(packet: &mut CapturedPacket) {
    let preview_length = packet.payload.len().min(MAX_PACKET_PAYLOAD_PREVIEW_BYTES);
    let preview = &packet.payload[..preview_length];
    packet.payload_preview_length = preview_length;
    packet.payload_truncated = preview_length < packet.payload_length;
    packet.payload_hex = hex(preview);
    packet.payload_text = ascii(preview);
    packet.payload.clear();
    packet.payload.shrink_to_fit();
}

pub(super) fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let mut output = String::with_capacity(bytes.len().saturating_mul(3).saturating_sub(1));
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            output.push(' ');
        }
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

pub(super) fn ascii(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len());
    for byte in bytes {
        output.push(if byte.is_ascii_graphic() || *byte == b' ' {
            char::from(*byte)
        } else {
            '.'
        });
    }
    output
}

pub(super) fn tcp_flags(flags: u8) -> String {
    let mut names = Vec::new();
    for (mask, name) in [
        (1, "FIN"),
        (2, "SYN"),
        (4, "RST"),
        (8, "PSH"),
        (16, "ACK"),
        (32, "URG"),
        (64, "ECE"),
        (128, "CWR"),
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

pub(super) fn endpoint(address: &str, port: Option<u16>) -> String {
    port.map(|port| format!("{address}:{port}"))
        .unwrap_or_else(|| address.to_string())
}
