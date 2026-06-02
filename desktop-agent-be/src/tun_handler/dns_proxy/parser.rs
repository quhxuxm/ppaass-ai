use super::*;

pub(super) fn parse_dns_query(packet: &[u8]) -> Option<(String, String)> {
    if packet.len() < 12 || read_u16(packet, 4)? == 0 {
        return None;
    }

    let mut offset = 12;
    let query = parse_dns_name(packet, &mut offset)?;
    let record_type = dns_type_name(read_u16(packet, offset)?).to_string();
    Some((query, record_type))
}

pub(super) fn parse_dns_response(packet: &[u8]) -> Option<DnsResponseSummary> {
    if packet.len() < 12 {
        return None;
    }

    let flags = read_u16(packet, 2)?;
    let qdcount = read_u16(packet, 4)?;
    let ancount = read_u16(packet, 6)?;
    let mut offset = 12;

    for _ in 0..qdcount {
        parse_dns_name(packet, &mut offset)?;
        offset = offset.checked_add(4)?;
        if offset > packet.len() {
            return None;
        }
    }

    let mut answers = Vec::new();
    for _ in 0..ancount {
        parse_dns_name(packet, &mut offset)?;
        let record_type = read_u16(packet, offset)?;
        offset = offset.checked_add(2)?;
        let _class = read_u16(packet, offset)?;
        offset = offset.checked_add(2)?;
        let _ttl = read_u32(packet, offset)?;
        offset = offset.checked_add(4)?;
        let rdlength = read_u16(packet, offset)? as usize;
        offset = offset.checked_add(2)?;
        let rdata_offset = offset;
        let rdata_end = offset.checked_add(rdlength)?;
        if rdata_end > packet.len() {
            return None;
        }

        if let Some(answer) = parse_dns_answer_rdata(packet, rdata_offset, rdlength, record_type) {
            answers.push(answer);
        }
        offset = rdata_end;
    }

    Some(DnsResponseSummary {
        status: dns_rcode_name(flags & 0x000f).to_string(),
        answers,
    })
}

fn parse_dns_answer_rdata(
    packet: &[u8],
    rdata_offset: usize,
    rdlength: usize,
    record_type: u16,
) -> Option<String> {
    let rdata = packet.get(rdata_offset..rdata_offset.checked_add(rdlength)?)?;
    match record_type {
        1 if rdata.len() == 4 => {
            Some(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string())
        }
        2 | 5 | 12 => {
            let mut offset = rdata_offset;
            parse_dns_name(packet, &mut offset)
        }
        15 if rdata.len() >= 3 => {
            let preference = u16::from_be_bytes([rdata[0], rdata[1]]);
            let mut offset = rdata_offset + 2;
            parse_dns_name(packet, &mut offset).map(|exchange| format!("{preference} {exchange}"))
        }
        16 => Some(parse_txt_rdata(rdata)),
        28 if rdata.len() == 16 => {
            let bytes: [u8; 16] = rdata.try_into().ok()?;
            Some(Ipv6Addr::from(bytes).to_string())
        }
        33 if rdata.len() >= 7 => {
            let port = u16::from_be_bytes([rdata[4], rdata[5]]);
            let mut offset = rdata_offset + 6;
            parse_dns_name(packet, &mut offset).map(|target| format!("{target}:{port}"))
        }
        64 | 65 if rdata.len() >= 3 => {
            let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
            let mut offset = rdata_offset + 2;
            parse_dns_name(packet, &mut offset).map(|target| {
                if target == "." {
                    format!("priority {priority}")
                } else {
                    format!("priority {priority} {target}")
                }
            })
        }
        _ => None,
    }
}

fn parse_txt_rdata(rdata: &[u8]) -> String {
    let mut cursor = 0;
    let mut values = Vec::new();
    while cursor < rdata.len() {
        let Some(length) = rdata.get(cursor).copied().map(usize::from) else {
            break;
        };
        cursor += 1;
        let end = (cursor + length).min(rdata.len());
        values.push(String::from_utf8_lossy(&rdata[cursor..end]).to_string());
        cursor = end;
    }
    values.join(" ")
}

fn parse_dns_name(packet: &[u8], offset: &mut usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut cursor = *offset;
    let mut jumped = false;
    let mut jumps = 0usize;

    loop {
        let length = *packet.get(cursor)?;
        if length & 0xc0 == 0xc0 {
            let next = *packet.get(cursor + 1)?;
            let pointer = ((((length & 0x3f) as u16) << 8) | next as u16) as usize;
            if !jumped {
                *offset = cursor + 2;
            }
            cursor = pointer;
            jumped = true;
            jumps += 1;
            if jumps > 16 {
                return None;
            }
            continue;
        }
        if length & 0xc0 != 0 {
            return None;
        }
        if length == 0 {
            if !jumped {
                *offset = cursor + 1;
            }
            break;
        }

        cursor += 1;
        let end = cursor.checked_add(length as usize)?;
        let label = packet.get(cursor..end)?;
        labels.push(String::from_utf8_lossy(label).to_string());
        cursor = end;
        if !jumped {
            *offset = cursor;
        }
    }

    if labels.is_empty() {
        Some(".".to_string())
    } else {
        Some(labels.join("."))
    }
}

fn read_u16(packet: &[u8], offset: usize) -> Option<u16> {
    let bytes = packet.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(packet: &[u8], offset: usize) -> Option<u32> {
    let bytes = packet.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn dns_type_name(record_type: u16) -> String {
    match record_type {
        1 => "A".to_string(),
        2 => "NS".to_string(),
        5 => "CNAME".to_string(),
        6 => "SOA".to_string(),
        12 => "PTR".to_string(),
        15 => "MX".to_string(),
        16 => "TXT".to_string(),
        28 => "AAAA".to_string(),
        33 => "SRV".to_string(),
        64 => "SVCB".to_string(),
        65 => "HTTPS".to_string(),
        255 => "ANY".to_string(),
        other => format!("TYPE{other}"),
    }
}

fn dns_rcode_name(rcode: u16) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "ERROR",
    }
}
