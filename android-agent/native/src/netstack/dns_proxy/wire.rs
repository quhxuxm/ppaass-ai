use super::*;

pub(super) async fn send_dns_request<W>(
    writer: &mut W,
    pending: &mut HashMap<u16, PendingDnsRequest>,
    next_id: &mut u16,
    request: &DnsProxyRequest,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let Some(original_id) = dns_id(&request.packet) else {
        debug!("Android TUN DNS request is too short; dropping");
        return Ok(());
    };
    let (query, record_type) = parse_dns_query(&request.packet)
        .unwrap_or_else(|| ("<unknown>".to_string(), "UNKNOWN".to_string()));
    debug!(
        query = %query,
        record_type,
        "Android TUN DNS proxy request"
    );

    cleanup_pending_dns(pending);
    let Some(upstream_id) = allocate_dns_id(pending, next_id) else {
        warn!("Android TUN DNS pending table is full; dropping request");
        return Ok(());
    };

    let started_at = Instant::now();
    let mut packet = request.packet.clone();
    write_dns_id(&mut packet, upstream_id);
    pending.insert(
        upstream_id,
        PendingDnsRequest {
            client: request.client,
            target: request.target,
            original_id,
            query,
            record_type,
            started_at,
            expires_at: Instant::now() + DNS_PENDING_TTL,
        },
    );

    let write_result = async {
        writer.write_all(&packet).await?;
        writer.flush().await
    }
    .await;

    if write_result.is_err() {
        pending.remove(&upstream_id);
    }

    write_result
}

pub(super) async fn handle_dns_response(
    netstack_tx: &UdpWriter,
    direct_domain_cache: &DirectDomainCache,
    response_cache: &mut DnsResponseCache,
    pending: &mut HashMap<u16, PendingDnsRequest>,
    response: &mut [u8],
) -> io::Result<()> {
    let Some(upstream_id) = dns_id(response) else {
        debug!("Android TUN DNS response is too short; dropping");
        return Ok(());
    };

    let Some(request) = pending.remove(&upstream_id) else {
        debug!("Android TUN DNS response had no matching id={upstream_id}");
        return Ok(());
    };

    let response_summary = parse_dns_response(response).unwrap_or_else(|| DnsResponseSummary {
        status: "INVALID".to_string(),
        answers: Vec::new(),
        min_ttl: None,
    });
    response_cache.insert(
        &request.query,
        &request.record_type,
        &response_summary,
        response,
    );
    direct_domain_cache.record_resolution(&request.query, &response_summary.answers);
    traffic_stats::record_dns_resolution(DnsResolutionRecord {
        timestamp_ms: traffic_stats::current_time_millis(),
        resolver: "agent".to_string(),
        client: request.client.to_string(),
        upstream: request.target.to_string(),
        query: request.query,
        record_type: request.record_type,
        status: response_summary.status,
        answers: response_summary.answers,
        duration_ms: request.started_at.elapsed().as_millis(),
    });

    write_dns_id(response, request.original_id);
    let mut tx = netstack_tx.lock().await;
    debug!(
        "Android TUN DNS response writeback: {} -> {} bytes={}",
        request.target,
        request.client,
        response.len()
    );
    tx.send((response.to_vec(), request.target, request.client))
        .await
}

pub(super) fn cleanup_pending_dns(pending: &mut HashMap<u16, PendingDnsRequest>) {
    let now = Instant::now();
    let expired_ids: Vec<u16> = pending
        .iter()
        .filter_map(|(id, request)| (request.expires_at <= now).then_some(*id))
        .collect();

    for id in expired_ids {
        if let Some(request) = pending.remove(&id) {
            traffic_stats::record_dns_resolution(DnsResolutionRecord {
                timestamp_ms: traffic_stats::current_time_millis(),
                resolver: "agent".to_string(),
                client: request.client.to_string(),
                upstream: request.target.to_string(),
                query: request.query,
                record_type: request.record_type,
                status: "TIMEOUT".to_string(),
                answers: Vec::new(),
                duration_ms: request.started_at.elapsed().as_millis(),
            });
        }
    }
}

pub(super) fn allocate_dns_id(
    pending: &HashMap<u16, PendingDnsRequest>,
    next_id: &mut u16,
) -> Option<u16> {
    for _ in 0..=u16::MAX {
        let id = *next_id;
        *next_id = next_id.wrapping_add(1);
        if !pending.contains_key(&id) {
            return Some(id);
        }
    }
    None
}

pub(super) fn dns_id(packet: &[u8]) -> Option<u16> {
    let bytes = packet.get(..2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

pub(super) fn write_dns_id(packet: &mut [u8], id: u16) {
    let bytes = id.to_be_bytes();
    packet[0] = bytes[0];
    packet[1] = bytes[1];
}

pub(super) fn build_dns_error_response(request: &[u8], rcode: u16) -> Option<Vec<u8>> {
    let question = parse_dns_question(request)?;
    let request_flags = read_u16(request, 2).unwrap_or(0);
    let flags = 0x8000 | (request_flags & 0x0100) | 0x0080 | (rcode & 0x000f);

    let mut response = Vec::with_capacity(question.question_end);
    response.extend_from_slice(request.get(..2)?);
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(request.get(12..question.question_end)?);
    Some(response)
}

pub(super) struct DnsQuestion {
    pub(super) query: String,
    pub(super) record_type: String,
    pub(super) question_end: usize,
}

pub(super) fn parse_dns_query(packet: &[u8]) -> Option<(String, String)> {
    let question = parse_dns_question(packet)?;
    Some((question.query, question.record_type))
}

pub(super) fn parse_dns_question(packet: &[u8]) -> Option<DnsQuestion> {
    // DNS 查询本身交给 hickory-proto 校验；这里仅补充计算 question 结束位置，
    // 便于构造错误响应时原样带回客户端问题段。
    let parsed = parse_dns_query_packet(packet)?;

    let mut offset = 12;
    parse_dns_name(packet, &mut offset)?;
    offset = offset.checked_add(2)?;
    let _class = read_u16(packet, offset)?;
    offset = offset.checked_add(2)?;
    if offset > packet.len() {
        return None;
    }
    Some(DnsQuestion {
        query: parsed.query,
        record_type: parsed.record_type,
        question_end: offset,
    })
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
    let mut min_ttl = None;
    for _ in 0..ancount {
        parse_dns_name(packet, &mut offset)?;
        let record_type = read_u16(packet, offset)?;
        offset = offset.checked_add(2)?;
        let _class = read_u16(packet, offset)?;
        offset = offset.checked_add(2)?;
        let ttl = read_u32(packet, offset)?;
        offset = offset.checked_add(4)?;
        let rdlength = read_u16(packet, offset)? as usize;
        offset = offset.checked_add(2)?;
        let rdata_offset = offset;
        let rdata_end = offset.checked_add(rdlength)?;
        if rdata_end > packet.len() {
            return None;
        }

        if let Some(answer) = parse_dns_answer_rdata(packet, rdata_offset, rdlength, record_type) {
            min_ttl = Some(min_ttl.map_or(ttl, |current: u32| current.min(ttl)));
            answers.push(answer);
        }
        offset = rdata_end;
    }

    Some(DnsResponseSummary {
        status: dns_rcode_name(flags & 0x000f).to_string(),
        answers,
        min_ttl,
    })
}

pub(super) fn parse_dns_answer_rdata(
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

pub(super) fn parse_txt_rdata(rdata: &[u8]) -> String {
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

pub(super) fn parse_dns_name(packet: &[u8], offset: &mut usize) -> Option<String> {
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

pub(super) fn read_u16(packet: &[u8], offset: usize) -> Option<u16> {
    let bytes = packet.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

pub(super) fn read_u32(packet: &[u8], offset: usize) -> Option<u32> {
    let bytes = packet.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(super) fn dns_rcode_name(rcode: u16) -> &'static str {
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
