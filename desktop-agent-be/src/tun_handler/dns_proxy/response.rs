use super::*;

pub(super) async fn try_send_cached_dns_response(
    netstack_tx: &UdpWriter,
    direct_domain_cache: &DirectDomainCache,
    response_cache: &mut DnsResponseCache,
    request: &DnsProxyRequest,
) -> bool {
    let Some(original_id) = dns_id(&request.packet) else {
        debug!("TUN UDP DNS 请求过短，跳过缓存查询");
        return false;
    };
    let Some((query, record_type)) = parse_dns_query(&request.packet) else {
        debug!("TUN UDP DNS 请求解析失败，跳过缓存查询");
        return false;
    };
    let Some(response) = response_cache.get(&query, &record_type, original_id) else {
        return false;
    };

    let response_summary = parse_dns_response(&response).unwrap_or_else(|| DnsResponseSummary {
        status: "INVALID".to_string(),
        answers: Vec::new(),
        min_ttl: None,
    });
    direct_domain_cache.record_resolution(&query, &response_summary.answers);
    telemetry::emit_dns_resolution(DnsResolutionRecord {
        timestamp_ms: telemetry::current_time_millis(),
        resolver: "agent-cache".to_string(),
        client: request.client.to_string(),
        upstream: request.target.to_string(),
        query,
        record_type,
        status: response_summary.status,
        answers: response_summary.answers,
        duration_ms: 0,
    });

    let mut writer = netstack_tx.lock().await;
    if let Err(e) = writer
        .send((response, request.target, request.client))
        .await
    {
        debug!("TUN UDP DNS 缓存回复写回失败：{e}");
    }
    true
}

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
        debug!("TUN UDP DNS 请求过短，已丢弃");
        return Ok(());
    };
    let (query, record_type) = parse_dns_query(&request.packet)
        .unwrap_or_else(|| ("<unknown>".to_string(), "UNKNOWN".to_string()));

    cleanup_pending_dns(pending);
    // 同一条共享连接上可能有多个并发 DNS 请求；改写 ID 用于区分响应归属。
    let Some(upstream_id) = allocate_dns_id(pending, next_id) else {
        warn!("TUN UDP DNS 待处理请求过多，已丢弃一个请求");
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
    // 根据改写后的 upstream_id 找回原请求，恢复原始 DNS ID 后写回 netstack。
    let Some(upstream_id) = dns_id(response) else {
        debug!("TUN UDP DNS 回复过短，已丢弃");
        return Ok(());
    };

    let Some(request) = pending.remove(&upstream_id) else {
        debug!("TUN UDP DNS 收到无匹配请求的回复 id={upstream_id}");
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
    telemetry::emit_dns_resolution(DnsResolutionRecord {
        timestamp_ms: telemetry::current_time_millis(),
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
    let mut s = netstack_tx.lock().await;
    s.send((response.to_vec(), request.target, request.client))
        .await
}

pub fn cleanup_pending_dns(pending: &mut HashMap<u16, PendingDnsRequest>) -> usize {
    let now = Instant::now();
    let expired_ids: Vec<u16> = pending
        .iter()
        .filter_map(|(id, request)| (request.expires_at <= now).then_some(*id))
        .collect();

    let expired_count = expired_ids.len();
    for id in expired_ids {
        if let Some(request) = pending.remove(&id) {
            telemetry::emit_dns_resolution(DnsResolutionRecord {
                timestamp_ms: telemetry::current_time_millis(),
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
    expired_count
}

pub fn allocate_dns_id(
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

pub fn dns_id(packet: &[u8]) -> Option<u16> {
    let bytes = packet.get(..2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

pub fn write_dns_id(packet: &mut [u8], id: u16) {
    let bytes = id.to_be_bytes();
    packet[0] = bytes[0];
    packet[1] = bytes[1];
}
