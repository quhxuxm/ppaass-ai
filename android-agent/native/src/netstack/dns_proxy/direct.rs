use super::*;

pub(super) async fn try_send_cached_dns_response(
    context: &ForwardContext,
    netstack_tx: &UdpWriter,
    response_cache: &mut DnsResponseCache,
    request: &DnsProxyRequest,
) -> bool {
    let Some(original_id) = dns_id(&request.packet) else {
        debug!("Android TUN DNS request too short; skipping cache lookup");
        return false;
    };
    let Some(question) = parse_dns_question(&request.packet) else {
        debug!("Android TUN DNS request parse failed; skipping cache lookup");
        return false;
    };
    let Some(response) = response_cache.get(&question.query, &question.record_type, original_id)
    else {
        return false;
    };

    let summary = parse_dns_response(&response).unwrap_or_else(|| DnsResponseSummary {
        status: "INVALID".to_string(),
        answers: Vec::new(),
        min_ttl: None,
    });
    context
        .direct_domain_cache
        .record_resolution(&question.query, &summary.answers);
    traffic_stats::record_dns_resolution(DnsResolutionRecord {
        timestamp_ms: traffic_stats::current_time_millis(),
        resolver: "agent-cache".to_string(),
        client: request.client.to_string(),
        upstream: request.target.to_string(),
        query: question.query,
        record_type: question.record_type,
        status: summary.status,
        answers: summary.answers,
        duration_ms: 0,
    });

    if let Err(e) = netstack_tx
        .send((response, request.target, request.client))
        .await
    {
        debug!("Android TUN DNS cached response writeback failed: {e}");
    }
    true
}

pub(super) async fn try_send_direct_dns_response(
    context: &ForwardContext,
    netstack_tx: &UdpWriter,
    response_cache: &mut DnsResponseCache,
    request: &DnsProxyRequest,
) -> bool {
    let Some(question) = parse_dns_question(&request.packet) else {
        debug!(
            bytes = request.packet.len(),
            "Android TUN DNS request parse failed"
        );
        return false;
    };
    if !context.direct_checker.is_direct_domain(&question.query) {
        debug!(
            query = %question.query,
            record_type = %question.record_type,
            "Android TUN DNS proxy candidate"
        );
        return false;
    }

    let started_at = Instant::now();
    debug!(
        "Android TUN DNS direct -> {} {} via {}",
        question.query, question.record_type, request.target
    );

    let direct_result = timeout(
        DIRECT_DNS_TIMEOUT,
        query_direct_dns(request.target, &request.packet),
    )
    .await;

    let mut response = match direct_result {
        Ok(Ok(response)) => response,
        Ok(Err(e)) => {
            debug!(
                "Android TUN DNS direct query failed: {} {} via {}, error: {}",
                question.query, question.record_type, request.target, e
            );
            build_dns_error_response(&request.packet, 2).unwrap_or_default()
        }
        Err(_) => {
            debug!(
                "Android TUN DNS direct query timed out: {} {} via {}",
                question.query, question.record_type, request.target
            );
            build_dns_error_response(&request.packet, 2).unwrap_or_default()
        }
    };

    if response.is_empty() {
        return true;
    }

    let summary = parse_dns_response(&response).unwrap_or_else(|| DnsResponseSummary {
        status: "INVALID".to_string(),
        answers: Vec::new(),
        min_ttl: None,
    });
    response_cache.insert(&question.query, &question.record_type, &summary, &response);
    context
        .direct_domain_cache
        .record_resolution(&question.query, &summary.answers);
    record_direct_dns_result(
        request,
        &question,
        &summary.status,
        summary.answers,
        started_at,
    );

    if let Err(e) = netstack_tx
        .send((response.split_off(0), request.target, request.client))
        .await
    {
        debug!("Android TUN DNS direct response writeback failed: {e}");
    }
    true
}

pub(super) async fn query_direct_dns(upstream: SocketAddr, packet: &[u8]) -> io::Result<Vec<u8>> {
    let socket = bind_direct_dns_socket(upstream)?;
    socket.send_to(packet, upstream).await?;
    let mut response = vec![0u8; 65535];
    let (n, _) = socket.recv_from(&mut response).await?;
    response.truncate(n);
    Ok(response)
}

pub(super) fn bind_direct_dns_socket(upstream: SocketAddr) -> io::Result<UdpSocket> {
    let socket = Socket::new(
        Domain::for_address(upstream),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    protect_direct_socket(&socket)?;
    super::super::udp::tune_direct_udp_socket(&socket, upstream);
    let bind_addr: SocketAddr = if upstream.is_ipv4() {
        "0.0.0.0:0".parse().expect("valid IPv4 bind address")
    } else {
        "[::]:0".parse().expect("valid IPv6 bind address")
    };
    socket.bind(&SockAddr::from(bind_addr))?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

pub(super) fn protect_direct_socket(socket: &Socket) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;

        crate::socket_protector::protect_fd(socket.as_raw_fd())
    }

    #[cfg(not(unix))]
    {
        let _ = socket;
        Ok(())
    }
}

pub(super) fn record_direct_dns_result(
    request: &DnsProxyRequest,
    question: &DnsQuestion,
    status: &str,
    answers: Vec<String>,
    started_at: Instant,
) {
    traffic_stats::record_dns_resolution(DnsResolutionRecord {
        timestamp_ms: traffic_stats::current_time_millis(),
        resolver: "agent-direct".to_string(),
        client: request.client.to_string(),
        upstream: request.target.to_string(),
        query: question.query.clone(),
        record_type: question.record_type.clone(),
        status: status.to_string(),
        answers,
        duration_ms: started_at.elapsed().as_millis(),
    });
}
