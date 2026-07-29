use super::*;

pub(super) async fn verify_mixed_protocol_range_downloads(
    agent_addr: &str,
    file_size: u64,
    chunk_size: u64,
    chunk_count: u64,
) -> Result<()> {
    let mut handles = Vec::with_capacity(chunk_count as usize);
    for idx in 0..chunk_count {
        let agent_addr = agent_addr.to_string();
        handles.push(tokio::spawn(async move {
            let start = idx * chunk_size + (idx % 13);
            let end = start + chunk_size - 1;
            match idx % 3 {
                0 => {
                    verify_fluctuating_http_range_chunk(
                        &agent_addr,
                        "127.0.0.1:9090",
                        file_size,
                        start,
                        end,
                    )
                    .await
                }
                1 => {
                    verify_fluctuating_connect_range_chunk(
                        &agent_addr,
                        "127.0.0.1:9090",
                        file_size,
                        start,
                        end,
                    )
                    .await
                }
                _ => {
                    verify_fluctuating_socks5_range_chunk(
                        &agent_addr,
                        "127.0.0.1:9090",
                        file_size,
                        start,
                        end,
                    )
                    .await
                }
            }
        }));
    }

    let mut errors = Vec::new();
    for handle in handles {
        match handle
            .await
            .context("mixed protocol verification task panicked")?
        {
            Ok(()) => {}
            Err(err) => errors.push(err.to_string()),
        }
    }

    anyhow::ensure!(
        errors.is_empty(),
        "混合协议分片校验失败：{}",
        errors.join("; ")
    );
    Ok(())
}

pub(super) async fn verify_fluctuating_http_range_chunk(
    agent_addr: &str,
    target_authority: &str,
    file_size: u64,
    range_start: u64,
    range_end: u64,
) -> Result<()> {
    let client = MockHttpClient::new(agent_addr.to_string());
    let headers = [("Range", format!("bytes={range_start}-{range_end}"))];
    let target_url = format!("http://{target_authority}/fluctuating-large?size={file_size}");
    let request = client.get_bytes_with_headers(&target_url, &headers);
    let (_, status, headers, body) = tokio::time::timeout(FLUCTUATING_TARGET_TIMEOUT, request)
        .await
        .context("HTTP fluctuating range timeout")??;

    verify_large_range_response(
        "HTTP Range with fluctuating target",
        file_size,
        range_start,
        range_end,
        status,
        &headers,
        &body,
    )
}

pub(super) async fn verify_fluctuating_connect_range_chunk(
    agent_addr: &str,
    target_authority: &str,
    file_size: u64,
    range_start: u64,
    range_end: u64,
) -> Result<()> {
    let client = MockHttpClient::new(agent_addr.to_string());
    let headers = [("Range", format!("bytes={range_start}-{range_end}"))];
    let target_path = format!("/fluctuating-large?size={file_size}");
    let request =
        client.connect_tunnel_get_bytes_with_headers(target_authority, &target_path, &headers);
    let (_, status, headers, body) = tokio::time::timeout(FLUCTUATING_TARGET_TIMEOUT, request)
        .await
        .context("CONNECT fluctuating range timeout")??;

    verify_large_range_response(
        "CONNECT Range with fluctuating target",
        file_size,
        range_start,
        range_end,
        status,
        &headers,
        &body,
    )
}

pub(super) async fn verify_fluctuating_socks5_range_chunk(
    agent_addr: &str,
    target_authority: &str,
    file_size: u64,
    range_start: u64,
    range_end: u64,
) -> Result<()> {
    let target_addr: SocketAddr = target_authority
        .parse()
        .context("invalid fluctuating target addr")?;
    let mut stream = TcpStream::connect(agent_addr)
        .await
        .context("failed to connect to agent for SOCKS5 fluctuating range")?;

    async_socks5::connect(
        &mut stream,
        (target_addr.ip().to_string(), target_addr.port()),
        None,
    )
    .await
    .context("failed to connect through SOCKS5 for fluctuating range")?;

    let request = format!(
        "GET /fluctuating-large?size={file_size} HTTP/1.1\r\nHost: {target_authority}\r\nRange: bytes={range_start}-{range_end}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .context("failed to write SOCKS5 fluctuating range request")?;
    stream
        .flush()
        .await
        .context("failed to flush SOCKS5 fluctuating range request")?;

    let (status, headers, body) = tokio::time::timeout(
        FLUCTUATING_TARGET_TIMEOUT,
        read_raw_http_response(&mut stream),
    )
    .await
    .context("SOCKS5 fluctuating range timeout")??;

    verify_large_range_response(
        "SOCKS5 Range with fluctuating target",
        file_size,
        range_start,
        range_end,
        status,
        &headers,
        &body,
    )
}

pub(super) async fn verify_socks5_large_range_chunk(
    agent_addr: &str,
    file_size: u64,
    range_start: u64,
    range_end: u64,
) -> Result<()> {
    let mut stream = TcpStream::connect(agent_addr)
        .await
        .context("failed to connect to agent for SOCKS5 large range")?;

    async_socks5::connect(&mut stream, ("127.0.0.1".to_string(), 9090), None)
        .await
        .context("failed to connect through SOCKS5 for large range")?;

    let request = format!(
        "GET /large?size={file_size} HTTP/1.1\r\nHost: 127.0.0.1:9090\r\nRange: bytes={range_start}-{range_end}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .context("failed to write SOCKS5 large range request")?;
    stream
        .flush()
        .await
        .context("failed to flush SOCKS5 large range request")?;

    let (status, headers, body) = read_raw_http_response(&mut stream).await?;

    verify_large_range_response(
        "SOCKS5 Large Range",
        file_size,
        range_start,
        range_end,
        status,
        &headers,
        &body,
    )
}

pub(super) async fn verify_http_repeated_range_sequence(
    agent_addr: &str,
    count: u64,
    file_size: u64,
    chunk_size: u64,
) -> Result<()> {
    for idx in 0..count {
        let range_start = idx * chunk_size + (idx % 17);
        let range_end = range_start + chunk_size - 1;
        verify_fluctuating_http_range_chunk(
            agent_addr,
            "127.0.0.1:9090",
            file_size,
            range_start,
            range_end,
        )
        .await
        .with_context(|| format!("HTTP repeated range request {idx} failed"))?;
    }
    Ok(())
}

pub(super) async fn verify_connect_keepalive_range_sequence(
    agent_addr: &str,
    count: u64,
    file_size: u64,
    chunk_size: u64,
) -> Result<()> {
    let mut stream = TcpStream::connect(agent_addr)
        .await
        .context("failed to connect to agent for CONNECT keep-alive sequence")?;
    write_connect_request(&mut stream, "127.0.0.1:9090").await?;
    read_connect_ok_response(&mut stream).await?;

    for idx in 0..count {
        let range_start = idx * chunk_size + (idx % 19);
        let range_end = range_start + chunk_size - 1;
        let close = idx + 1 == count;
        write_tunneled_range_request(&mut stream, file_size, range_start, range_end, close)
            .await
            .with_context(|| format!("CONNECT keep-alive request {idx} write failed"))?;
        let (status, headers, body) = read_raw_http_response(&mut stream)
            .await
            .with_context(|| {
                format!(
                    "CONNECT keep-alive response {idx} read failed for range {range_start}-{range_end}"
                )
            })?;

        verify_large_range_response(
            "CONNECT keep-alive Range",
            file_size,
            range_start,
            range_end,
            status,
            &headers,
            &body,
        )?;
    }

    Ok(())
}
