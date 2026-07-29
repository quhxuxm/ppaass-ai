use super::*;

pub(super) async fn slow_read_http_range(
    agent_addr: &str,
    file_size: u64,
    range_start: u64,
    range_end: u64,
) -> Result<()> {
    let mut stream = TcpStream::connect(agent_addr)
        .await
        .context("failed to connect to agent for slow HTTP range")?;
    write_http_proxy_range_request(&mut stream, file_size, range_start, range_end, true).await?;
    let (status, headers, body) = read_raw_http_response_slow(&mut stream).await?;

    verify_large_range_response(
        "Slow HTTP Range",
        file_size,
        range_start,
        range_end,
        status,
        &headers,
        &body,
    )
}

pub(super) async fn slow_read_connect_range(
    agent_addr: &str,
    file_size: u64,
    range_start: u64,
    range_end: u64,
) -> Result<()> {
    let mut stream = TcpStream::connect(agent_addr)
        .await
        .context("failed to connect to agent for slow CONNECT range")?;
    write_connect_request(&mut stream, "127.0.0.1:9090").await?;
    read_connect_ok_response(&mut stream).await?;
    write_tunneled_range_request(&mut stream, file_size, range_start, range_end, true).await?;
    let (status, headers, body) = read_raw_http_response_slow(&mut stream).await?;

    verify_large_range_response(
        "Slow CONNECT Range",
        file_size,
        range_start,
        range_end,
        status,
        &headers,
        &body,
    )
}

pub(super) async fn slow_read_socks5_range(
    agent_addr: &str,
    file_size: u64,
    range_start: u64,
    range_end: u64,
) -> Result<()> {
    let mut stream = TcpStream::connect(agent_addr)
        .await
        .context("failed to connect to agent for slow SOCKS5 range")?;
    async_socks5::connect(&mut stream, ("127.0.0.1".to_string(), 9090), None)
        .await
        .context("failed to connect through SOCKS5 for slow range")?;
    write_tunneled_range_request(&mut stream, file_size, range_start, range_end, true).await?;
    let (status, headers, body) = read_raw_http_response_slow(&mut stream).await?;

    verify_large_range_response(
        "Slow SOCKS5 Range",
        file_size,
        range_start,
        range_end,
        status,
        &headers,
        &body,
    )
}

pub(super) async fn cancel_http_range_after_partial_body(
    agent_addr: &str,
    file_size: u64,
    range_start: u64,
    range_end: u64,
) -> Result<()> {
    let mut stream = TcpStream::connect(agent_addr)
        .await
        .context("failed to connect to agent for cancelled HTTP range")?;
    write_http_proxy_range_request(&mut stream, file_size, range_start, range_end, true).await?;
    read_partial_response_then_drop(
        &mut stream,
        "Cancelled HTTP Range",
        file_size,
        range_start,
        range_end,
    )
    .await
}

pub(super) async fn cancel_connect_range_after_partial_body(
    agent_addr: &str,
    file_size: u64,
    range_start: u64,
    range_end: u64,
) -> Result<()> {
    let mut stream = TcpStream::connect(agent_addr)
        .await
        .context("failed to connect to agent for cancelled CONNECT range")?;
    write_connect_request(&mut stream, "127.0.0.1:9090").await?;
    read_connect_ok_response(&mut stream).await?;
    write_tunneled_range_request(&mut stream, file_size, range_start, range_end, true).await?;
    read_partial_response_then_drop(
        &mut stream,
        "Cancelled CONNECT Range",
        file_size,
        range_start,
        range_end,
    )
    .await
}

pub(super) async fn cancel_socks5_range_after_partial_body(
    agent_addr: &str,
    file_size: u64,
    range_start: u64,
    range_end: u64,
) -> Result<()> {
    let mut stream = TcpStream::connect(agent_addr)
        .await
        .context("failed to connect to agent for cancelled SOCKS5 range")?;
    async_socks5::connect(&mut stream, ("127.0.0.1".to_string(), 9090), None)
        .await
        .context("failed to connect through SOCKS5 for cancelled range")?;
    write_tunneled_range_request(&mut stream, file_size, range_start, range_end, true).await?;
    read_partial_response_then_drop(
        &mut stream,
        "Cancelled SOCKS5 Range",
        file_size,
        range_start,
        range_end,
    )
    .await
}

pub(super) async fn verify_http_range_chunk(
    agent_addr: &str,
    file_size: u64,
    range_start: u64,
    range_end: u64,
) -> Result<()> {
    let client = MockHttpClient::new(agent_addr.to_string());
    let headers = [("Range", format!("bytes={range_start}-{range_end}"))];
    let (_, status, headers, body) = client
        .get_bytes_with_headers(
            &format!("http://127.0.0.1:9090/large?size={file_size}"),
            &headers,
        )
        .await
        .with_context(|| format!("HTTP range {range_start}-{range_end} failed"))?;

    verify_large_range_response(
        "HTTP Range with blocked target connects",
        file_size,
        range_start,
        range_end,
        status,
        &headers,
        &body,
    )
}

pub(super) async fn verify_connect_range_chunk(
    agent_addr: &str,
    file_size: u64,
    range_start: u64,
    range_end: u64,
) -> Result<()> {
    let client = MockHttpClient::new(agent_addr.to_string());
    let headers = [("Range", format!("bytes={range_start}-{range_end}"))];
    let (_, status, headers, body) = client
        .connect_tunnel_get_bytes_with_headers(
            "127.0.0.1:9090",
            &format!("/large?size={file_size}"),
            &headers,
        )
        .await
        .with_context(|| format!("CONNECT range {range_start}-{range_end} failed"))?;

    verify_large_range_response(
        "CONNECT Range with blocked target connects",
        file_size,
        range_start,
        range_end,
        status,
        &headers,
        &body,
    )
}
