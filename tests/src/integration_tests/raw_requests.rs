use super::*;

pub(super) async fn run_blocked_target_connect_attempt(agent_addr: String, worker_id: usize) {
    match worker_id % 3 {
        0 => {
            let client = MockHttpClient::new(agent_addr);
            let _ = tokio::time::timeout(
                BLOCKED_TARGET_TIMEOUT,
                client.get(&format!(
                    "http://{BLOCKED_TARGET_HOST}:{BLOCKED_TARGET_PORT}/"
                )),
            )
            .await;
        }
        1 => {
            let client = MockHttpClient::new(agent_addr);
            let _ = tokio::time::timeout(
                BLOCKED_TARGET_TIMEOUT,
                client.connect_tunnel_get_bytes_with_headers(
                    &format!("{BLOCKED_TARGET_HOST}:{BLOCKED_TARGET_PORT}"),
                    "/",
                    &[],
                ),
            )
            .await;
        }
        _ => {
            let client = MockSocks5Client::new(agent_addr);
            let _ = tokio::time::timeout(
                BLOCKED_TARGET_TIMEOUT,
                client.send_receive(BLOCKED_TARGET_HOST, BLOCKED_TARGET_PORT, b"probe"),
            )
            .await;
        }
    }
}

pub(super) async fn write_connect_request(stream: &mut TcpStream, authority: &str) -> Result<()> {
    let request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: keep-alive\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .context("failed to write CONNECT request")?;
    stream
        .flush()
        .await
        .context("failed to flush CONNECT request")
}

pub(super) async fn read_connect_ok_response(stream: &mut TcpStream) -> Result<()> {
    let (head, _leftover) = read_http_head_bytes(stream).await?;
    let head = String::from_utf8(head).context("CONNECT response is not UTF-8")?;
    let status_line = head.lines().next().unwrap_or_default();
    anyhow::ensure!(
        status_line.contains(" 200 "),
        "CONNECT failed: {status_line}"
    );
    Ok(())
}

pub(super) async fn write_http_proxy_range_request(
    stream: &mut TcpStream,
    file_size: u64,
    range_start: u64,
    range_end: u64,
    close: bool,
) -> Result<()> {
    let connection = if close { "close" } else { "keep-alive" };
    let request = format!(
        "GET http://127.0.0.1:9090/fluctuating-large?size={file_size} HTTP/1.1\r\nHost: 127.0.0.1:9090\r\nRange: bytes={range_start}-{range_end}\r\nConnection: {connection}\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .context("failed to write HTTP proxy range request")?;
    stream
        .flush()
        .await
        .context("failed to flush HTTP proxy range request")
}

pub(super) async fn write_tunneled_range_request(
    stream: &mut TcpStream,
    file_size: u64,
    range_start: u64,
    range_end: u64,
    close: bool,
) -> Result<()> {
    let connection = if close { "close" } else { "keep-alive" };
    let request = format!(
        "GET /fluctuating-large?size={file_size} HTTP/1.1\r\nHost: 127.0.0.1:9090\r\nRange: bytes={range_start}-{range_end}\r\nConnection: {connection}\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .context("failed to write tunneled range request")?;
    stream
        .flush()
        .await
        .context("failed to flush tunneled range request")
}

pub(super) async fn read_partial_response_then_drop(
    stream: &mut TcpStream,
    label: &str,
    file_size: u64,
    range_start: u64,
    range_end: u64,
) -> Result<()> {
    let (head_bytes, leftover) = read_http_head_bytes(stream).await?;
    let (status, headers) = parse_raw_http_response_head(head_bytes)?;
    let expected_len = range_end - range_start + 1;
    let content_length = response_content_length(&headers)? as u64;

    anyhow::ensure!(
        status == StatusCode::PARTIAL_CONTENT,
        "{label} unexpected status before cancellation: {status}"
    );
    anyhow::ensure!(
        content_length == expected_len,
        "{label} content-length mismatch before cancellation: header {content_length}, expected {expected_len}"
    );
    let expected_content_range = format!("bytes {range_start}-{range_end}/{file_size}");
    let actual_content_range = headers
        .get(hyper::header::CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    anyhow::ensure!(
        actual_content_range == expected_content_range,
        "{label} unexpected content-range before cancellation: {actual_content_range}"
    );

    let mut partial_len = leftover.len().min(expected_len as usize);
    let target_partial_len = 8 * 1024_usize;
    let mut buf = [0_u8; 1024];
    while partial_len < target_partial_len.min(expected_len as usize) {
        let n = stream
            .read(&mut buf)
            .await
            .context("failed to read partial response body")?;
        anyhow::ensure!(n != 0, "{label} ended before cancellation point");
        partial_len += n;
    }

    anyhow::ensure!(
        partial_len < expected_len as usize,
        "{label} completed before cancellation point"
    );
    Ok(())
}
