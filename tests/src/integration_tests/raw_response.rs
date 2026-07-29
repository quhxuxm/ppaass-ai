use super::*;

pub(super) async fn read_http_head_bytes(stream: &mut TcpStream) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut bytes = Vec::with_capacity(1024);
    let mut buf = [0_u8; 1024];

    loop {
        let n = stream
            .read(&mut buf)
            .await
            .context("failed to read HTTP head")?;
        anyhow::ensure!(n != 0, "connection closed before HTTP head");
        bytes.extend_from_slice(&buf[..n]);

        if let Some(end) = find_http_head_end(&bytes) {
            let leftover = bytes.split_off(end);
            return Ok((bytes, leftover));
        }

        anyhow::ensure!(bytes.len() <= 16 * 1024, "HTTP head too large");
    }
}

pub(super) fn find_http_head_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

pub(super) async fn read_raw_http_response(
    stream: &mut TcpStream,
) -> Result<(StatusCode, HeaderMap, Bytes)> {
    let (head_bytes, leftover) = read_http_head_bytes(stream).await?;
    let (status, headers) = parse_raw_http_response_head(head_bytes)?;
    let content_length = response_content_length(&headers)?;

    let mut body = leftover;
    let mut buf = [0_u8; 8192];
    if body.len() < content_length {
        while body.len() < content_length {
            let remaining = content_length - body.len();
            let read_len = remaining.min(buf.len());
            let n = stream
                .read(&mut buf[..read_len])
                .await
                .context("failed to read raw response body")?;
            anyhow::ensure!(
                n != 0,
                "raw response body ended early: got {} bytes, expected content-length {}",
                body.len(),
                content_length
            );
            body.extend_from_slice(&buf[..n]);
        }
    }
    body.truncate(content_length);

    Ok((status, headers, Bytes::from(body)))
}

pub(super) async fn read_raw_http_response_slow(
    stream: &mut TcpStream,
) -> Result<(StatusCode, HeaderMap, Bytes)> {
    let (head_bytes, leftover) = read_http_head_bytes(stream).await?;
    let (status, headers) = parse_raw_http_response_head(head_bytes)?;
    let content_length = response_content_length(&headers)?;

    let mut body = leftover;
    let mut buf = [0_u8; 513];
    while body.len() < content_length {
        let remaining = content_length - body.len();
        let read_len = remaining.min(buf.len());
        let n = stream
            .read(&mut buf[..read_len])
            .await
            .context("failed to slow-read raw response body")?;
        anyhow::ensure!(
            n != 0,
            "raw response body ended early during slow read: got {} bytes, expected content-length {}",
            body.len(),
            content_length
        );
        body.extend_from_slice(&buf[..n]);
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    body.truncate(content_length);

    Ok((status, headers, Bytes::from(body)))
}

pub(super) fn parse_raw_http_response_head(head_bytes: Vec<u8>) -> Result<(StatusCode, HeaderMap)> {
    let head = String::from_utf8(head_bytes).context("HTTP response head is not UTF-8")?;
    let mut lines = head.lines();
    let status_line = lines.next().context("missing HTTP response status line")?;
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .context("missing HTTP response status code")?
        .parse::<u16>()
        .context("invalid HTTP response status code")?;
    let status = StatusCode::from_u16(status_code).context("unsupported HTTP status code")?;

    let mut headers = HeaderMap::new();
    for line in lines {
        if line.trim().is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = HeaderName::from_bytes(name.trim().as_bytes())
            .with_context(|| format!("invalid response header name: {name}"))?;
        let value = HeaderValue::from_str(value.trim())
            .with_context(|| format!("invalid response header value for {name}"))?;
        headers.append(name, value);
    }

    Ok((status, headers))
}

pub(super) fn response_content_length(headers: &HeaderMap) -> Result<usize> {
    headers
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .context("missing or invalid raw response content-length")
}

pub(super) fn verify_large_range_response(
    label: &str,
    file_size: u64,
    range_start: u64,
    range_end: u64,
    status: StatusCode,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<()> {
    let expected_len = range_end - range_start + 1;
    let actual_body_len = body.len() as u64;
    let content_length = headers
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .with_context(|| {
            format!("{label} missing or invalid content-length for range {range_start}-{range_end}")
        })?;

    anyhow::ensure!(
        status == StatusCode::PARTIAL_CONTENT,
        "{label} unexpected status {status} for range {range_start}-{range_end}"
    );
    anyhow::ensure!(
        content_length == expected_len,
        "{label} content-length mismatch for range {range_start}-{range_end}: header {content_length}, expected {expected_len}"
    );
    anyhow::ensure!(
        content_length == actual_body_len,
        "{label} content-length/body mismatch for range {range_start}-{range_end}: header {content_length}, body {actual_body_len}"
    );

    let expected_content_range = format!("bytes {range_start}-{range_end}/{file_size}");
    let actual_content_range = headers
        .get(hyper::header::CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    anyhow::ensure!(
        actual_content_range == expected_content_range,
        "{label} unexpected content-range for range {range_start}-{range_end}: {actual_content_range}"
    );

    if let Some((offset, byte)) = body.iter().enumerate().find(|(offset, byte)| {
        **byte != crate::mock_target::large_file_byte_at(range_start + *offset as u64)
    }) {
        anyhow::bail!(
            "{label} body mismatch at absolute offset {}: got {}, expected {}",
            range_start + offset as u64,
            byte,
            crate::mock_target::large_file_byte_at(range_start + offset as u64)
        );
    }

    Ok(())
}
