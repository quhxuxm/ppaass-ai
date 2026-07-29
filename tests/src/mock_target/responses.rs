use super::*;

pub(super) async fn handle_http_request(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let path = req.uri().path();
    info!("HTTP 请求：{} {}", req.method(), path);

    let response = match path {
        "/health" => Response::builder()
            .status(StatusCode::OK)
            .body(full_body("OK"))?,
        "/echo" => {
            // 回显请求体
            let body = req.collect().await?.to_bytes();
            Response::builder()
                .status(StatusCode::OK)
                .body(BoxBody::new(Full::new(body).map_err(|e| match e {})))?
        }
        "/large" => {
            // 返回用于吞吐测试的大响应，并支持 Range 分片下载。
            handle_large_response(&req)?
        }
        "/fluctuating-large" => {
            // 按小块和短暂停顿流式返回，用于模拟目标网络波动。
            handle_fluctuating_large_response(&req)?
        }
        "/json" => {
            let json_data = r#"{"status":"success","message":"Mock target response"}"#;
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(full_body(json_data))?
        }
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(full_body("Not Found"))?,
    };

    Ok(response)
}

pub(super) fn handle_large_response(
    req: &Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let size = large_response_size(req.uri().query());
    let range = match parse_range_header(
        req.headers()
            .get(RANGE)
            .and_then(|value| value.to_str().ok()),
        size,
    ) {
        Ok(range) => range,
        Err(()) => {
            return Ok(Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header(ACCEPT_RANGES, "bytes")
                .header(CONTENT_RANGE, format!("bytes */{size}"))
                .body(full_body("Range Not Satisfiable"))?);
        }
    };

    if let Some((start, end)) = range {
        let body = large_file_body(start, end - start + 1);
        return Ok(Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header(ACCEPT_RANGES, "bytes")
            .header(CONTENT_RANGE, format!("bytes {start}-{end}/{size}"))
            .header(CONTENT_LENGTH, body.len().to_string())
            .body(full_body(body))?);
    }

    let body = large_file_body(0, size);
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(ACCEPT_RANGES, "bytes")
        .header(CONTENT_LENGTH, body.len().to_string())
        .body(full_body(body))?)
}

pub(super) fn handle_fluctuating_large_response(
    req: &Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let size = large_response_size(req.uri().query());
    let range = match parse_range_header(
        req.headers()
            .get(RANGE)
            .and_then(|value| value.to_str().ok()),
        size,
    ) {
        Ok(range) => range,
        Err(()) => {
            return Ok(Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header(ACCEPT_RANGES, "bytes")
                .header(CONTENT_RANGE, format!("bytes */{size}"))
                .body(full_body("Range Not Satisfiable"))?);
        }
    };

    let (status, start, end) = if let Some((start, end)) = range {
        (StatusCode::PARTIAL_CONTENT, start, end)
    } else {
        (StatusCode::OK, 0, size - 1)
    };
    let body_len = end - start + 1;
    let mut builder = Response::builder()
        .status(status)
        .header(ACCEPT_RANGES, "bytes")
        .header(CONTENT_LENGTH, body_len.to_string());
    if status == StatusCode::PARTIAL_CONTENT {
        builder = builder.header(CONTENT_RANGE, format!("bytes {start}-{end}/{size}"));
    }

    Ok(builder.body(fluctuating_large_body(start, body_len))?)
}

pub(super) fn large_response_size(query: Option<&str>) -> u64 {
    query
        .and_then(|query| {
            query.split('&').find_map(|pair| {
                let (key, value) = pair.split_once('=')?;
                (key == "size").then_some(value)
            })
        })
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_LARGE_RESPONSE_SIZE_BYTES)
        .clamp(1, MAX_LARGE_RESPONSE_SIZE_BYTES)
}

pub(super) fn parse_range_header(
    range: Option<&str>,
    size: u64,
) -> std::result::Result<Option<(u64, u64)>, ()> {
    let Some(range) = range else {
        return Ok(None);
    };
    let range = range.trim().strip_prefix("bytes=").ok_or(())?;
    if range.contains(',') {
        return Err(());
    }
    let (start, end) = range.split_once('-').ok_or(())?;

    if start.is_empty() {
        let suffix_len = end.parse::<u64>().map_err(|_| ())?;
        if suffix_len == 0 {
            return Err(());
        }
        let start = size.saturating_sub(suffix_len);
        return Ok(Some((start, size - 1)));
    }

    let start = start.parse::<u64>().map_err(|_| ())?;
    if start >= size {
        return Err(());
    }

    let end = if end.is_empty() {
        size - 1
    } else {
        end.parse::<u64>().map_err(|_| ())?.min(size - 1)
    };
    if end < start {
        return Err(());
    }

    Ok(Some((start, end)))
}

pub(super) fn large_file_body(start: u64, len: u64) -> Vec<u8> {
    (0..len)
        .map(|offset| large_file_byte_at(start + offset))
        .collect()
}

pub(super) fn fluctuating_large_body(start: u64, len: u64) -> BoxBody<Bytes, hyper::Error> {
    const PATTERN: [usize; 8] = [1, 7, 257, 1024, 4093, 8192, 17, 2048];
    const PAUSES_MS: [u64; 6] = [0, 2, 8, 1, 15, 3];

    let body_stream = stream::unfold(
        (0_u64, 0_usize, false),
        move |(written, pattern_idx, inserted_lull)| async move {
            if written >= len {
                return None;
            }

            let mut inserted_lull = inserted_lull;
            if !inserted_lull && written >= len / 2 {
                tokio::time::sleep(Duration::from_millis(180)).await;
                inserted_lull = true;
            }

            let chunk_len = PATTERN[pattern_idx % PATTERN.len()].min((len - written) as usize);
            let chunk = large_file_body(start + written, chunk_len as u64);
            let next_pattern_idx = pattern_idx + 1;
            let pause = PAUSES_MS[next_pattern_idx % PAUSES_MS.len()];
            if pause > 0 {
                tokio::time::sleep(Duration::from_millis(pause)).await;
            }

            Some((
                Ok::<_, Infallible>(Frame::data(Bytes::from(chunk))),
                (written + chunk_len as u64, next_pattern_idx, inserted_lull),
            ))
        },
    );

    BoxBody::new(StreamBody::new(body_stream).map_err(|err| match err {}))
}

pub(crate) fn large_file_byte_at(offset: u64) -> u8 {
    b'A' + (offset % 26) as u8
}

pub(super) fn full_body<T: Into<Bytes>>(body: T) -> BoxBody<Bytes, hyper::Error> {
    BoxBody::new(Full::new(body.into()).map_err(|e| match e {}))
}

pub(super) async fn handle_tcp_echo(mut stream: TcpStream) -> Result<()> {
    let mut buffer = vec![0u8; 8192];

    loop {
        let n = stream.read(&mut buffer).await?;
        if n == 0 {
            // 连接已关闭
            break;
        }

        // 回显数据
        stream.write_all(&buffer[..n]).await?;
        stream.flush().await?;
    }

    Ok(())
}
