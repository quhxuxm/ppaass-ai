use super::*;

pub(super) async fn run_concurrent_segment_size_regression(agent_addr: &str) -> Result<()> {
    tokio::time::timeout(BROWSER_LIKE_TIMEOUT, async {
        let file_size = 32 * 1024 * 1024_u64;
        let cases = [
            (RangeProtocol::Http, RangeEndpoint::Fluctuating, 13, 512),
            (
                RangeProtocol::Connect,
                RangeEndpoint::Fluctuating,
                4099,
                1024,
            ),
            (
                RangeProtocol::Socks5,
                RangeEndpoint::Fluctuating,
                16387,
                4096,
            ),
            (RangeProtocol::Http, RangeEndpoint::Fluctuating, 32771, 8192),
            (
                RangeProtocol::Http,
                RangeEndpoint::Large,
                1024 * 1024 + 17,
                512 * 1024,
            ),
            (
                RangeProtocol::Connect,
                RangeEndpoint::Large,
                3 * 1024 * 1024 + 33,
                1024 * 1024,
            ),
            (
                RangeProtocol::Socks5,
                RangeEndpoint::Large,
                6 * 1024 * 1024 + 65,
                2 * 1024 * 1024,
            ),
        ];

        let mut handles = Vec::with_capacity(cases.len());
        for (idx, (protocol, endpoint, range_start, len)) in cases.into_iter().enumerate() {
            let agent_addr = agent_addr.to_string();
            handles.push(tokio::spawn(async move {
                let range_end = range_start + len - 1;
                verify_segment_size_case(
                    &agent_addr,
                    protocol,
                    endpoint,
                    file_size,
                    range_start,
                    range_end,
                )
                .await
                .with_context(|| {
                    format!("segment size case {idx} failed for range {range_start}-{range_end}")
                })
            }));
        }

        let mut errors = Vec::new();
        for handle in handles {
            match handle.await.context("segment size task panicked")? {
                Ok(()) => {}
                Err(err) => errors.push(err.to_string()),
            }
        }

        anyhow::ensure!(
            errors.is_empty(),
            "并发大/小分片长度校验失败：{}",
            errors.join("; ")
        );
        Ok(())
    })
    .await
    .context("concurrent segment size regression timed out")?
}

pub(super) async fn verify_h2_multiplexed_range_sequence(
    stream: TcpStream,
    label: &'static str,
    count: u64,
    file_size: u64,
    chunk_size: u64,
) -> Result<()> {
    let io = TokioIo::new(stream);
    let (sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .context("HTTP/2 client handshake failed")?;
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut handles = Vec::with_capacity(count as usize);
    for idx in 0..count {
        let mut sender = sender.clone();
        handles.push(tokio::spawn(async move {
            let range_start = idx * chunk_size + (idx % 23);
            let range_end = range_start + chunk_size - 1;
            let request = Request::builder()
                .uri(format!("/fluctuating-large?size={file_size}"))
                .header(hyper::header::HOST, "127.0.0.1:9093")
                .header(
                    hyper::header::RANGE,
                    format!("bytes={range_start}-{range_end}"),
                )
                .body(Empty::<Bytes>::new())
                .context("failed to build HTTP/2 range request")?;
            let response = sender
                .send_request(request)
                .await
                .with_context(|| format!("{label} request {idx} failed"))?;
            let status = response.status();
            let headers = response.headers().clone();
            let body = response
                .collect()
                .await
                .with_context(|| format!("{label} response {idx} collect failed"))?
                .to_bytes();

            verify_large_range_response(
                label,
                file_size,
                range_start,
                range_end,
                status,
                &headers,
                &body,
            )
        }));
    }

    let mut errors = Vec::new();
    for handle in handles {
        match handle.await.context("HTTP/2 range task panicked")? {
            Ok(()) => {}
            Err(err) => errors.push(err.to_string()),
        }
    }

    drop(sender);
    let _ = tokio::time::timeout(Duration::from_secs(2), conn_task).await;

    anyhow::ensure!(
        errors.is_empty(),
        "{label} 分片校验失败：{}",
        errors.join("; ")
    );
    Ok(())
}

pub(super) async fn verify_segment_size_case(
    agent_addr: &str,
    protocol: RangeProtocol,
    endpoint: RangeEndpoint,
    file_size: u64,
    range_start: u64,
    range_end: u64,
) -> Result<()> {
    match (protocol, endpoint) {
        (RangeProtocol::Http, RangeEndpoint::Fluctuating) => {
            verify_fluctuating_http_range_chunk(
                agent_addr,
                "127.0.0.1:9090",
                file_size,
                range_start,
                range_end,
            )
            .await
        }
        (RangeProtocol::Connect, RangeEndpoint::Fluctuating) => {
            verify_fluctuating_connect_range_chunk(
                agent_addr,
                "127.0.0.1:9090",
                file_size,
                range_start,
                range_end,
            )
            .await
        }
        (RangeProtocol::Socks5, RangeEndpoint::Fluctuating) => {
            verify_fluctuating_socks5_range_chunk(
                agent_addr,
                "127.0.0.1:9090",
                file_size,
                range_start,
                range_end,
            )
            .await
        }
        (RangeProtocol::Http, RangeEndpoint::Large) => {
            verify_http_range_chunk(agent_addr, file_size, range_start, range_end).await
        }
        (RangeProtocol::Connect, RangeEndpoint::Large) => {
            verify_connect_range_chunk(agent_addr, file_size, range_start, range_end).await
        }
        (RangeProtocol::Socks5, RangeEndpoint::Large) => {
            verify_socks5_large_range_chunk(agent_addr, file_size, range_start, range_end).await
        }
    }
}
