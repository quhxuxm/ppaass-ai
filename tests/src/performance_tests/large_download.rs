use super::*;

pub async fn run_large_download_tests(
    agent_addr: &str,
    file_size_bytes: u64,
    chunk_size_bytes: u64,
    concurrency: usize,
    rounds: usize,
    connect_tunnel: bool,
) -> Result<LargeDownloadTestResults> {
    anyhow::ensure!(file_size_bytes > 0, "file size must be greater than 0");
    anyhow::ensure!(chunk_size_bytes > 0, "chunk size must be greater than 0");
    anyhow::ensure!(concurrency > 0, "concurrency must be greater than 0");
    anyhow::ensure!(rounds > 0, "rounds must be greater than 0");

    let target_authority = "127.0.0.1:9090";
    let target_path = format!("/large?size={file_size_bytes}");
    let target_url = if connect_tunnel {
        format!("CONNECT {target_authority}{target_path}")
    } else {
        format!("http://{target_authority}{target_path}")
    };
    info!("=== 开始 HTTP Range 分片大文件下载测试 ===");
    info!(
        "Agent：{}，URL：{}，file={} bytes，chunk={} bytes，并发分片：{}，轮次：{}，CONNECT tunnel={}",
        agent_addr,
        target_url,
        file_size_bytes,
        chunk_size_bytes,
        concurrency,
        rounds,
        connect_tunnel
    );

    let chunks_per_round = file_size_bytes.div_ceil(chunk_size_bytes);
    let total_chunks = chunks_per_round
        .checked_mul(rounds as u64)
        .context("large download chunk count overflow")?;
    anyhow::ensure!(
        total_chunks <= usize::MAX as u64,
        "large download chunk count is too large"
    );

    let mut chunks = Vec::with_capacity(total_chunks as usize);
    for _round in 0..rounds {
        for chunk_idx in 0..chunks_per_round {
            let start = chunk_idx * chunk_size_bytes;
            let end = (start + chunk_size_bytes - 1).min(file_size_bytes - 1);
            chunks.push(LargeDownloadChunk { start, end });
        }
    }

    let start_time = Instant::now();
    let histogram = Arc::new(Mutex::new(Histogram::<u64>::new(3).unwrap()));
    let success = Arc::new(AtomicUsize::new(0));
    let failed = Arc::new(AtomicUsize::new(0));
    let total_bytes = Arc::new(AtomicU64::new(0));
    let next_chunk = Arc::new(AtomicUsize::new(0));
    let chunks = Arc::new(chunks);

    let mut system = System::new_all();
    system.refresh_all();
    let initial_memory = system.used_memory();
    let peak_memory = Arc::new(AtomicU64::new(initial_memory));

    let mut handles = Vec::with_capacity(concurrency.min(chunks.len()));
    for worker_id in 0..concurrency.min(chunks.len()) {
        handles.push(tokio::spawn(large_download_worker(
            worker_id,
            agent_addr.to_string(),
            target_url.clone(),
            target_authority.to_string(),
            target_path.clone(),
            connect_tunnel,
            file_size_bytes,
            chunks.clone(),
            next_chunk.clone(),
            histogram.clone(),
            success.clone(),
            failed.clone(),
            total_bytes.clone(),
        )));
    }

    let peak_mem = peak_memory.clone();
    let monitor_handle = tokio::spawn(async move {
        let mut sys = System::new_all();
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            sys.refresh_all();
            peak_mem.fetch_max(sys.used_memory(), Ordering::Relaxed);
        }
    });

    for handle in handles {
        let _ = handle.await;
    }
    monitor_handle.abort();
    let _ = monitor_handle.await;

    let actual_duration = start_time.elapsed();
    let hist = histogram.lock().await;
    let succ = success.load(Ordering::Relaxed);
    let fail = failed.load(Ordering::Relaxed);
    let total = succ + fail;
    let downloaded = total_bytes.load(Ordering::Relaxed);
    let success_rate_percent = if total > 0 {
        (succ as f64 / total as f64) * 100.0
    } else {
        0.0
    };
    let chunks_per_second = total as f64 / actual_duration.as_secs_f64();
    let throughput_mbps = (downloaded as f64 * 8.0) / (actual_duration.as_secs_f64() * 1_000_000.0);

    system.refresh_all();
    let results = LargeDownloadTestResults {
        test_duration_secs: actual_duration.as_secs(),
        agent_addr: agent_addr.to_string(),
        target_url,
        file_size_bytes,
        chunk_size_bytes,
        concurrency,
        rounds,
        total_chunks: total,
        successful_chunks: succ,
        failed_chunks: fail,
        success_rate_percent,
        chunks_per_second,
        throughput_mbps,
        chunk_metrics: calculate_large_download_metrics(&hist, succ, fail, downloaded),
        system_metrics: SystemMetrics {
            cpu_usage_percent: system.global_cpu_usage(),
            memory_usage_mb: system.used_memory() / 1024 / 1024,
            peak_memory_mb: peak_memory.load(Ordering::Relaxed) / 1024 / 1024,
        },
    };

    info!("=== HTTP Range 分片大文件下载测试完成 ===");
    info!("总分片：{}，成功：{}，失败：{}", total, succ, fail);
    info!("成功率：{:.2}%", success_rate_percent);
    info!("Chunks/sec：{:.2}", chunks_per_second);
    info!("吞吐量：{:.2} Mbps", throughput_mbps);

    Ok(results)
}

#[derive(Clone, Copy)]
struct LargeDownloadChunk {
    start: u64,
    end: u64,
}

#[allow(clippy::too_many_arguments)]
async fn large_download_worker(
    worker_id: usize,
    agent_addr: String,
    target_url: String,
    target_authority: String,
    target_path: String,
    connect_tunnel: bool,
    file_size_bytes: u64,
    chunks: Arc<Vec<LargeDownloadChunk>>,
    next_chunk: Arc<AtomicUsize>,
    histogram: Arc<Mutex<Histogram<u64>>>,
    success: Arc<AtomicUsize>,
    failed: Arc<AtomicUsize>,
    total_bytes: Arc<AtomicU64>,
) {
    let client = MockHttpClient::new(agent_addr);
    let mut latencies_us = Vec::with_capacity(128);

    loop {
        let idx = next_chunk.fetch_add(1, Ordering::Relaxed);
        let Some(chunk) = chunks.get(idx).copied() else {
            break;
        };

        match download_large_range_chunk(
            &client,
            &target_url,
            &target_authority,
            &target_path,
            connect_tunnel,
            file_size_bytes,
            chunk,
        )
        .await
        {
            Ok((duration, bytes)) => {
                latencies_us.push(duration.as_micros() as u64);
                success.fetch_add(1, Ordering::Relaxed);
                total_bytes.fetch_add(bytes, Ordering::Relaxed);

                if latencies_us.len() >= 128 {
                    let mut hist = histogram.lock().await;
                    for latency in latencies_us.drain(..) {
                        let _ = hist.record(latency);
                    }
                }
            }
            Err(err) => {
                warn!(
                    "Large download worker {worker_id} 分片 {}-{} 失败：{err}",
                    chunk.start, chunk.end
                );
                failed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    if !latencies_us.is_empty() {
        let mut hist = histogram.lock().await;
        for latency in latencies_us {
            let _ = hist.record(latency);
        }
    }
}

async fn download_large_range_chunk(
    client: &MockHttpClient,
    target_url: &str,
    target_authority: &str,
    target_path: &str,
    connect_tunnel: bool,
    file_size_bytes: u64,
    chunk: LargeDownloadChunk,
) -> Result<(Duration, u64)> {
    let expected_len = chunk.end - chunk.start + 1;
    let range_header = format!("bytes={}-{}", chunk.start, chunk.end);
    let headers = [("Range", range_header)];

    let request = async {
        if connect_tunnel {
            client
                .connect_tunnel_get_bytes_with_headers(target_authority, target_path, &headers)
                .await
        } else {
            client.get_bytes_with_headers(target_url, &headers).await
        }
    };
    let (duration, status, response_headers, body) =
        tokio::time::timeout(LARGE_DOWNLOAD_CHUNK_TIMEOUT, request)
            .await
            .with_context(|| {
                format!(
                    "chunk request timeout after {:?}: range {}-{}",
                    LARGE_DOWNLOAD_CHUNK_TIMEOUT, chunk.start, chunk.end
                )
            })??;

    let actual_body_len = body.len() as u64;
    let content_length = response_headers
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .with_context(|| {
            format!(
                "missing or invalid content-length for range {}-{}",
                chunk.start, chunk.end
            )
        })?;

    anyhow::ensure!(
        content_length == expected_len,
        "content-length mismatch for range {}-{}: header {}, expected {}",
        chunk.start,
        chunk.end,
        content_length,
        expected_len
    );
    anyhow::ensure!(
        content_length == actual_body_len,
        "content-length/body mismatch for range {}-{}: header {}, body {}",
        chunk.start,
        chunk.end,
        content_length,
        actual_body_len
    );

    anyhow::ensure!(
        status == StatusCode::PARTIAL_CONTENT,
        "unexpected status {status}"
    );
    let expected_content_range = format!("bytes {}-{}/{}", chunk.start, chunk.end, file_size_bytes);
    let actual_content_range = response_headers
        .get(hyper::header::CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    anyhow::ensure!(
        actual_content_range == expected_content_range,
        "unexpected content-range: {actual_content_range}"
    );
    anyhow::ensure!(
        actual_body_len == expected_len,
        "unexpected body length: got {}, expected {}",
        actual_body_len,
        expected_len
    );

    if let Some((offset, byte)) = body.iter().enumerate().find(|(offset, byte)| {
        **byte != crate::mock_target::large_file_byte_at(chunk.start + *offset as u64)
    }) {
        anyhow::bail!(
            "body mismatch at absolute offset {}: got {}, expected {}",
            chunk.start + offset as u64,
            byte,
            crate::mock_target::large_file_byte_at(chunk.start + offset as u64)
        );
    }

    Ok((duration, actual_body_len))
}
