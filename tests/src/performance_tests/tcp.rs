use super::*;
use crate::mock_client::read_connect_response;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpPerformanceMode {
    Direct,
    Tun,
    HttpConnect,
    Socks5,
}

impl TcpPerformanceMode {
    pub fn name_zh(self) -> &'static str {
        match self {
            Self::Direct => "TCP 直连基线",
            Self::Tun => "TUN TCP 端到端",
            Self::HttpConnect => "HTTP CONNECT 端到端",
            Self::Socks5 => "SOCKS5 TCP 端到端",
        }
    }
}

pub async fn run_tcp_performance_tests(
    agent_addr: &str,
    target_host: &str,
    target_port: u16,
    concurrency: usize,
    duration_secs: u64,
    payload_size: usize,
) -> Result<TcpPerformanceTestResults> {
    run_tcp_mode_performance_tests(
        TcpPerformanceMode::Socks5,
        agent_addr,
        target_host,
        target_port,
        concurrency,
        duration_secs,
        payload_size,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn run_tcp_mode_performance_tests(
    mode: TcpPerformanceMode,
    agent_addr: &str,
    target_host: &str,
    target_port: u16,
    concurrency: usize,
    duration_secs: u64,
    payload_size: usize,
) -> Result<TcpPerformanceTestResults> {
    let target_host = target_host.trim();
    anyhow::ensure!(!target_host.is_empty(), "TCP target host must not be empty");
    anyhow::ensure!(concurrency > 0, "TCP concurrency must be greater than zero");
    anyhow::ensure!(
        duration_secs > 0,
        "TCP test duration must be greater than zero"
    );

    info!("=== 开始 {} 性能测试 ===", mode.name_zh());
    info!(
        "Agent：{}，目标：{}:{}，并发连接：{}，payload={} bytes，持续时间：{} 秒",
        agent_addr, target_host, target_port, concurrency, payload_size, duration_secs
    );

    let payload_size = payload_size.max(1);
    let start_time = Instant::now();
    let end_time = start_time + Duration::from_secs(duration_secs);

    // TCP RTT 同样使用微秒记录，避免本机/局域网测试时被毫秒精度吞掉差异。
    let tcp_histogram = Arc::new(Mutex::new(Histogram::<u64>::new(3).unwrap()));
    let success = Arc::new(AtomicUsize::new(0));
    let failed = Arc::new(AtomicUsize::new(0));
    let upload_bytes = Arc::new(AtomicU64::new(0));
    let download_bytes = Arc::new(AtomicU64::new(0));

    let mut system = System::new_all();
    system.refresh_all();
    let initial_memory = system.used_memory();
    let peak_memory = Arc::new(AtomicU64::new(initial_memory));

    let mut handles = Vec::with_capacity(concurrency);
    for worker_id in 0..concurrency {
        handles.push(tokio::spawn(tcp_worker(
            worker_id,
            mode,
            agent_addr.to_string(),
            target_host.to_string(),
            target_port,
            payload_size,
            end_time,
            tcp_histogram.clone(),
            success.clone(),
            failed.clone(),
            upload_bytes.clone(),
            download_bytes.clone(),
        )));
    }

    let peak_mem = peak_memory.clone();
    let monitor_handle = tokio::spawn(async move {
        let mut sys = System::new_all();
        while Instant::now() < end_time {
            tokio::time::sleep(Duration::from_secs(1)).await;
            sys.refresh_all();
            peak_mem.fetch_max(sys.used_memory(), Ordering::Relaxed);
        }
    });

    for handle in handles {
        let _ = handle.await;
    }
    let _ = monitor_handle.await;

    let actual_duration = start_time.elapsed();
    let tcp_hist = tcp_histogram.lock().await;
    let tcp_succ = success.load(Ordering::Relaxed);
    let tcp_fail = failed.load(Ordering::Relaxed);
    let uploaded = upload_bytes.load(Ordering::Relaxed);
    let downloaded = download_bytes.load(Ordering::Relaxed);
    let total_transferred = uploaded + downloaded;
    let peak_mem_val = peak_memory.load(Ordering::Relaxed);

    let tcp_metrics = calculate_tcp_metrics(&tcp_hist, tcp_succ, tcp_fail, total_transferred);
    let total_chunks = tcp_succ + tcp_fail;
    let failure_rate_percent = if total_chunks > 0 {
        (tcp_fail as f64 / total_chunks as f64) * 100.0
    } else {
        0.0
    };
    let chunks_per_second = total_chunks as f64 / actual_duration.as_secs_f64();
    let seconds = actual_duration.as_secs_f64();
    let upload_throughput_mbps = (uploaded as f64 * 8.0) / (seconds * 1_000_000.0);
    let download_throughput_mbps = (downloaded as f64 * 8.0) / (seconds * 1_000_000.0);
    let throughput_mbps = upload_throughput_mbps + download_throughput_mbps;

    system.refresh_all();
    let cpu_usage = system.global_cpu_usage();
    let memory_usage_mb = system.used_memory() / 1024 / 1024;
    let peak_memory_mb = peak_mem_val / 1024 / 1024;

    let results = TcpPerformanceTestResults {
        test_duration_secs: actual_duration.as_secs(),
        agent_addr: agent_addr.to_string(),
        target_host: target_host.to_string(),
        target_port,
        concurrency,
        payload_size,
        total_chunks,
        successful_chunks: tcp_succ,
        failed_chunks: tcp_fail,
        failure_rate_percent,
        chunks_per_second,
        upload_bytes: uploaded,
        download_bytes: downloaded,
        upload_throughput_mbps,
        download_throughput_mbps,
        throughput_mbps,
        tcp_metrics,
        system_metrics: SystemMetrics {
            cpu_usage_percent: cpu_usage,
            memory_usage_mb,
            peak_memory_mb,
        },
    };

    info!("=== {} 性能测试完成 ===", mode.name_zh());
    info!("总 TCP chunks：{}", total_chunks);
    info!("成功：{}，失败：{}", tcp_succ, tcp_fail);
    info!("失败率：{:.2}%", failure_rate_percent);
    info!("Chunks/sec：{:.2}", chunks_per_second);
    info!(
        "上行：{:.2} Mbps，下行：{:.2} Mbps，合计：{:.2} Mbps",
        upload_throughput_mbps, download_throughput_mbps, throughput_mbps
    );

    Ok(results)
}
#[allow(clippy::too_many_arguments)]
pub(super) async fn tcp_worker(
    worker_id: usize,
    mode: TcpPerformanceMode,
    agent_addr: String,
    target_host: String,
    target_port: u16,
    payload_size: usize,
    end_time: Instant,
    histogram: Arc<Mutex<Histogram<u64>>>,
    success: Arc<AtomicUsize>,
    failed: Arc<AtomicUsize>,
    upload_bytes: Arc<AtomicU64>,
    download_bytes: Arc<AtomicU64>,
) {
    let mut consecutive_failures = 0usize;
    let mut latencies_us = Vec::with_capacity(256);
    let mut sequence = 0u64;

    while Instant::now() < end_time {
        let mut stream = match create_tcp_stream(mode, &agent_addr, &target_host, target_port).await
        {
            Ok(stream) => stream,
            Err(e) => {
                warn!(
                    "TCP worker {worker_id} 建立 {} 连接失败：{e}",
                    mode.name_zh()
                );
                failed.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        while Instant::now() < end_time {
            let payload = tcp_payload(worker_id, sequence, payload_size);
            let mut response = vec![0u8; payload.len()];
            sequence = sequence.wrapping_add(1);
            let start = Instant::now();

            if let Err(e) = stream.write_all(&payload).await {
                warn!("TCP worker {worker_id} 发送失败：{e}");
                failed.fetch_add(1, Ordering::Relaxed);
                consecutive_failures += 1;
                break;
            }
            upload_bytes.fetch_add(payload.len() as u64, Ordering::Relaxed);

            if let Err(e) = stream.flush().await {
                warn!("TCP worker {worker_id} flush 失败：{e}");
                failed.fetch_add(1, Ordering::Relaxed);
                consecutive_failures += 1;
                break;
            }

            match tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut response))
                .await
            {
                Ok(Ok(_)) if response == payload => {
                    download_bytes.fetch_add(response.len() as u64, Ordering::Relaxed);
                    latencies_us.push(start.elapsed().as_micros() as u64);
                    success.fetch_add(1, Ordering::Relaxed);
                    consecutive_failures = 0;

                    if latencies_us.len() >= 256 {
                        let mut hist = histogram.lock().await;
                        for latency in latencies_us.drain(..) {
                            let _ = hist.record(latency);
                        }
                    }
                }
                Ok(Ok(_)) => {
                    download_bytes.fetch_add(response.len() as u64, Ordering::Relaxed);
                    warn!(
                        "TCP worker {worker_id} 回显不匹配：sent={} received={}",
                        payload.len(),
                        response.len()
                    );
                    failed.fetch_add(1, Ordering::Relaxed);
                    consecutive_failures += 1;
                }
                Ok(Err(e)) => {
                    warn!("TCP worker {worker_id} 接收失败：{e}");
                    failed.fetch_add(1, Ordering::Relaxed);
                    consecutive_failures += 1;
                    break;
                }
                Err(_) => {
                    warn!("TCP worker {worker_id} 接收超时");
                    failed.fetch_add(1, Ordering::Relaxed);
                    consecutive_failures += 1;
                    break;
                }
            }

            if consecutive_failures > 0 {
                let delay_ms = std::cmp::min(200, consecutive_failures * 20) as u64;
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
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

async fn create_tcp_stream(
    mode: TcpPerformanceMode,
    agent_addr: &str,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream> {
    match mode {
        TcpPerformanceMode::Direct | TcpPerformanceMode::Tun => {
            let target = format!("{target_host}:{target_port}");
            common::connect_tcp_happy_eyeballs(&target, |_, _| Ok(()))
                .await
                .with_context(|| format!("Failed to connect directly to {target}"))
        }
        TcpPerformanceMode::HttpConnect => {
            create_http_connect_stream(agent_addr, target_host, target_port).await
        }
        TcpPerformanceMode::Socks5 => {
            create_socks_tcp_stream(agent_addr, target_host, target_port).await
        }
    }
}

async fn create_http_connect_stream(
    agent_addr: &str,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream> {
    let mut stream = connect_to_agent_with_retry(
        agent_addr,
        "Failed to connect to agent for HTTP CONNECT performance test",
    )
    .await?;
    let authority = format!("{target_host}:{target_port}");
    let request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: keep-alive\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    read_connect_response(&mut stream).await?;
    Ok(stream)
}

pub(super) async fn create_socks_tcp_stream(
    agent_addr: &str,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream> {
    let mut stream = connect_to_agent_with_retry(
        agent_addr,
        "Failed to connect to agent for TCP performance test",
    )
    .await?;
    async_socks5::connect(&mut stream, (target_host.to_string(), target_port), None)
        .await
        .context("Failed to connect via SOCKS5 for TCP performance test")?;
    Ok(stream)
}

pub(super) fn tcp_payload(worker_id: usize, sequence: u64, payload_size: usize) -> Vec<u8> {
    // TCP 压测只关心端到端字节完整性，payload 复用 UDP 的确定性模式；
    // worker/sequence 前缀能帮助定位并发场景下的回显错配。
    udp_payload(worker_id, sequence, payload_size)
}
