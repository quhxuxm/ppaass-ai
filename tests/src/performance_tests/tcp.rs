use super::*;

pub async fn run_tcp_performance_tests(
    agent_addr: &str,
    target_host: &str,
    target_port: u16,
    concurrency: usize,
    duration_secs: u64,
    payload_size: usize,
) -> Result<TcpPerformanceTestResults> {
    let target_host = target_host.trim();
    anyhow::ensure!(!target_host.is_empty(), "TCP target host must not be empty");

    info!("=== 开始 TCP 专项性能测试 ===");
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
    let total_bytes = Arc::new(AtomicU64::new(0));

    let mut system = System::new_all();
    system.refresh_all();
    let initial_memory = system.used_memory();
    let peak_memory = Arc::new(AtomicU64::new(initial_memory));

    let mut handles = Vec::with_capacity(concurrency);
    for worker_id in 0..concurrency {
        handles.push(tokio::spawn(tcp_worker(
            worker_id,
            agent_addr.to_string(),
            target_host.to_string(),
            target_port,
            payload_size,
            end_time,
            tcp_histogram.clone(),
            success.clone(),
            failed.clone(),
            total_bytes.clone(),
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
    let total_transferred = total_bytes.load(Ordering::Relaxed);
    let peak_mem_val = peak_memory.load(Ordering::Relaxed);

    let tcp_metrics = calculate_tcp_metrics(&tcp_hist, tcp_succ, tcp_fail, total_transferred);
    let total_chunks = tcp_succ + tcp_fail;
    let failure_rate_percent = if total_chunks > 0 {
        (tcp_fail as f64 / total_chunks as f64) * 100.0
    } else {
        0.0
    };
    let chunks_per_second = total_chunks as f64 / actual_duration.as_secs_f64();
    let throughput_mbps =
        (total_transferred as f64 * 8.0) / (actual_duration.as_secs_f64() * 1_000_000.0);

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
        throughput_mbps,
        tcp_metrics,
        system_metrics: SystemMetrics {
            cpu_usage_percent: cpu_usage,
            memory_usage_mb,
            peak_memory_mb,
        },
    };

    info!("=== TCP 专项性能测试完成 ===");
    info!("总 TCP chunks：{}", total_chunks);
    info!("成功：{}，失败：{}", tcp_succ, tcp_fail);
    info!("失败率：{:.2}%", failure_rate_percent);
    info!("Chunks/sec：{:.2}", chunks_per_second);
    info!("吞吐量：{:.2} Mbps", throughput_mbps);

    Ok(results)
}
#[allow(clippy::too_many_arguments)]
pub(super) async fn tcp_worker(
    worker_id: usize,
    agent_addr: String,
    target_host: String,
    target_port: u16,
    payload_size: usize,
    end_time: Instant,
    histogram: Arc<Mutex<Histogram<u64>>>,
    success: Arc<AtomicUsize>,
    failed: Arc<AtomicUsize>,
    total_bytes: Arc<AtomicU64>,
) {
    let mut consecutive_failures = 0usize;
    let mut latencies_us = Vec::with_capacity(256);
    let mut sequence = 0u64;

    while Instant::now() < end_time {
        let mut stream = match create_socks_tcp_stream(&agent_addr, &target_host, target_port).await
        {
            Ok(stream) => stream,
            Err(e) => {
                warn!("TCP worker {worker_id} 建立 SOCKS5 CONNECT 失败：{e}");
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
                    latencies_us.push(start.elapsed().as_micros() as u64);
                    success.fetch_add(1, Ordering::Relaxed);
                    total_bytes.fetch_add((payload.len() * 2) as u64, Ordering::Relaxed);
                    consecutive_failures = 0;

                    if latencies_us.len() >= 256 {
                        let mut hist = histogram.lock().await;
                        for latency in latencies_us.drain(..) {
                            let _ = hist.record(latency);
                        }
                    }
                }
                Ok(Ok(_)) => {
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
