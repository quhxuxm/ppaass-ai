use super::*;

pub async fn run_quic_probe_tests(
    agent_addr: &str,
    target_host: &str,
    target_port: u16,
    attempts: usize,
    timeout_ms: u64,
) -> Result<QuicProbeTestResults> {
    info!("=== 开始 QUIC Version Negotiation 探针 ===");
    info!(
        "Agent：{}，目标：{}:{}，attempts={}，timeout={}ms",
        agent_addr, target_host, target_port, attempts, timeout_ms
    );

    let start_time = Instant::now();
    let histogram = Arc::new(Mutex::new(Histogram::<u64>::new(3).unwrap()));
    let success = Arc::new(AtomicUsize::new(0));
    let failed = Arc::new(AtomicUsize::new(0));
    let total_bytes = Arc::new(AtomicU64::new(0));
    let versions = Arc::new(Mutex::new(BTreeSet::<String>::new()));
    let target = socks_udp_target(target_host, target_port)?;

    quic_probe_worker(
        0,
        agent_addr.to_string(),
        target,
        QuicProbeStop::Attempts(attempts),
        Duration::from_millis(timeout_ms.max(1)),
        histogram.clone(),
        success.clone(),
        failed.clone(),
        total_bytes.clone(),
        versions.clone(),
    )
    .await;

    let mut system = System::new_all();
    system.refresh_all();
    build_quic_results(
        "probe",
        start_time,
        agent_addr,
        target_host,
        target_port,
        1,
        Some(attempts),
        histogram,
        success,
        failed,
        total_bytes,
        versions,
        system.global_cpu_usage(),
        system.used_memory() / 1024 / 1024,
        system.used_memory() / 1024 / 1024,
    )
    .await
}

pub async fn run_quic_performance_tests(
    agent_addr: &str,
    target_host: &str,
    target_port: u16,
    concurrency: usize,
    duration_secs: u64,
    timeout_ms: u64,
) -> Result<QuicProbeTestResults> {
    info!("=== 开始 QUIC UDP/443 专项压测 ===");
    info!(
        "Agent：{}，目标：{}:{}，并发 flow：{}，持续时间：{} 秒，timeout={}ms",
        agent_addr, target_host, target_port, concurrency, duration_secs, timeout_ms
    );

    let start_time = Instant::now();
    let end_time = start_time + Duration::from_secs(duration_secs);
    let histogram = Arc::new(Mutex::new(Histogram::<u64>::new(3).unwrap()));
    let success = Arc::new(AtomicUsize::new(0));
    let failed = Arc::new(AtomicUsize::new(0));
    let total_bytes = Arc::new(AtomicU64::new(0));
    let versions = Arc::new(Mutex::new(BTreeSet::<String>::new()));
    let target = socks_udp_target(target_host, target_port)?;

    let mut system = System::new_all();
    system.refresh_all();
    let initial_memory = system.used_memory();
    let peak_memory = Arc::new(AtomicU64::new(initial_memory));

    let mut handles = Vec::with_capacity(concurrency);
    for worker_id in 0..concurrency {
        handles.push(tokio::spawn(quic_probe_worker(
            worker_id,
            agent_addr.to_string(),
            target.clone(),
            QuicProbeStop::Deadline(end_time),
            Duration::from_millis(timeout_ms.max(1)),
            histogram.clone(),
            success.clone(),
            failed.clone(),
            total_bytes.clone(),
            versions.clone(),
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

    system.refresh_all();
    build_quic_results(
        "performance",
        start_time,
        agent_addr,
        target_host,
        target_port,
        concurrency,
        None,
        histogram,
        success,
        failed,
        total_bytes,
        versions,
        system.global_cpu_usage(),
        system.used_memory() / 1024 / 1024,
        peak_memory.load(Ordering::Relaxed) / 1024 / 1024,
    )
    .await
}

#[derive(Clone, Copy)]
enum QuicProbeStop {
    Attempts(usize),
    Deadline(Instant),
}

impl QuicProbeStop {
    fn should_continue(self, sequence: u64) -> bool {
        match self {
            Self::Attempts(attempts) => (sequence as usize) < attempts,
            Self::Deadline(deadline) => Instant::now() < deadline,
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn quic_probe_worker(
    worker_id: usize,
    agent_addr: String,
    target: async_socks5::AddrKind,
    stop: QuicProbeStop,
    timeout_duration: Duration,
    histogram: Arc<Mutex<Histogram<u64>>>,
    success: Arc<AtomicUsize>,
    failed: Arc<AtomicUsize>,
    total_bytes: Arc<AtomicU64>,
    versions: Arc<Mutex<BTreeSet<String>>>,
) {
    let mut datagram = None;
    let mut latencies_us = Vec::with_capacity(128);
    let mut consecutive_failures = 0usize;
    let mut sequence = 0u64;

    while stop.should_continue(sequence) {
        if datagram.is_none() {
            match create_socks_udp_datagram(&agent_addr).await {
                Ok(next) => datagram = Some(next),
                Err(e) => {
                    warn!("QUIC worker {worker_id} 建立 SOCKS5 UDP associate 失败：{e}");
                    failed.fetch_add(1, Ordering::Relaxed);
                    sequence = sequence.wrapping_add(1);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            }
        }

        let probe = quic_version_negotiation_probe(worker_id, sequence, 1200);
        sequence = sequence.wrapping_add(1);
        total_bytes.fetch_add(probe.len() as u64, Ordering::Relaxed);
        let start = Instant::now();
        let datagram_ref = datagram.as_ref().expect("datagram is initialized above");

        if let Err(e) = datagram_ref.send_to(&probe, target.clone()).await {
            warn!("QUIC worker {worker_id} 发送 UDP/443 探针失败：{e}");
            failed.fetch_add(1, Ordering::Relaxed);
            consecutive_failures += 1;
            datagram = None;
            continue;
        }

        let mut buf = vec![0u8; 2048];
        match tokio::time::timeout(timeout_duration, datagram_ref.recv_from(&mut buf)).await {
            Ok(Ok((n, _src))) => {
                total_bytes.fetch_add(n as u64, Ordering::Relaxed);
                if let Some(parsed_versions) = parse_quic_version_negotiation_response(&buf[..n]) {
                    latencies_us.push(start.elapsed().as_micros() as u64);
                    success.fetch_add(1, Ordering::Relaxed);
                    consecutive_failures = 0;

                    if !parsed_versions.is_empty() {
                        let mut version_set = versions.lock().await;
                        for version in parsed_versions {
                            version_set.insert(format_quic_version(version));
                        }
                    }

                    if latencies_us.len() >= 128 {
                        let mut hist = histogram.lock().await;
                        for latency in latencies_us.drain(..) {
                            let _ = hist.record(latency);
                        }
                    }
                } else {
                    failed.fetch_add(1, Ordering::Relaxed);
                    consecutive_failures += 1;
                }
            }
            Ok(Err(e)) => {
                warn!("QUIC worker {worker_id} 接收 UDP/443 回复失败：{e}");
                failed.fetch_add(1, Ordering::Relaxed);
                consecutive_failures += 1;
                datagram = None;
            }
            Err(_) => {
                failed.fetch_add(1, Ordering::Relaxed);
                consecutive_failures += 1;
            }
        }

        if consecutive_failures > 0 {
            let delay_ms = std::cmp::min(200, consecutive_failures * 20) as u64;
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }
    }

    if !latencies_us.is_empty() {
        let mut hist = histogram.lock().await;
        for latency in latencies_us {
            let _ = hist.record(latency);
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn build_quic_results(
    test_mode: &str,
    start_time: Instant,
    agent_addr: &str,
    target_host: &str,
    target_port: u16,
    concurrency: usize,
    configured_attempts: Option<usize>,
    histogram: Arc<Mutex<Histogram<u64>>>,
    success: Arc<AtomicUsize>,
    failed: Arc<AtomicUsize>,
    total_bytes: Arc<AtomicU64>,
    versions: Arc<Mutex<BTreeSet<String>>>,
    cpu_usage_percent: f32,
    memory_usage_mb: u64,
    peak_memory_mb: u64,
) -> Result<QuicProbeTestResults> {
    let actual_duration = start_time.elapsed();
    let hist = histogram.lock().await;
    let succ = success.load(Ordering::Relaxed);
    let fail = failed.load(Ordering::Relaxed);
    let total = succ + fail;
    let total_transferred = total_bytes.load(Ordering::Relaxed);
    let response_rate_percent = if total > 0 {
        (succ as f64 / total as f64) * 100.0
    } else {
        0.0
    };
    let probes_per_second = total as f64 / actual_duration.as_secs_f64();
    let throughput_mbps =
        (total_transferred as f64 * 8.0) / (actual_duration.as_secs_f64() * 1_000_000.0);
    let quic_metrics = calculate_quic_metrics(&hist, succ, fail, total_transferred);
    let supported_versions = versions.lock().await.iter().cloned().collect::<Vec<_>>();

    info!("=== QUIC {} 测试完成 ===", test_mode);
    info!("总探针：{}，VN 成功：{}，失败：{}", total, succ, fail);
    info!("VN 响应率：{:.2}%", response_rate_percent);
    info!("探针速率：{:.2}/s", probes_per_second);

    Ok(QuicProbeTestResults {
        test_mode: test_mode.to_string(),
        test_duration_secs: actual_duration.as_secs(),
        agent_addr: agent_addr.to_string(),
        target_host: target_host.to_string(),
        target_port,
        concurrency,
        configured_attempts,
        total_probes: total,
        successful_vn_responses: succ,
        failed_probes: fail,
        response_rate_percent,
        probes_per_second,
        throughput_mbps,
        supported_versions,
        quic_metrics,
        system_metrics: SystemMetrics {
            cpu_usage_percent,
            memory_usage_mb,
            peak_memory_mb,
        },
    })
}
