use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpPerformanceMode {
    Direct,
    Socks5Relay,
}

impl UdpPerformanceMode {
    pub fn name_zh(self) -> &'static str {
        match self {
            Self::Direct => "UDP 直连基线",
            Self::Socks5Relay => "SOCKS5 UDP Relay 端到端",
        }
    }
}

pub async fn run_udp_performance_tests(
    agent_addr: &str,
    target_host: &str,
    target_port: u16,
    concurrency: usize,
    duration_secs: u64,
    payload_size: usize,
) -> Result<UdpPerformanceTestResults> {
    run_udp_mode_performance_tests(
        UdpPerformanceMode::Socks5Relay,
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
pub async fn run_udp_mode_performance_tests(
    mode: UdpPerformanceMode,
    agent_addr: &str,
    target_host: &str,
    target_port: u16,
    concurrency: usize,
    duration_secs: u64,
    payload_size: usize,
) -> Result<UdpPerformanceTestResults> {
    info!("=== 开始 {} 性能测试 ===", mode.name_zh());
    info!(
        "Agent：{}，目标：{}:{}，并发 flow：{}，payload={} bytes，持续时间：{} 秒",
        agent_addr, target_host, target_port, concurrency, payload_size, duration_secs
    );

    let target_addr: SocketAddr = format!("{target_host}:{target_port}")
        .parse()
        .context("UDP target must be an IP socket address, e.g. 127.0.0.1:9092")?;
    let payload_size = payload_size.max(1);
    let start_time = Instant::now();
    let end_time = start_time + Duration::from_secs(duration_secs);

    // UDP RTT 通常可能低于 1ms，因此直方图内部使用微秒，报告时再转成毫秒。
    let udp_histogram = Arc::new(Mutex::new(Histogram::<u64>::new(3).unwrap()));
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
        let agent_addr = agent_addr.to_string();
        let hist = udp_histogram.clone();
        let success = success.clone();
        let failed = failed.clone();
        let uploaded = upload_bytes.clone();
        let downloaded = download_bytes.clone();

        handles.push(tokio::spawn(async move {
            udp_worker(
                worker_id,
                mode,
                agent_addr,
                target_addr,
                payload_size,
                end_time,
                hist,
                success,
                failed,
                uploaded,
                downloaded,
            )
            .await;
        }));
    }

    let peak_mem = peak_memory.clone();
    let monitor_handle = tokio::spawn(async move {
        let mut sys = System::new_all();
        while Instant::now() < end_time {
            tokio::time::sleep(Duration::from_secs(1)).await;
            sys.refresh_all();
            let current_mem = sys.used_memory();
            peak_mem.fetch_max(current_mem, Ordering::Relaxed);
        }
    });

    for handle in handles {
        let _ = handle.await;
    }
    let _ = monitor_handle.await;

    let actual_duration = start_time.elapsed();
    let udp_hist = udp_histogram.lock().await;
    let udp_succ = success.load(Ordering::Relaxed);
    let udp_fail = failed.load(Ordering::Relaxed);
    let uploaded = upload_bytes.load(Ordering::Relaxed);
    let downloaded = download_bytes.load(Ordering::Relaxed);
    let total_transferred = uploaded + downloaded;
    let peak_mem_val = peak_memory.load(Ordering::Relaxed);

    let udp_metrics = calculate_udp_metrics(&udp_hist, udp_succ, udp_fail, total_transferred);
    let total_datagrams = udp_succ + udp_fail;
    let packet_loss_percent = if total_datagrams > 0 {
        (udp_fail as f64 / total_datagrams as f64) * 100.0
    } else {
        0.0
    };
    let datagrams_per_second = total_datagrams as f64 / actual_duration.as_secs_f64();
    let seconds = actual_duration.as_secs_f64();
    let upload_throughput_mbps = (uploaded as f64 * 8.0) / (seconds * 1_000_000.0);
    let download_throughput_mbps = (downloaded as f64 * 8.0) / (seconds * 1_000_000.0);
    let throughput_mbps = upload_throughput_mbps + download_throughput_mbps;

    system.refresh_all();
    let cpu_usage = system.global_cpu_usage();
    let memory_usage_mb = system.used_memory() / 1024 / 1024;
    let peak_memory_mb = peak_mem_val / 1024 / 1024;

    let results = UdpPerformanceTestResults {
        test_duration_secs: actual_duration.as_secs(),
        agent_addr: agent_addr.to_string(),
        target_addr: target_addr.to_string(),
        concurrency,
        payload_size,
        total_datagrams,
        successful_datagrams: udp_succ,
        failed_datagrams: udp_fail,
        packet_loss_percent,
        datagrams_per_second,
        upload_bytes: uploaded,
        download_bytes: downloaded,
        upload_throughput_mbps,
        download_throughput_mbps,
        throughput_mbps,
        udp_metrics,
        system_metrics: SystemMetrics {
            cpu_usage_percent: cpu_usage,
            memory_usage_mb,
            peak_memory_mb,
        },
    };

    info!("=== {} 性能测试完成 ===", mode.name_zh());
    info!("总 UDP datagrams：{}", total_datagrams);
    info!("成功：{}，失败：{}", udp_succ, udp_fail);
    info!("丢包/失败率：{:.2}%", packet_loss_percent);
    info!("Datagrams/sec：{:.2}", datagrams_per_second);
    info!(
        "上行：{:.2} Mbps，下行：{:.2} Mbps，合计：{:.2} Mbps",
        upload_throughput_mbps, download_throughput_mbps, throughput_mbps
    );

    Ok(results)
}
#[allow(clippy::too_many_arguments)]
pub(super) async fn udp_worker(
    worker_id: usize,
    mode: UdpPerformanceMode,
    agent_addr: String,
    target_addr: SocketAddr,
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
        let datagram = match create_udp_channel(mode, &agent_addr).await {
            Ok(datagram) => datagram,
            Err(e) => {
                warn!(
                    "UDP worker {worker_id} 建立 {} 通道失败：{e}",
                    mode.name_zh()
                );
                failed.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        while Instant::now() < end_time {
            let payload = udp_payload(worker_id, sequence, payload_size);
            sequence = sequence.wrapping_add(1);
            let start = Instant::now();

            match datagram.send_to(&payload, target_addr).await {
                Ok(n) => {
                    upload_bytes.fetch_add(n as u64, Ordering::Relaxed);
                }
                Err(e) => {
                    warn!("UDP worker {worker_id} 发送失败：{e}");
                    failed.fetch_add(1, Ordering::Relaxed);
                    consecutive_failures += 1;
                    break;
                }
            }

            let mut buf = vec![0u8; payload_size.max(4096)];
            match tokio::time::timeout(Duration::from_secs(3), datagram.recv_from(&mut buf)).await {
                Ok(Ok(n)) if buf[..n] == payload => {
                    download_bytes.fetch_add(n as u64, Ordering::Relaxed);
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
                Ok(Ok(n)) => {
                    download_bytes.fetch_add(n as u64, Ordering::Relaxed);
                    warn!(
                        "UDP worker {worker_id} 回显不匹配：sent={} received={n}",
                        payload.len()
                    );
                    failed.fetch_add(1, Ordering::Relaxed);
                    consecutive_failures += 1;
                }
                Ok(Err(e)) => {
                    warn!("UDP worker {worker_id} 接收失败：{e}");
                    failed.fetch_add(1, Ordering::Relaxed);
                    consecutive_failures += 1;
                    break;
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
    }

    if !latencies_us.is_empty() {
        let mut hist = histogram.lock().await;
        for latency in latencies_us {
            let _ = hist.record(latency);
        }
    }
}

enum UdpChannel {
    Direct(UdpSocket),
    Socks5(async_socks5::SocksDatagram<TcpStream>),
}

impl UdpChannel {
    async fn send_to(&self, payload: &[u8], target: SocketAddr) -> Result<usize> {
        match self {
            Self::Direct(socket) => Ok(socket.send_to(payload, target).await?),
            Self::Socks5(datagram) => Ok(datagram.send_to(payload, target).await?),
        }
    }

    async fn recv_from(&self, payload: &mut [u8]) -> Result<usize> {
        match self {
            Self::Direct(socket) => Ok(socket.recv_from(payload).await?.0),
            Self::Socks5(datagram) => Ok(datagram.recv_from(payload).await?.0),
        }
    }
}

async fn create_udp_channel(mode: UdpPerformanceMode, agent_addr: &str) -> Result<UdpChannel> {
    match mode {
        UdpPerformanceMode::Direct => Ok(UdpChannel::Direct(
            UdpSocket::bind("0.0.0.0:0")
                .await
                .context("Failed to bind direct UDP performance socket")?,
        )),
        UdpPerformanceMode::Socks5Relay => Ok(UdpChannel::Socks5(
            create_socks_udp_datagram(agent_addr).await?,
        )),
    }
}

pub(super) async fn create_socks_udp_datagram(
    agent_addr: &str,
) -> Result<async_socks5::SocksDatagram<TcpStream>> {
    let stream = connect_to_agent_with_retry(
        agent_addr,
        "Failed to connect to agent for UDP performance test",
    )
    .await?;
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("Failed to bind local UDP socket for UDP performance test")?;
    async_socks5::SocksDatagram::associate(stream, socket, None, None::<SocketAddr>)
        .await
        .context("Failed to associate via SOCKS5 for UDP performance test")
}

pub(super) fn udp_payload(worker_id: usize, sequence: u64, payload_size: usize) -> Vec<u8> {
    let mut payload = vec![0u8; payload_size];
    let worker = worker_id as u64;
    for (offset, byte) in worker.to_be_bytes().iter().enumerate().take(payload.len()) {
        payload[offset] = *byte;
    }
    for (offset, byte) in sequence
        .to_be_bytes()
        .iter()
        .enumerate()
        .take(payload.len().saturating_sub(8))
    {
        payload[offset + 8] = *byte;
    }
    for (idx, byte) in payload.iter_mut().enumerate().skip(16) {
        *byte = (idx as u8).wrapping_add(worker_id as u8);
    }
    payload
}
