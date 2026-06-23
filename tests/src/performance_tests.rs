use crate::mock_client::{MockHttpClient, MockSocks5Client};
use anyhow::{Context, Result};
use hdrhistogram::Histogram;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use sysinfo::System;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Mutex, Semaphore};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceTestResults {
    pub test_duration_secs: u64,
    pub total_requests: usize,
    pub successful_requests: usize,
    pub failed_requests: usize,
    pub requests_per_second: f64,
    pub throughput_mbps: f64,
    pub http_metrics: RequestMetrics,
    pub socks5_metrics: RequestMetrics,
    pub system_metrics: SystemMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMetrics {
    pub total_requests: usize,
    pub successful: usize,
    pub failed: usize,
    pub avg_latency_ms: f64,
    pub min_latency_ms: f64,
    pub max_latency_ms: f64,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub total_bytes_transferred: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub cpu_usage_percent: f32,
    pub memory_usage_mb: u64,
    pub peak_memory_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpPerformanceTestResults {
    pub test_duration_secs: u64,
    pub agent_addr: String,
    pub target_addr: String,
    pub concurrency: usize,
    pub payload_size: usize,
    pub total_datagrams: usize,
    pub successful_datagrams: usize,
    pub failed_datagrams: usize,
    pub packet_loss_percent: f64,
    pub datagrams_per_second: f64,
    pub throughput_mbps: f64,
    pub udp_metrics: UdpDatagramMetrics,
    pub system_metrics: SystemMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpDatagramMetrics {
    pub total_datagrams: usize,
    pub successful: usize,
    pub failed: usize,
    pub avg_rtt_ms: f64,
    pub min_rtt_ms: f64,
    pub max_rtt_ms: f64,
    pub p50_rtt_ms: f64,
    pub p95_rtt_ms: f64,
    pub p99_rtt_ms: f64,
    pub total_bytes_transferred: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpPerformanceTestResults {
    pub test_duration_secs: u64,
    pub agent_addr: String,
    pub target_host: String,
    pub target_port: u16,
    pub concurrency: usize,
    pub payload_size: usize,
    pub total_chunks: usize,
    pub successful_chunks: usize,
    pub failed_chunks: usize,
    pub failure_rate_percent: f64,
    pub chunks_per_second: f64,
    pub throughput_mbps: f64,
    pub tcp_metrics: TcpTransferMetrics,
    pub system_metrics: SystemMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpTransferMetrics {
    pub total_chunks: usize,
    pub successful: usize,
    pub failed: usize,
    pub avg_rtt_ms: f64,
    pub min_rtt_ms: f64,
    pub max_rtt_ms: f64,
    pub p50_rtt_ms: f64,
    pub p95_rtt_ms: f64,
    pub p99_rtt_ms: f64,
    pub total_bytes_transferred: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicProbeTestResults {
    pub test_mode: String,
    pub test_duration_secs: u64,
    pub agent_addr: String,
    pub target_host: String,
    pub target_port: u16,
    pub concurrency: usize,
    pub configured_attempts: Option<usize>,
    pub total_probes: usize,
    pub successful_vn_responses: usize,
    pub failed_probes: usize,
    pub response_rate_percent: f64,
    pub probes_per_second: f64,
    pub throughput_mbps: f64,
    pub supported_versions: Vec<String>,
    pub quic_metrics: QuicProbeMetrics,
    pub system_metrics: SystemMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicProbeMetrics {
    pub total_probes: usize,
    pub successful_vn_responses: usize,
    pub failed_probes: usize,
    pub avg_rtt_ms: f64,
    pub min_rtt_ms: f64,
    pub max_rtt_ms: f64,
    pub p50_rtt_ms: f64,
    pub p95_rtt_ms: f64,
    pub p99_rtt_ms: f64,
    pub total_bytes_transferred: u64,
}

pub async fn run_performance_tests(
    agent_addr: &str,
    concurrency: usize,
    duration_secs: u64,
) -> Result<PerformanceTestResults> {
    info!("=== 开始性能测试 ===");
    info!(
        "Agent：{}，并发数：{}，持续时间：{} 秒",
        agent_addr, concurrency, duration_secs
    );

    let start_time = Instant::now();
    let end_time = start_time + Duration::from_secs(duration_secs);

    // 指标采集的共享状态
    let http_histogram = Arc::new(Mutex::new(Histogram::<u64>::new(3).unwrap()));
    let socks5_histogram = Arc::new(Mutex::new(Histogram::<u64>::new(3).unwrap()));
    let http_success = Arc::new(AtomicUsize::new(0));
    let http_failed = Arc::new(AtomicUsize::new(0));
    let socks5_success = Arc::new(AtomicUsize::new(0));
    let socks5_failed = Arc::new(AtomicUsize::new(0));
    let total_bytes = Arc::new(AtomicU64::new(0));

    // 系统监控
    let mut system = System::new_all();
    system.refresh_all();
    let initial_memory = system.used_memory();
    let peak_memory = Arc::new(AtomicU64::new(initial_memory));

    // 增加信号量以限制并发请求并降低内存使用
    let max_concurrent = std::cmp::min(concurrency * 2, 200); // 最大并发限制为 200
    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    info!("最大并发请求数限制为：{}", max_concurrent);

    // 启动工作任务
    let mut handles = Vec::new();

    // HTTP 工作任务（占并发数的 60%）
    let http_workers = (concurrency as f32 * 0.6) as usize;
    for _ in 0..http_workers {
        let addr = agent_addr.to_string();
        let hist = http_histogram.clone();
        let success = http_success.clone();
        let failed = http_failed.clone();
        let bytes = total_bytes.clone();
        let sem = semaphore.clone();

        let handle = tokio::spawn(async move {
            http_worker(addr, end_time, hist, success, failed, bytes, sem).await;
        });
        handles.push(handle);
    }

    // SOCKS5 工作任务（占并发数的 40%）
    let socks5_workers = concurrency - http_workers;
    for _ in 0..socks5_workers {
        let addr = agent_addr.to_string();
        let hist = socks5_histogram.clone();
        let success = socks5_success.clone();
        let failed = socks5_failed.clone();
        let bytes = total_bytes.clone();
        let sem = semaphore.clone();

        let handle = tokio::spawn(async move {
            socks5_worker(addr, end_time, hist, success, failed, bytes, sem).await;
        });
        handles.push(handle);
    }

    // 系统监控任务
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

    // 等待所有工作任务完成
    for handle in handles {
        let _ = handle.await;
    }
    let _ = monitor_handle.await;

    let actual_duration = start_time.elapsed();

    // 收集结果
    let http_hist = http_histogram.lock().await;
    let socks5_hist = socks5_histogram.lock().await;
    let http_succ = http_success.load(Ordering::Relaxed);
    let http_fail = http_failed.load(Ordering::Relaxed);
    let socks5_succ = socks5_success.load(Ordering::Relaxed);
    let socks5_fail = socks5_failed.load(Ordering::Relaxed);
    let total_transferred = total_bytes.load(Ordering::Relaxed);
    let peak_mem_val = peak_memory.load(Ordering::Relaxed);

    let http_metrics = calculate_metrics(&http_hist, http_succ, http_fail);
    let socks5_metrics = calculate_metrics(&socks5_hist, socks5_succ, socks5_fail);

    let total_requests = http_succ + http_fail + socks5_succ + socks5_fail;
    let successful_requests = http_succ + socks5_succ;
    let failed_requests = http_fail + socks5_fail;

    let requests_per_second = total_requests as f64 / actual_duration.as_secs_f64();
    let throughput_mbps =
        (total_transferred as f64 * 8.0) / (actual_duration.as_secs_f64() * 1_000_000.0);

    // 最终系统指标
    system.refresh_all();
    let cpu_usage = system.global_cpu_usage();
    let memory_usage_mb = system.used_memory() / 1024 / 1024;
    let peak_memory_mb = peak_mem_val / 1024 / 1024;

    let results = PerformanceTestResults {
        test_duration_secs: actual_duration.as_secs(),
        total_requests,
        successful_requests,
        failed_requests,
        requests_per_second,
        throughput_mbps,
        http_metrics,
        socks5_metrics,
        system_metrics: SystemMetrics {
            cpu_usage_percent: cpu_usage,
            memory_usage_mb,
            peak_memory_mb,
        },
    };

    info!("=== 性能测试完成 ===");
    info!("总请求数：{}", total_requests);
    if total_requests > 0 {
        info!(
            "成功率：{:.2}%",
            (successful_requests as f64 / total_requests as f64) * 100.0
        );
    } else {
        info!("成功率：N/A（没有已完成请求）");
    }
    info!("每秒请求数：{:.2}", requests_per_second);
    info!("吞吐量：{:.2} Mbps", throughput_mbps);

    Ok(results)
}

pub async fn run_udp_performance_tests(
    agent_addr: &str,
    target_host: &str,
    target_port: u16,
    concurrency: usize,
    duration_secs: u64,
    payload_size: usize,
) -> Result<UdpPerformanceTestResults> {
    info!("=== 开始 UDP 专项性能测试 ===");
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
    let total_bytes = Arc::new(AtomicU64::new(0));

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
        let bytes = total_bytes.clone();

        handles.push(tokio::spawn(async move {
            udp_worker(
                worker_id,
                agent_addr,
                target_addr,
                payload_size,
                end_time,
                hist,
                success,
                failed,
                bytes,
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
    let total_transferred = total_bytes.load(Ordering::Relaxed);
    let peak_mem_val = peak_memory.load(Ordering::Relaxed);

    let udp_metrics = calculate_udp_metrics(&udp_hist, udp_succ, udp_fail, total_transferred);
    let total_datagrams = udp_succ + udp_fail;
    let packet_loss_percent = if total_datagrams > 0 {
        (udp_fail as f64 / total_datagrams as f64) * 100.0
    } else {
        0.0
    };
    let datagrams_per_second = total_datagrams as f64 / actual_duration.as_secs_f64();
    let throughput_mbps =
        (total_transferred as f64 * 8.0) / (actual_duration.as_secs_f64() * 1_000_000.0);

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
        throughput_mbps,
        udp_metrics,
        system_metrics: SystemMetrics {
            cpu_usage_percent: cpu_usage,
            memory_usage_mb,
            peak_memory_mb,
        },
    };

    info!("=== UDP 专项性能测试完成 ===");
    info!("总 UDP datagrams：{}", total_datagrams);
    info!("成功：{}，失败：{}", udp_succ, udp_fail);
    info!("丢包/失败率：{:.2}%", packet_loss_percent);
    info!("Datagrams/sec：{:.2}", datagrams_per_second);
    info!("吞吐量：{:.2} Mbps", throughput_mbps);

    Ok(results)
}

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
async fn build_quic_results(
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

fn socks_udp_target(host: &str, port: u16) -> Result<async_socks5::AddrKind> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        Ok(async_socks5::AddrKind::Ip(SocketAddr::new(ip, port)))
    } else {
        let host = host.trim();
        anyhow::ensure!(!host.is_empty(), "QUIC target host must not be empty");
        anyhow::ensure!(
            host.len() <= 255,
            "SOCKS5 UDP domain target must be at most 255 bytes"
        );
        Ok(async_socks5::AddrKind::Domain(host.to_string(), port))
    }
}

fn quic_version_negotiation_probe(
    worker_id: usize,
    sequence: u64,
    datagram_size: usize,
) -> Vec<u8> {
    // QUIC 服务器通常会忽略小于 1200 字节的 Initial datagram，因此这里按
    // QUIC 最小 UDP payload 约束补零。version 使用保留版本，预期服务器返回
    // Version Negotiation 包（long header + version=0）。
    let size = datagram_size.max(1200);
    let mut packet = Vec::with_capacity(size);
    packet.push(0xc0);
    packet.extend_from_slice(&0x0a0a_0a0a_u32.to_be_bytes());

    let mut dcid = [0u8; 8];
    dcid[..4].copy_from_slice(&(worker_id as u32).to_be_bytes());
    dcid[4..].copy_from_slice(&(sequence as u32).to_be_bytes());
    let mut scid = [0u8; 8];
    scid.copy_from_slice(&sequence.rotate_left(17).to_be_bytes());

    packet.push(dcid.len() as u8);
    packet.extend_from_slice(&dcid);
    packet.push(scid.len() as u8);
    packet.extend_from_slice(&scid);
    packet.resize(size, 0);
    packet
}

fn parse_quic_version_negotiation_response(buf: &[u8]) -> Option<Vec<u32>> {
    if buf.len() < 7 || buf[0] & 0x80 == 0 {
        return None;
    }
    let version = u32::from_be_bytes(buf[1..5].try_into().ok()?);
    if version != 0 {
        return None;
    }

    let mut offset = 5usize;
    let dcid_len = *buf.get(offset)? as usize;
    offset += 1 + dcid_len;
    let scid_len = *buf.get(offset)? as usize;
    offset += 1 + scid_len;
    if offset > buf.len() {
        return None;
    }
    let versions = &buf[offset..];
    if versions.is_empty() || !versions.len().is_multiple_of(4) {
        return None;
    }

    Some(
        versions
            .chunks_exact(4)
            .map(|chunk| u32::from_be_bytes(chunk.try_into().expect("chunk size is fixed")))
            .collect(),
    )
}

fn format_quic_version(version: u32) -> String {
    format!("0x{version:08x}")
}

#[allow(clippy::too_many_arguments)]
async fn tcp_worker(
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

async fn create_socks_tcp_stream(
    agent_addr: &str,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(agent_addr)
        .await
        .context("Failed to connect to agent for TCP performance test")?;
    async_socks5::connect(&mut stream, (target_host.to_string(), target_port), None)
        .await
        .context("Failed to connect via SOCKS5 for TCP performance test")?;
    Ok(stream)
}

fn tcp_payload(worker_id: usize, sequence: u64, payload_size: usize) -> Vec<u8> {
    // TCP 压测只关心端到端字节完整性，payload 复用 UDP 的确定性模式；
    // worker/sequence 前缀能帮助定位并发场景下的回显错配。
    udp_payload(worker_id, sequence, payload_size)
}

#[allow(clippy::too_many_arguments)]
async fn udp_worker(
    worker_id: usize,
    agent_addr: String,
    target_addr: SocketAddr,
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
        let datagram = match create_socks_udp_datagram(&agent_addr).await {
            Ok(datagram) => datagram,
            Err(e) => {
                warn!("UDP worker {worker_id} 建立 SOCKS5 UDP associate 失败：{e}");
                failed.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        while Instant::now() < end_time {
            let payload = udp_payload(worker_id, sequence, payload_size);
            sequence = sequence.wrapping_add(1);
            let start = Instant::now();

            if let Err(e) = datagram.send_to(&payload, target_addr).await {
                warn!("UDP worker {worker_id} 发送失败：{e}");
                failed.fetch_add(1, Ordering::Relaxed);
                consecutive_failures += 1;
                break;
            }

            let mut buf = vec![0u8; payload_size.max(4096)];
            match tokio::time::timeout(Duration::from_secs(3), datagram.recv_from(&mut buf)).await {
                Ok(Ok((n, _src))) if buf[..n] == payload => {
                    latencies_us.push(start.elapsed().as_micros() as u64);
                    success.fetch_add(1, Ordering::Relaxed);
                    total_bytes.fetch_add((payload.len() + n) as u64, Ordering::Relaxed);
                    consecutive_failures = 0;

                    if latencies_us.len() >= 256 {
                        let mut hist = histogram.lock().await;
                        for latency in latencies_us.drain(..) {
                            let _ = hist.record(latency);
                        }
                    }
                }
                Ok(Ok((n, _src))) => {
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

async fn create_socks_udp_datagram(
    agent_addr: &str,
) -> Result<async_socks5::SocksDatagram<TcpStream>> {
    let stream = TcpStream::connect(agent_addr)
        .await
        .context("Failed to connect to agent for UDP performance test")?;
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("Failed to bind local UDP socket for UDP performance test")?;
    async_socks5::SocksDatagram::associate(stream, socket, None, None::<SocketAddr>)
        .await
        .context("Failed to associate via SOCKS5 for UDP performance test")
}

fn udp_payload(worker_id: usize, sequence: u64, payload_size: usize) -> Vec<u8> {
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

async fn http_worker(
    agent_addr: String,
    end_time: Instant,
    histogram: Arc<Mutex<Histogram<u64>>>,
    success: Arc<AtomicUsize>,
    failed: Arc<AtomicUsize>,
    total_bytes: Arc<AtomicU64>,
    semaphore: Arc<Semaphore>,
) {
    let client = MockHttpClient::new(agent_addr);
    let urls = [
        "http://127.0.0.1:9090/health",
        "http://127.0.0.1:9090/json",
        "http://127.0.0.1:9090/large",
    ];
    let mut url_idx = 0;
    let mut consecutive_failures = 0;
    let mut latencies = Vec::with_capacity(100); // 批量更新直方图

    while Instant::now() < end_time {
        let url = urls[url_idx % urls.len()];
        url_idx += 1;

        // 发送请求前获取信号量许可
        let _permit = match semaphore.try_acquire() {
            Ok(p) => p,
            Err(_) => {
                // 如果无法获取，则稍等后重试
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };

        match client.get(url).await {
            Ok((duration, body)) => {
                latencies.push(duration.as_millis() as u64);
                success.fetch_add(1, Ordering::Relaxed);
                total_bytes.fetch_add(body.len() as u64, Ordering::Relaxed);
                consecutive_failures = 0;

                // 每 100 个请求批量更新一次直方图
                if latencies.len() >= 100 {
                    let mut hist = histogram.lock().await;
                    for latency in latencies.drain(..) {
                        let _ = hist.record(latency);
                    }
                }
            }
            Err(e) => {
                warn!("HTTP 请求失败：{}", e);
                failed.fetch_add(1, Ordering::Relaxed);
                consecutive_failures += 1;

                // 对连续失败增加指数退避
                if consecutive_failures > 0 {
                    let delay_ms = std::cmp::min(100, consecutive_failures * 10);
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
            }
        }
    }

    // 刷新剩余延迟数据
    if !latencies.is_empty() {
        let mut hist = histogram.lock().await;
        for latency in latencies {
            let _ = hist.record(latency);
        }
    }
}

async fn socks5_worker(
    agent_addr: String,
    end_time: Instant,
    histogram: Arc<Mutex<Histogram<u64>>>,
    success: Arc<AtomicUsize>,
    failed: Arc<AtomicUsize>,
    total_bytes: Arc<AtomicU64>,
    semaphore: Arc<Semaphore>,
) {
    let client = MockSocks5Client::new(agent_addr);
    let test_data = b"Performance test data";
    let mut consecutive_failures = 0;
    let mut latencies = Vec::with_capacity(100); // 批量更新直方图

    while Instant::now() < end_time {
        // 发送请求前获取信号量许可
        let _permit = match semaphore.try_acquire() {
            Ok(p) => p,
            Err(_) => {
                // 如果无法获取，则稍等后重试
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };

        match client.send_receive("127.0.0.1", 9091, test_data).await {
            Ok((duration, response)) => {
                latencies.push(duration.as_millis() as u64);
                success.fetch_add(1, Ordering::Relaxed);
                total_bytes.fetch_add((test_data.len() + response.len()) as u64, Ordering::Relaxed);
                consecutive_failures = 0;

                // 每 100 个请求批量更新一次直方图
                if latencies.len() >= 100 {
                    let mut hist = histogram.lock().await;
                    for latency in latencies.drain(..) {
                        let _ = hist.record(latency);
                    }
                }
            }
            Err(e) => {
                warn!("SOCKS5 请求失败：{}", e);
                failed.fetch_add(1, Ordering::Relaxed);
                consecutive_failures += 1;

                // 对连续失败增加指数退避
                if consecutive_failures > 0 {
                    let delay_ms = std::cmp::min(100, consecutive_failures * 10);
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
            }
        }
    }

    // 刷新剩余延迟数据
    if !latencies.is_empty() {
        let mut hist = histogram.lock().await;
        for latency in latencies {
            let _ = hist.record(latency);
        }
    }
}

fn calculate_metrics(
    histogram: &Histogram<u64>,
    successful: usize,
    failed: usize,
) -> RequestMetrics {
    let total = successful + failed;

    if histogram.is_empty() {
        return RequestMetrics {
            total_requests: total,
            successful,
            failed,
            avg_latency_ms: 0.0,
            min_latency_ms: 0.0,
            max_latency_ms: 0.0,
            p50_latency_ms: 0.0,
            p95_latency_ms: 0.0,
            p99_latency_ms: 0.0,
            total_bytes_transferred: 0,
        };
    }

    RequestMetrics {
        total_requests: total,
        successful,
        failed,
        avg_latency_ms: histogram.mean(),
        min_latency_ms: histogram.min() as f64,
        max_latency_ms: histogram.max() as f64,
        p50_latency_ms: histogram.value_at_quantile(0.5) as f64,
        p95_latency_ms: histogram.value_at_quantile(0.95) as f64,
        p99_latency_ms: histogram.value_at_quantile(0.99) as f64,
        total_bytes_transferred: 0, // 单独计算
    }
}

fn calculate_udp_metrics(
    histogram: &Histogram<u64>,
    successful: usize,
    failed: usize,
    total_bytes_transferred: u64,
) -> UdpDatagramMetrics {
    let total = successful + failed;

    if histogram.is_empty() {
        return UdpDatagramMetrics {
            total_datagrams: total,
            successful,
            failed,
            avg_rtt_ms: 0.0,
            min_rtt_ms: 0.0,
            max_rtt_ms: 0.0,
            p50_rtt_ms: 0.0,
            p95_rtt_ms: 0.0,
            p99_rtt_ms: 0.0,
            total_bytes_transferred,
        };
    }

    UdpDatagramMetrics {
        total_datagrams: total,
        successful,
        failed,
        avg_rtt_ms: histogram.mean() / 1000.0,
        min_rtt_ms: histogram.min() as f64 / 1000.0,
        max_rtt_ms: histogram.max() as f64 / 1000.0,
        p50_rtt_ms: histogram.value_at_quantile(0.5) as f64 / 1000.0,
        p95_rtt_ms: histogram.value_at_quantile(0.95) as f64 / 1000.0,
        p99_rtt_ms: histogram.value_at_quantile(0.99) as f64 / 1000.0,
        total_bytes_transferred,
    }
}

fn calculate_tcp_metrics(
    histogram: &Histogram<u64>,
    successful: usize,
    failed: usize,
    total_bytes_transferred: u64,
) -> TcpTransferMetrics {
    let total = successful + failed;

    if histogram.is_empty() {
        return TcpTransferMetrics {
            total_chunks: total,
            successful,
            failed,
            avg_rtt_ms: 0.0,
            min_rtt_ms: 0.0,
            max_rtt_ms: 0.0,
            p50_rtt_ms: 0.0,
            p95_rtt_ms: 0.0,
            p99_rtt_ms: 0.0,
            total_bytes_transferred,
        };
    }

    TcpTransferMetrics {
        total_chunks: total,
        successful,
        failed,
        avg_rtt_ms: histogram.mean() / 1000.0,
        min_rtt_ms: histogram.min() as f64 / 1000.0,
        max_rtt_ms: histogram.max() as f64 / 1000.0,
        p50_rtt_ms: histogram.value_at_quantile(0.5) as f64 / 1000.0,
        p95_rtt_ms: histogram.value_at_quantile(0.95) as f64 / 1000.0,
        p99_rtt_ms: histogram.value_at_quantile(0.99) as f64 / 1000.0,
        total_bytes_transferred,
    }
}

fn calculate_quic_metrics(
    histogram: &Histogram<u64>,
    successful: usize,
    failed: usize,
    total_bytes_transferred: u64,
) -> QuicProbeMetrics {
    let total = successful + failed;

    if histogram.is_empty() {
        return QuicProbeMetrics {
            total_probes: total,
            successful_vn_responses: successful,
            failed_probes: failed,
            avg_rtt_ms: 0.0,
            min_rtt_ms: 0.0,
            max_rtt_ms: 0.0,
            p50_rtt_ms: 0.0,
            p95_rtt_ms: 0.0,
            p99_rtt_ms: 0.0,
            total_bytes_transferred,
        };
    }

    QuicProbeMetrics {
        total_probes: total,
        successful_vn_responses: successful,
        failed_probes: failed,
        avg_rtt_ms: histogram.mean() / 1000.0,
        min_rtt_ms: histogram.min() as f64 / 1000.0,
        max_rtt_ms: histogram.max() as f64 / 1000.0,
        p50_rtt_ms: histogram.value_at_quantile(0.5) as f64 / 1000.0,
        p95_rtt_ms: histogram.value_at_quantile(0.95) as f64 / 1000.0,
        p99_rtt_ms: histogram.value_at_quantile(0.99) as f64 / 1000.0,
        total_bytes_transferred,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_calculation() {
        let mut hist = Histogram::<u64>::new(3).unwrap();
        hist.record(100).unwrap();
        hist.record(200).unwrap();
        hist.record(300).unwrap();

        let metrics = calculate_metrics(&hist, 3, 0);
        assert_eq!(metrics.total_requests, 3);
        assert_eq!(metrics.successful, 3);
        assert_eq!(metrics.failed, 0);
        assert!(metrics.avg_latency_ms > 0.0);
    }

    #[test]
    fn test_udp_metrics_calculation_uses_microseconds() {
        let mut hist = Histogram::<u64>::new(3).unwrap();
        hist.record(500).unwrap();
        hist.record(1500).unwrap();
        hist.record(2500).unwrap();

        let metrics = calculate_udp_metrics(&hist, 3, 1, 4096);
        assert_eq!(metrics.total_datagrams, 4);
        assert_eq!(metrics.successful, 3);
        assert_eq!(metrics.failed, 1);
        assert!(metrics.avg_rtt_ms > 0.0);
        assert_eq!(metrics.total_bytes_transferred, 4096);
    }

    #[test]
    fn test_tcp_metrics_calculation_uses_microseconds() {
        let mut hist = Histogram::<u64>::new(3).unwrap();
        hist.record(1000).unwrap();
        hist.record(2000).unwrap();
        hist.record(3000).unwrap();

        let metrics = calculate_tcp_metrics(&hist, 3, 2, 128 * 1024);
        assert_eq!(metrics.total_chunks, 5);
        assert_eq!(metrics.successful, 3);
        assert_eq!(metrics.failed, 2);
        assert!(metrics.avg_rtt_ms >= 1.0);
        assert_eq!(metrics.total_bytes_transferred, 128 * 1024);
    }

    #[test]
    fn quic_probe_is_padded_to_minimum_udp_payload() {
        let probe = quic_version_negotiation_probe(7, 42, 32);

        assert_eq!(probe.len(), 1200);
        assert_eq!(probe[0], 0xc0);
        assert_eq!(&probe[1..5], &0x0a0a_0a0a_u32.to_be_bytes());
    }

    #[test]
    fn parses_quic_version_negotiation_versions() {
        let mut response = Vec::new();
        response.push(0x80);
        response.extend_from_slice(&0u32.to_be_bytes());
        response.push(8);
        response.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        response.push(8);
        response.extend_from_slice(&[8, 7, 6, 5, 4, 3, 2, 1]);
        response.extend_from_slice(&1u32.to_be_bytes());
        response.extend_from_slice(&0x6b33_43cf_u32.to_be_bytes());

        let versions = parse_quic_version_negotiation_response(&response).unwrap();

        assert_eq!(versions, vec![1, 0x6b33_43cf]);
        assert_eq!(format_quic_version(1), "0x00000001");
    }
}
