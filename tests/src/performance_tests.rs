use crate::mock_client::{MockHttpClient, MockSocks5Client};
use anyhow::{Context, Result};
use hdrhistogram::Histogram;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use sysinfo::System;
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
}
