use crate::mock_client::{MockHttpClient, MockSocks5Client};
use anyhow::Result;
use hdrhistogram::Histogram;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use sysinfo::System;
use tokio::sync::Mutex;
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

pub async fn run_performance_tests(
    agent_addr: &str,
    concurrency: usize,
    duration_secs: u64,
) -> Result<PerformanceTestResults> {
    info!("=== Starting Performance Tests ===");
    info!("Agent: {}, Concurrency: {}, Duration: {}s", agent_addr, concurrency, duration_secs);

    let start_time = Instant::now();
    let end_time = start_time + Duration::from_secs(duration_secs);

    // Shared state for metrics collection
    let http_histogram = Arc::new(Mutex::new(Histogram::<u64>::new(3).unwrap()));
    let socks5_histogram = Arc::new(Mutex::new(Histogram::<u64>::new(3).unwrap()));
    let http_success = Arc::new(Mutex::new(0usize));
    let http_failed = Arc::new(Mutex::new(0usize));
    let socks5_success = Arc::new(Mutex::new(0usize));
    let socks5_failed = Arc::new(Mutex::new(0usize));
    let total_bytes = Arc::new(Mutex::new(0u64));

    // System monitoring
    let mut system = System::new_all();
    system.refresh_all();
    let initial_memory = system.used_memory();
    let peak_memory = Arc::new(Mutex::new(initial_memory));

    // Spawn worker tasks
    let mut handles = Vec::new();

    // HTTP workers (60% of concurrency)
    let http_workers = (concurrency as f32 * 0.6) as usize;
    for _ in 0..http_workers {
        let addr = agent_addr.to_string();
        let hist = http_histogram.clone();
        let success = http_success.clone();
        let failed = http_failed.clone();
        let bytes = total_bytes.clone();
        
        let handle = tokio::spawn(async move {
            http_worker(addr, end_time, hist, success, failed, bytes).await;
        });
        handles.push(handle);
    }

    // SOCKS5 workers (40% of concurrency)
    let socks5_workers = concurrency - http_workers;
    for _ in 0..socks5_workers {
        let addr = agent_addr.to_string();
        let hist = socks5_histogram.clone();
        let success = socks5_success.clone();
        let failed = socks5_failed.clone();
        let bytes = total_bytes.clone();
        
        let handle = tokio::spawn(async move {
            socks5_worker(addr, end_time, hist, success, failed, bytes).await;
        });
        handles.push(handle);
    }

    // System monitoring task
    let peak_mem = peak_memory.clone();
    let monitor_handle = tokio::spawn(async move {
        let mut sys = System::new_all();
        while Instant::now() < end_time {
            tokio::time::sleep(Duration::from_secs(1)).await;
            sys.refresh_all();
            let current_mem = sys.used_memory();
            let mut peak = peak_mem.lock().await;
            if current_mem > *peak {
                *peak = current_mem;
            }
        }
    });

    // Wait for all workers to complete
    for handle in handles {
        let _ = handle.await;
    }
    let _ = monitor_handle.await;

    let actual_duration = start_time.elapsed();

    // Collect results
    let http_hist = http_histogram.lock().await;
    let socks5_hist = socks5_histogram.lock().await;
    let http_succ = *http_success.lock().await;
    let http_fail = *http_failed.lock().await;
    let socks5_succ = *socks5_success.lock().await;
    let socks5_fail = *socks5_failed.lock().await;
    let total_transferred = *total_bytes.lock().await;
    let peak_mem_val = *peak_memory.lock().await;

    let http_metrics = calculate_metrics(&http_hist, http_succ, http_fail);
    let socks5_metrics = calculate_metrics(&socks5_hist, socks5_succ, socks5_fail);

    let total_requests = http_succ + http_fail + socks5_succ + socks5_fail;
    let successful_requests = http_succ + socks5_succ;
    let failed_requests = http_fail + socks5_fail;

    let requests_per_second = total_requests as f64 / actual_duration.as_secs_f64();
    let throughput_mbps = (total_transferred as f64 * 8.0) / (actual_duration.as_secs_f64() * 1_000_000.0);

    // Final system metrics
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

    info!("=== Performance Tests Complete ===");
    info!("Total Requests: {}", total_requests);
    info!("Success Rate: {:.2}%", (successful_requests as f64 / total_requests as f64) * 100.0);
    info!("Requests/sec: {:.2}", requests_per_second);
    info!("Throughput: {:.2} Mbps", throughput_mbps);

    Ok(results)
}

async fn http_worker(
    agent_addr: String,
    end_time: Instant,
    histogram: Arc<Mutex<Histogram<u64>>>,
    success: Arc<Mutex<usize>>,
    failed: Arc<Mutex<usize>>,
    total_bytes: Arc<Mutex<u64>>,
) {
    let client = MockHttpClient::new(agent_addr);
    let urls = [
        "http://127.0.0.1:9090/health",
        "http://127.0.0.1:9090/json",
        "http://127.0.0.1:9090/large",
    ];
    let mut url_idx = 0;

    while Instant::now() < end_time {
        let url = urls[url_idx % urls.len()];
        url_idx += 1;

        match client.get(url).await {
            Ok((duration, body)) => {
                let mut hist = histogram.lock().await;
                let _ = hist.record(duration.as_millis() as u64);
                drop(hist);

                let mut succ = success.lock().await;
                *succ += 1;
                drop(succ);

                let mut bytes = total_bytes.lock().await;
                *bytes += body.len() as u64;
            }
            Err(e) => {
                warn!("HTTP request failed: {}", e);
                let mut fail = failed.lock().await;
                *fail += 1;
            }
        }
    }
}

async fn socks5_worker(
    agent_addr: String,
    end_time: Instant,
    histogram: Arc<Mutex<Histogram<u64>>>,
    success: Arc<Mutex<usize>>,
    failed: Arc<Mutex<usize>>,
    total_bytes: Arc<Mutex<u64>>,
) {
    let client = MockSocks5Client::new(agent_addr);
    let test_data = b"Performance test data";

    while Instant::now() < end_time {
        match client.send_receive("127.0.0.1", 9091, test_data).await {
            Ok((duration, response)) => {
                let mut hist = histogram.lock().await;
                let _ = hist.record(duration.as_millis() as u64);
                drop(hist);

                let mut succ = success.lock().await;
                *succ += 1;
                drop(succ);

                let mut bytes = total_bytes.lock().await;
                *bytes += (test_data.len() + response.len()) as u64;
            }
            Err(e) => {
                warn!("SOCKS5 request failed: {}", e);
                let mut fail = failed.lock().await;
                *fail += 1;
            }
        }
    }
}

fn calculate_metrics(histogram: &Histogram<u64>, successful: usize, failed: usize) -> RequestMetrics {
    let total = successful + failed;
    
    if histogram.len() == 0 {
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
        total_bytes_transferred: 0, // Calculated separately
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
}
