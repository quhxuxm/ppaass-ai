use crate::mock_client::{MockHttpClient, MockSocks5Client, connect_to_agent_with_retry};
use anyhow::{Context, Result};
use hdrhistogram::Histogram;
use hyper::StatusCode;
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

const LARGE_DOWNLOAD_CHUNK_TIMEOUT: Duration = Duration::from_secs(30);

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LargeDownloadTestResults {
    pub test_duration_secs: u64,
    pub agent_addr: String,
    pub target_url: String,
    pub file_size_bytes: u64,
    pub chunk_size_bytes: u64,
    pub concurrency: usize,
    pub rounds: usize,
    pub total_chunks: usize,
    pub successful_chunks: usize,
    pub failed_chunks: usize,
    pub success_rate_percent: f64,
    pub chunks_per_second: f64,
    pub throughput_mbps: f64,
    pub chunk_metrics: LargeDownloadChunkMetrics,
    pub system_metrics: SystemMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LargeDownloadChunkMetrics {
    pub total_chunks: usize,
    pub successful: usize,
    pub failed: usize,
    pub avg_latency_ms: f64,
    pub min_latency_ms: f64,
    pub max_latency_ms: f64,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub total_bytes_downloaded: u64,
}

mod http;
mod large_download;
mod metrics;
mod quic;
mod quic_packet;
mod tcp;
mod udp;

pub use http::run_performance_tests;
pub use large_download::run_large_download_tests;
use metrics::*;
pub use quic::{run_quic_performance_tests, run_quic_probe_tests};
use quic_packet::*;
pub use tcp::run_tcp_performance_tests;
pub use udp::run_udp_performance_tests;
use udp::{create_socks_udp_datagram, udp_payload};

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
