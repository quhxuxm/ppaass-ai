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
use metrics::{calculate_large_download_metrics, calculate_quic_metrics};
pub use metrics::{calculate_metrics, calculate_tcp_metrics, calculate_udp_metrics};
pub use quic::{run_quic_performance_tests, run_quic_probe_tests};
use quic_packet::socks_udp_target;
pub use quic_packet::{
    format_quic_version, parse_quic_version_negotiation_response, quic_version_negotiation_probe,
};
pub use tcp::run_tcp_performance_tests;
pub use udp::run_udp_performance_tests;
use udp::{create_socks_udp_datagram, udp_payload};
