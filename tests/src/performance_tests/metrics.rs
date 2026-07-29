use super::*;

pub(super) fn calculate_metrics(
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

pub(super) fn calculate_udp_metrics(
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

pub(super) fn calculate_tcp_metrics(
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

pub(super) fn calculate_large_download_metrics(
    histogram: &Histogram<u64>,
    successful: usize,
    failed: usize,
    total_bytes_downloaded: u64,
) -> LargeDownloadChunkMetrics {
    let total = successful + failed;

    if histogram.is_empty() {
        return LargeDownloadChunkMetrics {
            total_chunks: total,
            successful,
            failed,
            avg_latency_ms: 0.0,
            min_latency_ms: 0.0,
            max_latency_ms: 0.0,
            p50_latency_ms: 0.0,
            p95_latency_ms: 0.0,
            p99_latency_ms: 0.0,
            total_bytes_downloaded,
        };
    }

    LargeDownloadChunkMetrics {
        total_chunks: total,
        successful,
        failed,
        avg_latency_ms: histogram.mean() / 1000.0,
        min_latency_ms: histogram.min() as f64 / 1000.0,
        max_latency_ms: histogram.max() as f64 / 1000.0,
        p50_latency_ms: histogram.value_at_quantile(0.5) as f64 / 1000.0,
        p95_latency_ms: histogram.value_at_quantile(0.95) as f64 / 1000.0,
        p99_latency_ms: histogram.value_at_quantile(0.99) as f64 / 1000.0,
        total_bytes_downloaded,
    }
}

pub(super) fn calculate_quic_metrics(
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
