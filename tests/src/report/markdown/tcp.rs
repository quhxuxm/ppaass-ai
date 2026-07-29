use super::*;

pub(crate) fn generate_tcp_markdown_report(
    results: &TcpPerformanceTestResults,
    path: &str,
) -> Result<()> {
    let metrics = &results.tcp_metrics;
    let mut content = String::new();

    content.push_str("# PPAASS TCP Relay Performance Test Report\n\n");
    content.push_str(&format!(
        "**Test Duration:** {} seconds\n\n",
        results.test_duration_secs
    ));
    content.push_str("## Summary\n\n");
    content.push_str(&format!("- **Agent:** {}\n", results.agent_addr));
    content.push_str(&format!(
        "- **Target:** {}:{}\n",
        results.target_host, results.target_port
    ));
    content.push_str(&format!("- **Concurrency:** {}\n", results.concurrency));
    content.push_str(&format!(
        "- **Payload Size:** {} bytes\n",
        results.payload_size
    ));
    content.push_str(&format!("- **Total Chunks:** {}\n", results.total_chunks));
    content.push_str(&format!(
        "- **Successful Chunks:** {}\n",
        results.successful_chunks
    ));
    content.push_str(&format!("- **Failed Chunks:** {}\n", results.failed_chunks));
    content.push_str(&format!(
        "- **Failure Rate:** {:.2}%\n",
        results.failure_rate_percent
    ));
    content.push_str(&format!(
        "- **Chunks/sec:** {:.2}\n",
        results.chunks_per_second
    ));
    content.push_str(&format!(
        "- **Throughput:** {:.2} Mbps\n\n",
        results.throughput_mbps
    ));

    content.push_str("## TCP RTT Metrics\n\n");
    content.push_str("| Metric | Value |\n");
    content.push_str("|--------|-------|\n");
    content.push_str(&format!("| Avg RTT | {:.3} ms |\n", metrics.avg_rtt_ms));
    content.push_str(&format!("| Min RTT | {:.3} ms |\n", metrics.min_rtt_ms));
    content.push_str(&format!("| Max RTT | {:.3} ms |\n", metrics.max_rtt_ms));
    content.push_str(&format!("| P50 RTT | {:.3} ms |\n", metrics.p50_rtt_ms));
    content.push_str(&format!("| P95 RTT | {:.3} ms |\n", metrics.p95_rtt_ms));
    content.push_str(&format!("| P99 RTT | {:.3} ms |\n", metrics.p99_rtt_ms));
    content.push_str(&format!(
        "| Total Bytes Transferred | {} |\n\n",
        metrics.total_bytes_transferred
    ));

    content.push_str("## System Metrics\n\n");
    content.push_str(&format!(
        "- **CPU Usage:** {:.2}%\n",
        results.system_metrics.cpu_usage_percent
    ));
    content.push_str(&format!(
        "- **Memory Usage:** {} MB\n",
        results.system_metrics.memory_usage_mb
    ));
    content.push_str(&format!(
        "- **Peak Memory:** {} MB\n",
        results.system_metrics.peak_memory_mb
    ));

    let mut file = File::create(path)?;
    file.write_all(content.as_bytes())?;
    Ok(())
}
