use super::*;

/// 生成 Markdown 报告
pub(crate) fn generate_markdown_report(results: &PerformanceTestResults, path: &str) -> Result<()> {
    let mut content = String::new();

    content.push_str("# PPAASS Proxy Performance Test Report\n\n");
    content.push_str(&format!(
        "**Test Duration:** {} seconds\n\n",
        results.test_duration_secs
    ));

    content.push_str("## Summary\n\n");
    content.push_str(&format!(
        "- **Total Requests:** {}\n",
        results.total_requests
    ));
    content.push_str(&format!(
        "- **Successful Requests:** {}\n",
        results.successful_requests
    ));
    content.push_str(&format!(
        "- **Failed Requests:** {}\n",
        results.failed_requests
    ));

    if results.total_requests > 0 {
        content.push_str(&format!(
            "- **Success Rate:** {:.2}%\n",
            (results.successful_requests as f64 / results.total_requests as f64) * 100.0
        ));
    } else {
        content.push_str("- **Success Rate:** N/A (no requests completed)\n");
    }

    content.push_str(&format!(
        "- **Requests per Second:** {:.2}\n",
        results.requests_per_second
    ));
    content.push_str(&format!(
        "- **Throughput:** {:.2} Mbps\n\n",
        results.throughput_mbps
    ));

    content.push_str("## HTTP Metrics\n\n");
    content.push_str("| Metric | Value |\n");
    content.push_str("|--------|-------|\n");
    content.push_str(&format!(
        "| Total Requests | {} |\n",
        results.http_metrics.total_requests
    ));
    content.push_str(&format!(
        "| Successful | {} |\n",
        results.http_metrics.successful
    ));
    content.push_str(&format!("| Failed | {} |\n", results.http_metrics.failed));
    content.push_str(&format!(
        "| Avg Latency | {:.2} ms |\n",
        results.http_metrics.avg_latency_ms
    ));
    content.push_str(&format!(
        "| Min Latency | {:.2} ms |\n",
        results.http_metrics.min_latency_ms
    ));
    content.push_str(&format!(
        "| Max Latency | {:.2} ms |\n",
        results.http_metrics.max_latency_ms
    ));
    content.push_str(&format!(
        "| P50 Latency | {:.2} ms |\n",
        results.http_metrics.p50_latency_ms
    ));
    content.push_str(&format!(
        "| P95 Latency | {:.2} ms |\n",
        results.http_metrics.p95_latency_ms
    ));
    content.push_str(&format!(
        "| P99 Latency | {:.2} ms |\n\n",
        results.http_metrics.p99_latency_ms
    ));

    content.push_str("## SOCKS5 Metrics\n\n");
    content.push_str("| Metric | Value |\n");
    content.push_str("|--------|-------|\n");
    content.push_str(&format!(
        "| Total Requests | {} |\n",
        results.socks5_metrics.total_requests
    ));
    content.push_str(&format!(
        "| Successful | {} |\n",
        results.socks5_metrics.successful
    ));
    content.push_str(&format!("| Failed | {} |\n", results.socks5_metrics.failed));
    content.push_str(&format!(
        "| Avg Latency | {:.2} ms |\n",
        results.socks5_metrics.avg_latency_ms
    ));
    content.push_str(&format!(
        "| Min Latency | {:.2} ms |\n",
        results.socks5_metrics.min_latency_ms
    ));
    content.push_str(&format!(
        "| Max Latency | {:.2} ms |\n",
        results.socks5_metrics.max_latency_ms
    ));
    content.push_str(&format!(
        "| P50 Latency | {:.2} ms |\n",
        results.socks5_metrics.p50_latency_ms
    ));
    content.push_str(&format!(
        "| P95 Latency | {:.2} ms |\n",
        results.socks5_metrics.p95_latency_ms
    ));
    content.push_str(&format!(
        "| P99 Latency | {:.2} ms |\n\n",
        results.socks5_metrics.p99_latency_ms
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
