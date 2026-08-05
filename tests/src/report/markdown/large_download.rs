use super::*;

pub(crate) fn generate_large_download_markdown_report(
    results: &LargeDownloadTestResults,
    path: &str,
) -> Result<()> {
    let metrics = &results.chunk_metrics;
    let mut content = String::new();

    content.push_str("# PPAASS HTTP Range Large Download Test Report\n\n");
    content.push_str(&format!(
        "- **Duration:** {} seconds\n",
        results.test_duration_secs
    ));
    content.push_str(&format!("- **Agent:** {}\n", results.agent_addr));
    content.push_str(&format!("- **URL:** {}\n", results.target_url));
    content.push_str(&format!(
        "- **File Size:** {} bytes\n",
        results.file_size_bytes
    ));
    content.push_str(&format!(
        "- **Chunk Size:** {} bytes\n",
        results.chunk_size_bytes
    ));
    content.push_str(&format!("- **Concurrency:** {}\n", results.concurrency));
    content.push_str(&format!("- **Rounds:** {}\n", results.rounds));
    content.push_str(&format!("- **Total Chunks:** {}\n", results.total_chunks));
    content.push_str(&format!(
        "- **Successful Chunks:** {}\n",
        results.successful_chunks
    ));
    content.push_str(&format!("- **Failed Chunks:** {}\n", results.failed_chunks));
    content.push_str(&format!(
        "- **Success Rate:** {:.2}%\n",
        results.success_rate_percent
    ));
    content.push_str(&format!(
        "- **Chunks/sec:** {:.2}\n",
        results.chunks_per_second
    ));
    content.push_str(&format!(
        "- **Throughput:** {:.2} Mbps\n\n",
        results.throughput_mbps
    ));

    content.push_str("## Chunk Latency Metrics\n\n");
    content.push_str("| Metric | Value |\n");
    content.push_str("|--------|-------|\n");
    content.push_str(&format!(
        "| Average Latency | {:.3} ms |\n",
        metrics.avg_latency_ms
    ));
    content.push_str(&format!(
        "| Min Latency | {:.3} ms |\n",
        metrics.min_latency_ms
    ));
    content.push_str(&format!(
        "| P50 Latency | {:.3} ms |\n",
        metrics.p50_latency_ms
    ));
    content.push_str(&format!(
        "| P95 Latency | {:.3} ms |\n",
        metrics.p95_latency_ms
    ));
    content.push_str(&format!(
        "| P99 Latency | {:.3} ms |\n",
        metrics.p99_latency_ms
    ));
    content.push_str(&format!(
        "| Max Latency | {:.3} ms |\n",
        metrics.max_latency_ms
    ));
    content.push_str(&format!(
        "| Total Bytes Downloaded | {} |\n\n",
        metrics.total_bytes_downloaded
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
