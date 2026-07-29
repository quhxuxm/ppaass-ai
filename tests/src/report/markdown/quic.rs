use super::*;

pub(crate) fn generate_quic_markdown_report(
    results: &QuicProbeTestResults,
    path: &str,
) -> Result<()> {
    let metrics = &results.quic_metrics;
    let versions = if results.supported_versions.is_empty() {
        "N/A".to_string()
    } else {
        results.supported_versions.join(", ")
    };
    let mut content = String::new();

    content.push_str("# PPAASS QUIC UDP/443 Test Report\n\n");
    content.push_str(&format!("- **Mode:** {}\n", results.test_mode));
    content.push_str(&format!(
        "- **Duration:** {} seconds\n",
        results.test_duration_secs
    ));
    content.push_str(&format!("- **Agent:** {}\n", results.agent_addr));
    content.push_str(&format!(
        "- **Target:** {}:{}\n",
        results.target_host, results.target_port
    ));
    content.push_str(&format!("- **Concurrency:** {}\n", results.concurrency));
    if let Some(attempts) = results.configured_attempts {
        content.push_str(&format!("- **Configured Attempts:** {}\n", attempts));
    }
    content.push_str(&format!("- **Total Probes:** {}\n", results.total_probes));
    content.push_str(&format!(
        "- **Version Negotiation Responses:** {}\n",
        results.successful_vn_responses
    ));
    content.push_str(&format!("- **Failed Probes:** {}\n", results.failed_probes));
    content.push_str(&format!(
        "- **VN Response Rate:** {:.2}%\n",
        results.response_rate_percent
    ));
    content.push_str(&format!(
        "- **Probes/sec:** {:.2}\n",
        results.probes_per_second
    ));
    content.push_str(&format!(
        "- **Throughput:** {:.2} Mbps\n",
        results.throughput_mbps
    ));
    content.push_str(&format!("- **Supported Versions:** {}\n\n", versions));

    content.push_str("## QUIC RTT Metrics\n\n");
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
