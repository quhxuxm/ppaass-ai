use super::*;

pub(crate) fn generate_quic_html_report(results: &QuicProbeTestResults, path: &str) -> Result<()> {
    let metrics = &results.quic_metrics;
    let versions = if results.supported_versions.is_empty() {
        "N/A".to_string()
    } else {
        results.supported_versions.join(", ")
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PPAASS QUIC UDP/443 Test Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            margin: 0;
            padding: 24px;
            background: #f6f7f9;
            color: #202124;
        }}
        .container {{
            max-width: 1040px;
            margin: 0 auto;
            background: #fff;
            padding: 28px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(15, 23, 42, 0.08);
        }}
        h1 {{ margin-top: 0; }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 14px;
            margin: 22px 0;
        }}
        .metric-card {{
            border: 1px solid #d8dee8;
            border-radius: 8px;
            padding: 16px;
            background: #fbfcfe;
        }}
        .metric-card h3 {{
            margin: 0 0 8px 0;
            font-size: 13px;
            color: #526070;
        }}
        .metric-card .value {{
            font-size: 24px;
            font-weight: 700;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
        }}
        th, td {{
            padding: 10px 12px;
            border-bottom: 1px solid #e4e8ef;
            text-align: left;
        }}
        th {{ background: #eef2f7; }}
        .ok {{ color: #137333; font-weight: 600; }}
        .bad {{ color: #b3261e; font-weight: 600; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>PPAASS QUIC UDP/443 Test Report</h1>
        <p><strong>Mode:</strong> {} &nbsp; <strong>Agent:</strong> {} &nbsp; <strong>Target:</strong> {}:{}</p>
        <p><strong>Duration:</strong> {} seconds &nbsp; <strong>Concurrency:</strong> {} &nbsp; <strong>Supported Versions:</strong> {}</p>

        <div class="summary">
            <div class="metric-card"><h3>Total Probes</h3><div class="value">{}</div></div>
            <div class="metric-card"><h3>VN Response Rate</h3><div class="value">{:.2}%</div></div>
            <div class="metric-card"><h3>Probes/sec</h3><div class="value">{:.2}</div></div>
            <div class="metric-card"><h3>Throughput</h3><div class="value">{:.2} Mbps</div></div>
        </div>

        <h2>QUIC RTT Metrics</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Version Negotiation Responses</td><td class="ok">{}</td></tr>
            <tr><td>Failed Probes</td><td class="bad">{}</td></tr>
            <tr><td>Average RTT</td><td>{:.3} ms</td></tr>
            <tr><td>Min RTT</td><td>{:.3} ms</td></tr>
            <tr><td>P50 RTT</td><td>{:.3} ms</td></tr>
            <tr><td>P95 RTT</td><td>{:.3} ms</td></tr>
            <tr><td>P99 RTT</td><td>{:.3} ms</td></tr>
            <tr><td>Max RTT</td><td>{:.3} ms</td></tr>
            <tr><td>Total Bytes Transferred</td><td>{}</td></tr>
        </table>

        <h2>System Metrics</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>CPU Usage</td><td>{:.2}%</td></tr>
            <tr><td>Memory Usage</td><td>{} MB</td></tr>
            <tr><td>Peak Memory</td><td>{} MB</td></tr>
        </table>
    </div>
</body>
</html>"#,
        results.test_mode,
        results.agent_addr,
        results.target_host,
        results.target_port,
        results.test_duration_secs,
        results.concurrency,
        versions,
        results.total_probes,
        results.response_rate_percent,
        results.probes_per_second,
        results.throughput_mbps,
        results.successful_vn_responses,
        results.failed_probes,
        metrics.avg_rtt_ms,
        metrics.min_rtt_ms,
        metrics.p50_rtt_ms,
        metrics.p95_rtt_ms,
        metrics.p99_rtt_ms,
        metrics.max_rtt_ms,
        metrics.total_bytes_transferred,
        results.system_metrics.cpu_usage_percent,
        results.system_metrics.memory_usage_mb,
        results.system_metrics.peak_memory_mb,
    );

    let mut file = File::create(path)?;
    file.write_all(html.as_bytes())?;
    Ok(())
}
