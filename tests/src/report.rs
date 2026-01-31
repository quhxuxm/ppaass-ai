use crate::performance_tests::PerformanceTestResults;
use anyhow::Result;
use std::fs::File;
use std::io::Write;
use tracing::info;

/// Generate all performance reports (JSON, Markdown, and HTML)
pub fn generate_reports(results: &PerformanceTestResults, output_path: &str) -> Result<()> {
    // Generate JSON report
    let json_path = output_path.replace(".html", ".json");
    generate_json_report(results, &json_path)?;
    info!("JSON report generated: {}", json_path);

    // Generate Markdown report
    let md_path = output_path.replace(".html", ".md");
    generate_markdown_report(results, &md_path)?;
    info!("Markdown report generated: {}", md_path);

    // Generate HTML report
    generate_html_report(results, output_path)?;
    info!("HTML report generated: {}", output_path);

    Ok(())
}

/// Generate JSON report
fn generate_json_report(results: &PerformanceTestResults, path: &str) -> Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

/// Generate Markdown report
fn generate_markdown_report(results: &PerformanceTestResults, path: &str) -> Result<()> {
    let mut content = String::new();
    
    content.push_str("# PPAASS Proxy Performance Test Report\n\n");
    content.push_str(&format!("**Test Duration:** {} seconds\n\n", results.test_duration_secs));
    
    content.push_str("## Summary\n\n");
    content.push_str(&format!("- **Total Requests:** {}\n", results.total_requests));
    content.push_str(&format!("- **Successful Requests:** {}\n", results.successful_requests));
    content.push_str(&format!("- **Failed Requests:** {}\n", results.failed_requests));
    
    if results.total_requests > 0 {
        content.push_str(&format!("- **Success Rate:** {:.2}%\n", 
            (results.successful_requests as f64 / results.total_requests as f64) * 100.0));
    } else {
        content.push_str("- **Success Rate:** N/A (no requests completed)\n");
    }
    
    content.push_str(&format!("- **Requests per Second:** {:.2}\n", results.requests_per_second));
    content.push_str(&format!("- **Throughput:** {:.2} Mbps\n\n", results.throughput_mbps));
    
    content.push_str("## HTTP Metrics\n\n");
    content.push_str("| Metric | Value |\n");
    content.push_str("|--------|-------|\n");
    content.push_str(&format!("| Total Requests | {} |\n", results.http_metrics.total_requests));
    content.push_str(&format!("| Successful | {} |\n", results.http_metrics.successful));
    content.push_str(&format!("| Failed | {} |\n", results.http_metrics.failed));
    content.push_str(&format!("| Avg Latency | {:.2} ms |\n", results.http_metrics.avg_latency_ms));
    content.push_str(&format!("| Min Latency | {:.2} ms |\n", results.http_metrics.min_latency_ms));
    content.push_str(&format!("| Max Latency | {:.2} ms |\n", results.http_metrics.max_latency_ms));
    content.push_str(&format!("| P50 Latency | {:.2} ms |\n", results.http_metrics.p50_latency_ms));
    content.push_str(&format!("| P95 Latency | {:.2} ms |\n", results.http_metrics.p95_latency_ms));
    content.push_str(&format!("| P99 Latency | {:.2} ms |\n\n", results.http_metrics.p99_latency_ms));
    
    content.push_str("## SOCKS5 Metrics\n\n");
    content.push_str("| Metric | Value |\n");
    content.push_str("|--------|-------|\n");
    content.push_str(&format!("| Total Requests | {} |\n", results.socks5_metrics.total_requests));
    content.push_str(&format!("| Successful | {} |\n", results.socks5_metrics.successful));
    content.push_str(&format!("| Failed | {} |\n", results.socks5_metrics.failed));
    content.push_str(&format!("| Avg Latency | {:.2} ms |\n", results.socks5_metrics.avg_latency_ms));
    content.push_str(&format!("| Min Latency | {:.2} ms |\n", results.socks5_metrics.min_latency_ms));
    content.push_str(&format!("| Max Latency | {:.2} ms |\n", results.socks5_metrics.max_latency_ms));
    content.push_str(&format!("| P50 Latency | {:.2} ms |\n", results.socks5_metrics.p50_latency_ms));
    content.push_str(&format!("| P95 Latency | {:.2} ms |\n", results.socks5_metrics.p95_latency_ms));
    content.push_str(&format!("| P99 Latency | {:.2} ms |\n\n", results.socks5_metrics.p99_latency_ms));
    
    content.push_str("## System Metrics\n\n");
    content.push_str(&format!("- **CPU Usage:** {:.2}%\n", results.system_metrics.cpu_usage_percent));
    content.push_str(&format!("- **Memory Usage:** {} MB\n", results.system_metrics.memory_usage_mb));
    content.push_str(&format!("- **Peak Memory:** {} MB\n", results.system_metrics.peak_memory_mb));
    
    let mut file = File::create(path)?;
    file.write_all(content.as_bytes())?;
    Ok(())
}

/// Generate HTML report with charts
fn generate_html_report(results: &PerformanceTestResults, path: &str) -> Result<()> {
    let success_rate = if results.total_requests > 0 {
        (results.successful_requests as f64 / results.total_requests as f64) * 100.0
    } else {
        0.0
    };
    
    let html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PPAASS Proxy Performance Test Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #4CAF50;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #555;
            margin-top: 30px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .metric-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .metric-card h3 {{
            margin: 0 0 10px 0;
            font-size: 14px;
            opacity: 0.9;
        }}
        .metric-card .value {{
            font-size: 28px;
            font-weight: bold;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #4CAF50;
            color: white;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .chart-container {{
            position: relative;
            height: 400px;
            margin: 30px 0;
        }}
        .success {{
            color: #4CAF50;
            font-weight: bold;
        }}
        .error {{
            color: #f44336;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>PPAASS Proxy Performance Test Report</h1>
        <p><strong>Test Duration:</strong> {} seconds</p>
        
        <h2>Summary</h2>
        <div class="summary">
            <div class="metric-card">
                <h3>Total Requests</h3>
                <div class="value">{}</div>
            </div>
            <div class="metric-card">
                <h3>Success Rate</h3>
                <div class="value">{:.2}%</div>
            </div>
            <div class="metric-card">
                <h3>Requests/sec</h3>
                <div class="value">{:.2}</div>
            </div>
            <div class="metric-card">
                <h3>Throughput</h3>
                <div class="value">{:.2} Mbps</div>
            </div>
        </div>

        <h2>Request Distribution</h2>
        <div class="chart-container">
            <canvas id="requestChart"></canvas>
        </div>

        <h2>HTTP Metrics</h2>
        <table>
            <tr>
                <th>Metric</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>Total Requests</td>
                <td>{}</td>
            </tr>
            <tr>
                <td>Successful</td>
                <td class="success">{}</td>
            </tr>
            <tr>
                <td>Failed</td>
                <td class="error">{}</td>
            </tr>
            <tr>
                <td>Average Latency</td>
                <td>{:.2} ms</td>
            </tr>
            <tr>
                <td>Min Latency</td>
                <td>{:.2} ms</td>
            </tr>
            <tr>
                <td>Max Latency</td>
                <td>{:.2} ms</td>
            </tr>
            <tr>
                <td>P50 Latency</td>
                <td>{:.2} ms</td>
            </tr>
            <tr>
                <td>P95 Latency</td>
                <td>{:.2} ms</td>
            </tr>
            <tr>
                <td>P99 Latency</td>
                <td>{:.2} ms</td>
            </tr>
        </table>

        <h2>HTTP Latency Distribution</h2>
        <div class="chart-container">
            <canvas id="httpLatencyChart"></canvas>
        </div>

        <h2>SOCKS5 Metrics</h2>
        <table>
            <tr>
                <th>Metric</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>Total Requests</td>
                <td>{}</td>
            </tr>
            <tr>
                <td>Successful</td>
                <td class="success">{}</td>
            </tr>
            <tr>
                <td>Failed</td>
                <td class="error">{}</td>
            </tr>
            <tr>
                <td>Average Latency</td>
                <td>{:.2} ms</td>
            </tr>
            <tr>
                <td>Min Latency</td>
                <td>{:.2} ms</td>
            </tr>
            <tr>
                <td>Max Latency</td>
                <td>{:.2} ms</td>
            </tr>
            <tr>
                <td>P50 Latency</td>
                <td>{:.2} ms</td>
            </tr>
            <tr>
                <td>P95 Latency</td>
                <td>{:.2} ms</td>
            </tr>
            <tr>
                <td>P99 Latency</td>
                <td>{:.2} ms</td>
            </tr>
        </table>

        <h2>SOCKS5 Latency Distribution</h2>
        <div class="chart-container">
            <canvas id="socks5LatencyChart"></canvas>
        </div>

        <h2>System Metrics</h2>
        <table>
            <tr>
                <th>Metric</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>CPU Usage</td>
                <td>{:.2}%</td>
            </tr>
            <tr>
                <td>Memory Usage</td>
                <td>{} MB</td>
            </tr>
            <tr>
                <td>Peak Memory</td>
                <td>{} MB</td>
            </tr>
        </table>
    </div>

    <script>
        // Request Distribution Chart
        new Chart(document.getElementById('requestChart'), {{
            type: 'bar',
            data: {{
                labels: ['HTTP', 'SOCKS5'],
                datasets: [{{
                    label: 'Successful',
                    data: [{}, {}],
                    backgroundColor: 'rgba(76, 175, 80, 0.8)'
                }}, {{
                    label: 'Failed',
                    data: [{}, {}],
                    backgroundColor: 'rgba(244, 67, 54, 0.8)'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                scales: {{
                    y: {{
                        beginAtZero: true
                    }}
                }}
            }}
        }});

        // HTTP Latency Distribution
        new Chart(document.getElementById('httpLatencyChart'), {{
            type: 'bar',
            data: {{
                labels: ['Min', 'P50', 'Avg', 'P95', 'P99', 'Max'],
                datasets: [{{
                    label: 'Latency (ms)',
                    data: [{:.2}, {:.2}, {:.2}, {:.2}, {:.2}, {:.2}],
                    backgroundColor: 'rgba(54, 162, 235, 0.8)'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                scales: {{
                    y: {{
                        beginAtZero: true,
                        title: {{
                            display: true,
                            text: 'Milliseconds'
                        }}
                    }}
                }}
            }}
        }});

        // SOCKS5 Latency Distribution
        new Chart(document.getElementById('socks5LatencyChart'), {{
            type: 'bar',
            data: {{
                labels: ['Min', 'P50', 'Avg', 'P95', 'P99', 'Max'],
                datasets: [{{
                    label: 'Latency (ms)',
                    data: [{:.2}, {:.2}, {:.2}, {:.2}, {:.2}, {:.2}],
                    backgroundColor: 'rgba(153, 102, 255, 0.8)'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                scales: {{
                    y: {{
                        beginAtZero: true,
                        title: {{
                            display: true,
                            text: 'Milliseconds'
                        }}
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>"#,
        results.test_duration_secs,
        results.total_requests,
        success_rate,
        results.requests_per_second,
        results.throughput_mbps,
        results.http_metrics.total_requests,
        results.http_metrics.successful,
        results.http_metrics.failed,
        results.http_metrics.avg_latency_ms,
        results.http_metrics.min_latency_ms,
        results.http_metrics.max_latency_ms,
        results.http_metrics.p50_latency_ms,
        results.http_metrics.p95_latency_ms,
        results.http_metrics.p99_latency_ms,
        results.socks5_metrics.total_requests,
        results.socks5_metrics.successful,
        results.socks5_metrics.failed,
        results.socks5_metrics.avg_latency_ms,
        results.socks5_metrics.min_latency_ms,
        results.socks5_metrics.max_latency_ms,
        results.socks5_metrics.p50_latency_ms,
        results.socks5_metrics.p95_latency_ms,
        results.socks5_metrics.p99_latency_ms,
        results.system_metrics.cpu_usage_percent,
        results.system_metrics.memory_usage_mb,
        results.system_metrics.peak_memory_mb,
        results.http_metrics.successful,
        results.socks5_metrics.successful,
        results.http_metrics.failed,
        results.socks5_metrics.failed,
        results.http_metrics.min_latency_ms,
        results.http_metrics.p50_latency_ms,
        results.http_metrics.avg_latency_ms,
        results.http_metrics.p95_latency_ms,
        results.http_metrics.p99_latency_ms,
        results.http_metrics.max_latency_ms,
        results.socks5_metrics.min_latency_ms,
        results.socks5_metrics.p50_latency_ms,
        results.socks5_metrics.avg_latency_ms,
        results.socks5_metrics.p95_latency_ms,
        results.socks5_metrics.p99_latency_ms,
        results.socks5_metrics.max_latency_ms,
    );

    let mut file = File::create(path)?;
    file.write_all(html.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::performance_tests::{RequestMetrics, SystemMetrics};

    #[test]
    fn test_json_report_generation() -> Result<()> {
        let results = PerformanceTestResults {
            test_duration_secs: 60,
            total_requests: 1000,
            successful_requests: 950,
            failed_requests: 50,
            requests_per_second: 16.67,
            throughput_mbps: 10.5,
            http_metrics: RequestMetrics {
                total_requests: 600,
                successful: 570,
                failed: 30,
                avg_latency_ms: 50.0,
                min_latency_ms: 10.0,
                max_latency_ms: 200.0,
                p50_latency_ms: 45.0,
                p95_latency_ms: 100.0,
                p99_latency_ms: 150.0,
                total_bytes_transferred: 1024000,
            },
            socks5_metrics: RequestMetrics {
                total_requests: 400,
                successful: 380,
                failed: 20,
                avg_latency_ms: 40.0,
                min_latency_ms: 8.0,
                max_latency_ms: 180.0,
                p50_latency_ms: 38.0,
                p95_latency_ms: 90.0,
                p99_latency_ms: 140.0,
                total_bytes_transferred: 512000,
            },
            system_metrics: SystemMetrics {
                cpu_usage_percent: 45.5,
                memory_usage_mb: 256,
                peak_memory_mb: 300,
            },
        };

        let temp_dir = std::env::temp_dir();
        let json_path = temp_dir.join("test_report.json");
        generate_json_report(&results, json_path.to_str().unwrap())?;
        
        assert!(json_path.exists());
        std::fs::remove_file(json_path)?;
        
        Ok(())
    }
}
