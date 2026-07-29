use crate::performance_tests::{
    LargeDownloadTestResults, PerformanceTestResults, QuicProbeTestResults,
    TcpPerformanceTestResults, UdpPerformanceTestResults,
};
use anyhow::Result;
use std::fs::File;
use std::io::Write;
use tracing::info;

mod html;
mod json;
mod markdown;

use html::*;
use json::*;
use markdown::*;

/// 生成所有性能报告（JSON、Markdown 和 HTML）
pub fn generate_reports(results: &PerformanceTestResults, output_path: &str) -> Result<()> {
    // 生成 JSON 报告
    let json_path = output_path.replace(".html", ".json");
    generate_json_report(results, &json_path)?;
    info!("JSON 报告已生成：{}", json_path);

    // 生成 Markdown 报告
    let md_path = output_path.replace(".html", ".md");
    generate_markdown_report(results, &md_path)?;
    info!("Markdown 报告已生成：{}", md_path);

    // 生成 HTML 报告
    generate_html_report(results, output_path)?;
    info!("HTML 报告已生成：{}", output_path);

    Ok(())
}

/// 生成 UDP 专项性能报告（JSON、Markdown 和 HTML）
pub fn generate_udp_reports(results: &UdpPerformanceTestResults, output_path: &str) -> Result<()> {
    let json_path = output_path.replace(".html", ".json");
    generate_udp_json_report(results, &json_path)?;
    info!("UDP JSON 报告已生成：{}", json_path);

    let md_path = output_path.replace(".html", ".md");
    generate_udp_markdown_report(results, &md_path)?;
    info!("UDP Markdown 报告已生成：{}", md_path);

    generate_udp_html_report(results, output_path)?;
    info!("UDP HTML 报告已生成：{}", output_path);

    Ok(())
}

/// 生成 TCP 专项性能报告（JSON、Markdown 和 HTML）
pub fn generate_tcp_reports(results: &TcpPerformanceTestResults, output_path: &str) -> Result<()> {
    let json_path = output_path.replace(".html", ".json");
    generate_tcp_json_report(results, &json_path)?;
    info!("TCP JSON 报告已生成：{}", json_path);

    let md_path = output_path.replace(".html", ".md");
    generate_tcp_markdown_report(results, &md_path)?;
    info!("TCP Markdown 报告已生成：{}", md_path);

    generate_tcp_html_report(results, output_path)?;
    info!("TCP HTML 报告已生成：{}", output_path);

    Ok(())
}

/// 生成 QUIC/UDP443 专项报告（JSON、Markdown 和 HTML）
pub fn generate_quic_reports(results: &QuicProbeTestResults, output_path: &str) -> Result<()> {
    let json_path = output_path.replace(".html", ".json");
    generate_quic_json_report(results, &json_path)?;
    info!("QUIC JSON 报告已生成：{}", json_path);

    let md_path = output_path.replace(".html", ".md");
    generate_quic_markdown_report(results, &md_path)?;
    info!("QUIC Markdown 报告已生成：{}", md_path);

    generate_quic_html_report(results, output_path)?;
    info!("QUIC HTML 报告已生成：{}", output_path);

    Ok(())
}

/// 生成 HTTP Range 分片大文件下载报告（JSON、Markdown 和 HTML）
pub fn generate_large_download_reports(
    results: &LargeDownloadTestResults,
    output_path: &str,
) -> Result<()> {
    let json_path = output_path.replace(".html", ".json");
    generate_large_download_json_report(results, &json_path)?;
    info!("Large download JSON 报告已生成：{}", json_path);

    let md_path = output_path.replace(".html", ".md");
    generate_large_download_markdown_report(results, &md_path)?;
    info!("Large download Markdown 报告已生成：{}", md_path);

    generate_large_download_html_report(results, output_path)?;
    info!("Large download HTML 报告已生成：{}", output_path);

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
