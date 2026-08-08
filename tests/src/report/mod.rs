use crate::performance_tests::{
    DirectionalLoss, InterfaceTestStatus, InterfaceThroughputResult, LargeDownloadTestResults,
    MaxThroughputTestResults, PerformanceTestResults, QuicProbeTestResults,
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

/// 生成端到端最高吞吐报告（JSON、Markdown 和 HTML）
pub fn generate_max_throughput_reports(
    results: &MaxThroughputTestResults,
    output_path: &str,
) -> Result<()> {
    let json_path = output_path.replace(".html", ".json");
    generate_max_throughput_json_report(results, &json_path)?;
    info!("最高吞吐 JSON 报告已生成：{}", json_path);

    let md_path = output_path.replace(".html", ".md");
    generate_max_throughput_markdown_report(results, &md_path)?;
    info!("最高吞吐 Markdown 报告已生成：{}", md_path);

    generate_max_throughput_html_report(results, output_path)?;
    info!("最高吞吐 HTML 报告已生成：{}", output_path);
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
