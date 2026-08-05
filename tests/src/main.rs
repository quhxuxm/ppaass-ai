mod cli;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};
use integration_test_support::{integration_tests, mock_target, performance_tests, report};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    // 初始化 tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Integration {
            proxy_addr,
            agent_addr,
        } => {
            tracing::info!("正在运行集成测试");
            tracing::info!("代理：{}，Agent：{}", proxy_addr, agent_addr);
            integration_tests::run_all_tests(&agent_addr).await?;
        }
        Commands::Performance {
            proxy_addr,
            agent_addr,
            concurrency,
            duration,
            output,
        } => {
            tracing::info!("正在运行性能测试");
            tracing::info!("代理：{}，Agent：{}", proxy_addr, agent_addr);
            tracing::info!("并发数：{}，持续时间：{} 秒", concurrency, duration);

            let results =
                performance_tests::run_performance_tests(&agent_addr, concurrency, duration)
                    .await?;

            report::generate_reports(&results, &output)?;
            tracing::info!("性能报告已生成：{}", output);
        }
        Commands::UdpPerformance {
            proxy_addr,
            agent_addr,
            target_host,
            target_port,
            concurrency,
            duration,
            payload_size,
            output,
        } => {
            tracing::info!("正在运行 UDP 专项性能测试");
            tracing::info!("代理：{}，Agent：{}", proxy_addr, agent_addr);
            tracing::info!(
                "目标：{}:{}，并发 flow：{}，payload={} bytes，持续时间：{} 秒",
                target_host,
                target_port,
                concurrency,
                payload_size,
                duration
            );

            let results = performance_tests::run_udp_performance_tests(
                &agent_addr,
                &target_host,
                target_port,
                concurrency,
                duration,
                payload_size,
            )
            .await?;

            report::generate_udp_reports(&results, &output)?;
            tracing::info!("UDP 性能报告已生成：{}", output);
        }
        Commands::TcpPerformance {
            proxy_addr,
            agent_addr,
            target_host,
            target_port,
            concurrency,
            duration,
            payload_size,
            output,
        } => {
            tracing::info!("正在运行 TCP 专项性能测试");
            tracing::info!("代理：{}，Agent：{}", proxy_addr, agent_addr);
            tracing::info!(
                "目标：{}:{}，并发连接：{}，payload={} bytes，持续时间：{} 秒",
                target_host,
                target_port,
                concurrency,
                payload_size,
                duration
            );

            let results = performance_tests::run_tcp_performance_tests(
                &agent_addr,
                &target_host,
                target_port,
                concurrency,
                duration,
                payload_size,
            )
            .await?;

            report::generate_tcp_reports(&results, &output)?;
            tracing::info!("TCP 性能报告已生成：{}", output);
        }
        Commands::LargeDownload {
            proxy_addr,
            agent_addr,
            file_size_mb,
            chunk_size_kb,
            concurrency,
            rounds,
            connect_tunnel,
            output,
        } => {
            tracing::info!("正在运行 HTTP Range 分片大文件下载测试");
            tracing::info!("代理：{}，Agent：{}", proxy_addr, agent_addr);
            tracing::info!(
                "file={} MB，chunk={} KB，并发分片：{}，轮次：{}，CONNECT tunnel={}",
                file_size_mb,
                chunk_size_kb,
                concurrency,
                rounds,
                connect_tunnel
            );

            let results = performance_tests::run_large_download_tests(
                &agent_addr,
                file_size_mb.saturating_mul(1024 * 1024),
                chunk_size_kb.saturating_mul(1024),
                concurrency,
                rounds,
                connect_tunnel,
            )
            .await?;

            report::generate_large_download_reports(&results, &output)?;
            tracing::info!("HTTP Range 分片大文件下载报告已生成：{}", output);
        }
        Commands::QuicProbe {
            proxy_addr,
            agent_addr,
            target_host,
            target_port,
            attempts,
            timeout_ms,
            output,
        } => {
            tracing::info!("正在运行 QUIC Version Negotiation 探针");
            tracing::info!("代理：{}，Agent：{}", proxy_addr, agent_addr);
            tracing::info!(
                "目标：{}:{}，attempts={}，timeout={}ms",
                target_host,
                target_port,
                attempts,
                timeout_ms
            );

            let results = performance_tests::run_quic_probe_tests(
                &agent_addr,
                &target_host,
                target_port,
                attempts,
                timeout_ms,
            )
            .await?;

            report::generate_quic_reports(&results, &output)?;
            tracing::info!("QUIC 探针报告已生成：{}", output);
        }
        Commands::QuicPerformance {
            proxy_addr,
            agent_addr,
            target_host,
            target_port,
            concurrency,
            duration,
            timeout_ms,
            output,
        } => {
            tracing::info!("正在运行 QUIC UDP/443 专项压测");
            tracing::info!("代理：{}，Agent：{}", proxy_addr, agent_addr);
            tracing::info!(
                "目标：{}:{}，并发 flow：{}，持续时间：{} 秒，timeout={}ms",
                target_host,
                target_port,
                concurrency,
                duration,
                timeout_ms
            );

            let results = performance_tests::run_quic_performance_tests(
                &agent_addr,
                &target_host,
                target_port,
                concurrency,
                duration,
                timeout_ms,
            )
            .await?;

            report::generate_quic_reports(&results, &output)?;
            tracing::info!("QUIC 压测报告已生成：{}", output);
        }
        Commands::MockTarget {
            http_port,
            h2_port,
            tcp_port,
            udp_port,
        } => {
            tracing::info!(
                "正在端口上启动模拟目标服务器：HTTP={}，H2={}，TCP={}，UDP={}",
                http_port,
                h2_port,
                tcp_port,
                udp_port
            );
            mock_target::run_mock_servers(http_port, h2_port, tcp_port, udp_port).await?;
        }
    }

    Ok(())
}
