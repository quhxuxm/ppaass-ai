pub mod integration_tests;
pub mod mock_client;
pub mod mock_target;
pub mod performance_tests;
pub mod report;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "integration-tests")]
#[command(about = "PPAASS 代理的集成与性能测试工具")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 运行集成测试
    Integration {
        /// 代理服务器地址（例如 "127.0.0.1:8080"）
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        proxy_addr: String,

        /// Agent 服务器地址（例如 "127.0.0.1:7070"）
        #[arg(short, long, default_value = "127.0.0.1:7070")]
        agent_addr: String,
    },
    /// 运行性能测试
    Performance {
        /// 代理服务器地址
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        proxy_addr: String,

        /// Agent 服务器地址
        #[arg(short, long, default_value = "127.0.0.1:7070")]
        agent_addr: String,

        /// 要测试的并发连接数
        #[arg(short, long, default_value = "100")]
        concurrency: usize,

        /// 测试持续时间（秒）
        #[arg(short, long, default_value = "60")]
        duration: u64,

        /// 输出报告文件路径
        #[arg(short, long, default_value = "performance-report.html")]
        output: String,
    },
    /// 运行 UDP 专项性能测试（SOCKS5 UDP ASSOCIATE -> UDP echo）
    UdpPerformance {
        /// 代理服务器地址
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        proxy_addr: String,

        /// Agent 服务器地址
        #[arg(short, long, default_value = "127.0.0.1:7070")]
        agent_addr: String,

        /// UDP echo 目标主机
        #[arg(long, default_value = "127.0.0.1")]
        target_host: String,

        /// UDP echo 目标端口
        #[arg(long, default_value = "9092")]
        target_port: u16,

        /// 并发 UDP flow 数
        #[arg(short, long, default_value = "100")]
        concurrency: usize,

        /// 测试持续时间（秒）
        #[arg(short, long, default_value = "60")]
        duration: u64,

        /// 每个 UDP payload 的字节数
        #[arg(long, default_value = "1200")]
        payload_size: usize,

        /// 输出报告文件路径
        #[arg(short, long, default_value = "udp-performance-report.html")]
        output: String,
    },
    /// 运行 TCP 专项性能测试（SOCKS5 CONNECT -> TCP echo）
    TcpPerformance {
        /// 代理服务器地址
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        proxy_addr: String,

        /// Agent 服务器地址
        #[arg(short, long, default_value = "127.0.0.1:7070")]
        agent_addr: String,

        /// TCP echo 目标主机
        #[arg(long, default_value = "127.0.0.1")]
        target_host: String,

        /// TCP echo 目标端口
        #[arg(long, default_value = "9091")]
        target_port: u16,

        /// 并发 TCP 连接数
        #[arg(short, long, default_value = "100")]
        concurrency: usize,

        /// 测试持续时间（秒）
        #[arg(short, long, default_value = "60")]
        duration: u64,

        /// 每次写入的 TCP payload 字节数
        #[arg(long, default_value = "65536")]
        payload_size: usize,

        /// 输出报告文件路径
        #[arg(short, long, default_value = "tcp-performance-report.html")]
        output: String,
    },
    /// 运行 HTTP Range 分片大文件下载测试
    LargeDownload {
        /// 代理服务器地址
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        proxy_addr: String,

        /// Agent 服务器地址
        #[arg(short, long, default_value = "127.0.0.1:7070")]
        agent_addr: String,

        /// 虚拟大文件大小（MB）
        #[arg(long, default_value = "64")]
        file_size_mb: u64,

        /// 每个 Range 分片大小（KB）
        #[arg(long, default_value = "1024")]
        chunk_size_kb: u64,

        /// 并发 Range 请求数
        #[arg(short, long, default_value = "16")]
        concurrency: usize,

        /// 完整文件下载轮次
        #[arg(long, default_value = "1")]
        rounds: usize,

        /// 先通过 HTTP CONNECT 建立隧道，再在隧道内执行 Range 分片下载
        #[arg(long)]
        connect_tunnel: bool,

        /// 输出报告文件路径
        #[arg(short, long, default_value = "large-download-report.html")]
        output: String,
    },
    /// 运行 QUIC Version Negotiation 连通性探针（SOCKS5 UDP -> UDP/443）
    QuicProbe {
        /// 代理服务器地址
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        proxy_addr: String,

        /// Agent 服务器地址
        #[arg(short, long, default_value = "127.0.0.1:7070")]
        agent_addr: String,

        /// QUIC 目标主机，支持域名或 IP
        #[arg(long, default_value = "cloudflare.com")]
        target_host: String,

        /// QUIC 目标端口
        #[arg(long, default_value = "443")]
        target_port: u16,

        /// 探针次数
        #[arg(long, default_value = "20")]
        attempts: usize,

        /// 单次探针超时时间（毫秒）
        #[arg(long, default_value = "3000")]
        timeout_ms: u64,

        /// 输出报告文件路径
        #[arg(short, long, default_value = "quic-probe-report.html")]
        output: String,
    },
    /// 运行 QUIC UDP/443 专项压测（重复发送 Version Negotiation 探针）
    QuicPerformance {
        /// 代理服务器地址
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        proxy_addr: String,

        /// Agent 服务器地址
        #[arg(short, long, default_value = "127.0.0.1:7070")]
        agent_addr: String,

        /// QUIC 目标主机，支持域名或 IP
        #[arg(long, default_value = "cloudflare.com")]
        target_host: String,

        /// QUIC 目标端口
        #[arg(long, default_value = "443")]
        target_port: u16,

        /// 并发 UDP/443 flow 数
        #[arg(short, long, default_value = "20")]
        concurrency: usize,

        /// 测试持续时间（秒）
        #[arg(short, long, default_value = "30")]
        duration: u64,

        /// 单次探针超时时间（毫秒）
        #[arg(long, default_value = "3000")]
        timeout_ms: u64,

        /// 输出报告文件路径
        #[arg(short, long, default_value = "quic-performance-report.html")]
        output: String,
    },
    /// 启动模拟目标服务器
    MockTarget {
        /// HTTP 服务器端口
        #[arg(long, default_value = "9090")]
        http_port: u16,

        /// HTTP/2 cleartext 服务器端口
        #[arg(long, default_value = "9093")]
        h2_port: u16,

        /// TCP 回显服务器端口
        #[arg(long, default_value = "9091")]
        tcp_port: u16,

        /// UDP 回显服务器端口
        #[arg(long, default_value = "9092")]
        udp_port: u16,
    },
}

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
