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
    /// 启动模拟目标服务器
    MockTarget {
        /// HTTP 服务器端口
        #[arg(long, default_value = "9090")]
        http_port: u16,

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
        Commands::MockTarget {
            http_port,
            tcp_port,
            udp_port,
        } => {
            tracing::info!(
                "正在端口上启动模拟目标服务器：HTTP={}，TCP={}，UDP={}",
                http_port,
                tcp_port,
                udp_port
            );
            mock_target::run_mock_servers(http_port, tcp_port, udp_port).await?;
        }
    }

    Ok(())
}
