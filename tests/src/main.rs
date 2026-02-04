pub mod mock_client;
pub mod mock_target;
pub mod integration_tests;
pub mod performance_tests;
pub mod report;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "integration-tests")]
#[command(about = "Integration and performance testing tool for PPAASS proxy")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run integration tests
    Integration {
        /// Proxy server address (e.g., "127.0.0.1:8080")
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        proxy_addr: String,
        
        /// Agent server address (e.g., "127.0.0.1:7070")
        #[arg(short, long, default_value = "127.0.0.1:7070")]
        agent_addr: String,
    },
    /// Run performance tests
    Performance {
        /// Proxy server address
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        proxy_addr: String,
        
        /// Agent server address
        #[arg(short, long, default_value = "127.0.0.1:7070")]
        agent_addr: String,
        
        /// Number of concurrent connections to test
        #[arg(short, long, default_value = "100")]
        concurrency: usize,
        
        /// Duration of test in seconds
        #[arg(short, long, default_value = "60")]
        duration: u64,
        
        /// Output report file path
        #[arg(short, long, default_value = "performance-report.html")]
        output: String,
    },
    /// Start mock target servers
    MockTarget {
        /// HTTP server port
        #[arg(long, default_value = "9090")]
        http_port: u16,
        
        /// TCP echo server port
        #[arg(long, default_value = "9091")]
        tcp_port: u16,

        /// UDP echo server port
        #[arg(long, default_value = "9092")]
        udp_port: u16,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info"))
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Integration { proxy_addr, agent_addr } => {
            tracing::info!("Running integration tests");
            tracing::info!("Proxy: {}, Agent: {}", proxy_addr, agent_addr);
            integration_tests::run_all_tests(&agent_addr).await?;
        }
        Commands::Performance { 
            proxy_addr, 
            agent_addr, 
            concurrency, 
            duration,
            output 
        } => {
            tracing::info!("Running performance tests");
            tracing::info!("Proxy: {}, Agent: {}", proxy_addr, agent_addr);
            tracing::info!("Concurrency: {}, Duration: {}s", concurrency, duration);
            
            let results = performance_tests::run_performance_tests(
                &agent_addr,
                concurrency,
                duration,
            ).await?;
            
            report::generate_reports(&results, &output)?;
            tracing::info!("Performance report generated: {}", output);
        }
        Commands::MockTarget { http_port, tcp_port, udp_port } => {
            tracing::info!("Starting mock target servers on ports: HTTP={}, TCP={}, UDP={}", http_port, tcp_port, udp_port);
            mock_target::run_mock_servers(http_port, tcp_port, udp_port).await?;
        }
    }

    Ok(())
}
