use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "integration-tests")]
#[command(about = "PPAASS 代理的集成与性能测试工具")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
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
