use clap::{Parser, Subcommand};
use integration_test_support::performance_tests::ThroughputInterface;

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
    /// 自动爬升并发，寻找 client -> agent -> proxy -> target 全链路最高可持续吞吐
    MaxThroughput {
        /// 代理服务器地址（用于记录测试拓扑）
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        proxy_addr: String,

        /// Agent SOCKS5 监听地址
        #[arg(short, long, default_value = "127.0.0.1:7080")]
        agent_addr: String,

        /// TCP echo 目标主机
        #[arg(long, default_value = "127.0.0.1")]
        target_host: String,

        /// TCP echo 目标端口
        #[arg(long, default_value = "9091")]
        target_port: u16,

        /// UDP echo 目标主机
        #[arg(long, default_value = "127.0.0.1")]
        udp_target_host: String,

        /// UDP echo 目标端口
        #[arg(long, default_value = "9092")]
        udp_target_port: u16,

        /// 起始并发连接数
        #[arg(long, default_value = "1")]
        start_concurrency: usize,

        /// 最大并发连接数
        #[arg(long, default_value = "128")]
        max_concurrency: usize,

        /// 每个并发级别的测试时间（秒）
        #[arg(long, default_value = "10")]
        stage_duration: u64,

        /// 正式测试前的预热时间（秒，0 表示不预热）
        #[arg(long, default_value = "2")]
        warmup_duration: u64,

        /// 并发级别之间的冷却时间（秒）
        #[arg(long, default_value = "1")]
        settle_duration: u64,

        /// 每次往返校验的 payload 字节数
        #[arg(long, default_value = "65536")]
        payload_size: usize,

        /// 每个 UDP payload 的字节数
        #[arg(long, default_value = "1200")]
        udp_payload_size: usize,

        /// TUN 测试必须命中的网卡名；不指定时自动接受 tun*/utun*
        #[arg(long)]
        tun_interface: Option<String>,

        /// 仅运行指定接口；可重复传入，省略时运行全部接口
        #[arg(long, value_enum)]
        interface: Vec<ThroughputInterface>,

        /// 可参与峰值评选的最大失败率（百分比）
        #[arg(long, default_value = "1.0")]
        max_failure_rate: f64,

        /// 输出报告文件路径
        #[arg(short, long, default_value = "max-throughput-report.html")]
        output: String,
    },
    /// 合并分段最高吞吐 JSON，并重新生成统一的中文报告
    MergeMaxThroughput {
        /// 第一段最高吞吐 JSON 报告
        #[arg(long)]
        base: String,

        /// 后续分段 JSON 报告，可重复指定
        #[arg(long, required = true)]
        continuation: Vec<String>,

        /// 合并后的 HTML 报告路径
        #[arg(short, long, default_value = "max-throughput-report.html")]
        output: String,
    },
    /// 从已有 JSON 重新生成最高吞吐中文报告，不重跑测试
    RenderMaxThroughput {
        /// 已有的最高吞吐 JSON 报告
        #[arg(short, long, default_value = "max-throughput-report.json")]
        input: String,

        /// 重新生成的 HTML 报告路径
        #[arg(short, long, default_value = "max-throughput-report.html")]
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
