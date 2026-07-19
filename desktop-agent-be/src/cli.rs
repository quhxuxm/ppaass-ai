use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct CliArgs {
    /// 配置文件路径
    #[arg(short, long, default_value = "config/agent.toml")]
    pub config: String,

    /// 覆盖监听地址
    #[arg(short, long)]
    pub listen: Option<String>,

    /// 覆盖代理服务器地址
    #[arg(short, long)]
    pub proxy: Option<String>,

    /// 覆盖用户名
    #[arg(short, long)]
    pub username: Option<String>,

    /// 覆盖日志级别（trace、debug、info、warn、error）
    #[arg(long)]
    pub log_level: Option<String>,

    /// 覆盖日志目录
    #[arg(long)]
    pub log_dir: Option<String>,

    /// 覆盖日志文件名
    #[arg(long)]
    pub log_file: Option<String>,

    /// 覆盖 framed TCP/TCP-Yamux 消息压缩模式（none、lz4、gzip、zstd）；原生 UDP 不压缩
    #[arg(long)]
    pub compression_mode: Option<String>,

    /// 覆盖运行时工作线程数
    #[arg(long)]
    pub runtime_threads: Option<usize>,

    // ── TUN 模式 ──────────────────────────────────────────────────────────────
    /// 启用 TUN 模式（将所有系统流量通过 TUN 设备转发）
    #[arg(long)]
    pub tun_enabled: bool,

    /// 覆盖 TUN 设备名称（Windows 如 ppaass-tun，macOS 如 utun8，Linux 如 tun0）
    #[arg(long)]
    pub tun_name: Option<String>,

    /// 覆盖 TUN IPv4 CIDR（如 10.10.10.1/24）
    #[arg(long)]
    pub tun_ipv4: Option<String>,

    /// 覆盖 TUN IPv6 CIDR（如 fd00::1/64）
    #[arg(long)]
    pub tun_ipv6: Option<String>,

    /// 覆盖 TUN MTU
    #[arg(long)]
    pub tun_mtu: Option<u16>,

    /// 覆盖 Windows TUN 运行库 wintun.dll 路径
    #[arg(long)]
    pub tun_wintun_file: Option<String>,

    /// 禁用 macOS 本地特权 TUN helper，回到旧的整进程提权路径
    #[arg(long)]
    pub tun_no_helper: bool,

    /// 覆盖 macOS 本地特权 TUN helper 的 socket 路径
    #[arg(long)]
    pub tun_helper_socket: Option<String>,

    /// helper 不可用时不回退到 sudo/UAC 整进程提权
    #[arg(long)]
    pub tun_helper_no_fallback: bool,

    /// 以 macOS TUN helper 服务模式运行当前 desktop-agent 二进制
    #[arg(long, hide = true)]
    pub tun_helper_service: bool,

    /// 限制允许连接 macOS TUN helper socket 的用户 UID
    #[arg(long, hide = true)]
    pub tun_helper_allowed_uid: Option<u32>,
}
