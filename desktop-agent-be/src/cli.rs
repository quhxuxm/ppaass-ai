use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct CliArgs {
    /// 以 macOS TUN helper 服务模式运行当前 desktop-agent 二进制
    #[arg(long, hide = true)]
    pub tun_helper_service: bool,

    /// 覆盖 macOS 本地特权 TUN helper 的 socket 路径
    #[arg(long, hide = true)]
    pub tun_helper_socket: Option<String>,

    /// 限制允许连接 macOS TUN helper socket 的用户 UID
    #[arg(long, hide = true)]
    pub tun_helper_allowed_uid: Option<u32>,

    /// helper 服务日志级别
    #[arg(long, hide = true)]
    pub log_level: Option<String>,
}
