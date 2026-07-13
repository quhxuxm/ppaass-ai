//! Desktop Agent 配置模型。
//!
//! 这里定义 agent.toml 的运行时结构：本地监听、proxy 地址/认证私钥、
//! Yamux、direct_access 和 TUN 模式。字段上的 serde default 决定了配置缺省行为。

use crate::direct_access::DirectAccessConfig;
use common::{QuicPolicy, TransportMode, YamuxConfig, tun_control::DEFAULT_TUN_HELPER_SOCKET_PATH};
use protocol::CompressionMode;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    pub proxy_addrs: Vec<String>,
    pub username: String,
    pub private_key_path: String,
    /// Agent 到 proxy 的外层传输。默认使用 QUIC；tcp 用于兼容旧 proxy。
    #[serde(default)]
    pub transport_mode: TransportMode,
    #[serde(default = "default_async_runtime_stack_size_mb")]
    pub async_runtime_stack_size_mb: usize,

    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,

    /// Agent -> proxy 消息压缩模式：none、lz4、gzip、zstd。
    /// 适用于 TUN、SOCKS5、HTTP/CONNECT 中所有走 proxy 的流量。
    #[serde(default = "default_compression_mode")]
    pub compression_mode: String,

    /// Yamux 多路复用配置。TCP relay 与 UDP relay 使用各自独立的 Yamux 外层 session。
    #[serde(default)]
    pub yamux: YamuxConfig,

    /// 日志级别：trace、debug、info、warn、error
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// 文件日志目录（使用文件日志可提升性能）
    pub log_dir: Option<String>,

    /// 日志文件名
    #[serde(default = "default_log_file")]
    pub log_file: String,

    /// Tokio 运行时工作线程数（默认为 CPU 核心数）
    #[serde(default)]
    pub runtime_threads: Option<usize>,

    /// 直连访问配置：决定哪些目标直连（绕过代理）、哪些走代理隧道
    #[serde(default)]
    pub direct_access: DirectAccessConfig,

    /// TUN 模式配置。启用时 agent 打开 TUN 设备，
    /// 将该接口上捕获的所有 IP 流量转发到代理。
    #[serde(default)]
    pub tun: TunConfig,
}

/// TUN 模式配置。
///
/// 当 `enabled = true` 时，agent 创建 TUN 设备，在其上构建小型
/// 用户空间 TCP/IP 协议栈（通过 netstack-smoltcp），并将接受的
/// TCP 流通过 direct framed TCP 转发到代理；UDP 可通过单独的
/// Yamux session manager 转发，也可由 agent 本地 UDP socket 直连目标。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunConfig {
    /// 启用 TUN 模式
    #[serde(default)]
    pub enabled: bool,

    /// TUN 设备名称（Windows 如 "ppaass-tun"，macOS 如 "utun8"，Linux 如 "tun0"）。
    /// macOS 上设备名大多为建议性质 — 内核会分配下一个空闲的 utun。
    #[serde(default = "default_tun_name")]
    pub name: String,

    /// 分配给 TUN 设备的 IPv4 地址，CIDR 格式。
    #[serde(default = "default_tun_ipv4")]
    pub ipv4: String,

    /// 分配给 TUN 设备的可选 IPv6 地址，CIDR 格式。
    #[serde(default)]
    pub ipv6: Option<String>,

    /// TUN 设备的 MTU。
    #[serde(default = "default_tun_mtu")]
    pub mtu: u16,

    /// TUN 模式下是否将 DNS 请求交给 proxy 端默认 DNS 处理。
    /// 启用后，发往任意 UDP/TCP 53 端口的请求都会走 proxy。
    #[serde(default)]
    pub proxy_dns: bool,

    /// TUN 模式下是否通过 proxy 转发普通 UDP。
    /// 关闭时，除独立处理的代理 DNS 与 UDP/443 QUIC 外，其余 UDP 从 agent
    /// 直接发往目标；QUIC 由 quic_policy 与 direct_access 分流。
    #[serde(default = "default_tun_proxy_udp")]
    pub proxy_udp: bool,

    /// TUN 模式下 UDP/443 QUIC 的细粒度处理策略。
    #[serde(default)]
    pub quic_policy: Option<QuicPolicy>,

    /// Windows TUN 模式所需的 wintun.dll 路径。
    /// 不设置时会依次检查 desktop-agent.exe 同目录、当前目录和 PATH。
    #[serde(default)]
    pub wintun_file: Option<String>,

    /// TUN 路由状态文件名或路径。
    /// 相对路径会放在当前运行目录下；不设置时使用 tun-routes.json。
    #[serde(default)]
    pub route_state_file: Option<String>,

    /// TUN DNS 状态文件名或路径。
    /// 相对路径会放在当前运行目录下；不设置时使用 tun-dns.json。
    #[serde(default)]
    pub dns_state_file: Option<String>,

    /// macOS 是否优先使用已安装的本地特权 helper 创建 TUN 和改写系统网络状态。
    #[serde(default = "default_macos_tun_helper_enabled", alias = "helper_enabled")]
    pub macos_helper_enabled: bool,

    /// macOS 本地特权 helper 的 Unix socket 路径。
    #[serde(default = "default_macos_tun_helper_socket", alias = "helper_socket")]
    pub macos_helper_socket: String,

    /// macOS helper 不可用时是否回退到旧的整进程提权路径。
    #[serde(
        default = "default_macos_tun_helper_fallback_to_privilege",
        alias = "helper_fallback_to_privilege"
    )]
    pub macos_helper_fallback_to_privilege: bool,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            name: default_tun_name(),
            ipv4: default_tun_ipv4(),
            ipv6: None,
            mtu: default_tun_mtu(),
            proxy_dns: false,
            proxy_udp: default_tun_proxy_udp(),
            quic_policy: None,
            wintun_file: None,
            route_state_file: None,
            dns_state_file: None,
            macos_helper_enabled: default_macos_tun_helper_enabled(),
            macos_helper_socket: default_macos_tun_helper_socket(),
            macos_helper_fallback_to_privilege: default_macos_tun_helper_fallback_to_privilege(),
        }
    }
}

fn default_tun_name() -> String {
    #[cfg(target_os = "windows")]
    {
        "ppaass-tun".to_string()
    }
    #[cfg(target_os = "macos")]
    {
        "utun8".to_string()
    }
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        "tun0".to_string()
    }
}

fn default_tun_ipv4() -> String {
    "10.10.10.1/24".to_string()
}

fn default_tun_mtu() -> u16 {
    1500
}

fn default_tun_proxy_udp() -> bool {
    true
}

fn default_macos_tun_helper_enabled() -> bool {
    cfg!(target_os = "macos")
}

fn default_macos_tun_helper_socket() -> String {
    DEFAULT_TUN_HELPER_SOCKET_PATH.to_string()
}

fn default_macos_tun_helper_fallback_to_privilege() -> bool {
    true
}

fn default_connect_timeout_secs() -> u64 {
    30
}

fn default_listen_addr() -> String {
    "0.0.0.0:10080".to_string()
}

fn default_compression_mode() -> String {
    "none".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_file() -> String {
    "desktop-agent.log".to_string()
}

fn default_async_runtime_stack_size_mb() -> usize {
    4
}

impl AgentConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        // 配置加载只做 TOML 反序列化和默认值填充，运行期语义由各模块校验。
        let content = fs::read_to_string(path)?;
        let config: AgentConfig = toml::from_str(&content)?;
        Ok(config)
    }

    #[allow(dead_code)]
    pub fn save<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        // 测试/工具场景使用，主程序目前只读取配置。
        let content = toml::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }

    pub fn get_compression_mode(&self) -> CompressionMode {
        self.compression_mode.parse().unwrap_or_default()
    }
}

impl TunConfig {
    /// 返回最终生效的 QUIC 策略。
    pub fn effective_quic_policy(&self) -> QuicPolicy {
        self.quic_policy.unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_AGENT_CONFIG: &str = r#"
listen_addr = "0.0.0.0:10080"
proxy_addrs = ["127.0.0.1:8080"]
username = "user1"
private_key_path = "keys/user1.pem"
"#;

    #[test]
    fn compression_mode_defaults_to_none() {
        let config: AgentConfig = toml::from_str(MINIMAL_AGENT_CONFIG).unwrap();

        assert_eq!(config.get_compression_mode(), CompressionMode::None);
        assert_eq!(config.transport_mode, TransportMode::Quic);
    }

    #[test]
    fn transport_mode_can_switch_back_to_tcp() {
        let config: AgentConfig =
            toml::from_str(&(MINIMAL_AGENT_CONFIG.to_owned() + "transport_mode = \"tcp\"\n"))
                .unwrap();
        assert_eq!(config.transport_mode, TransportMode::Tcp);
    }

    #[test]
    fn parses_compression_mode() {
        let config: AgentConfig =
            toml::from_str(&(MINIMAL_AGENT_CONFIG.to_owned() + r#"compression_mode = "lz4""#))
                .unwrap();

        assert_eq!(config.get_compression_mode(), CompressionMode::Lz4);
    }

    #[test]
    fn tun_allows_quic_by_default() {
        let config: AgentConfig = toml::from_str(MINIMAL_AGENT_CONFIG).unwrap();

        assert_eq!(config.tun.effective_quic_policy(), QuicPolicy::Allow);
    }

    #[test]
    fn tun_proxies_udp_by_default_for_backward_compatibility() {
        let config: AgentConfig = toml::from_str(MINIMAL_AGENT_CONFIG).unwrap();

        assert!(config.tun.proxy_udp);
    }

    #[test]
    fn tun_can_disable_udp_proxying() {
        let config: AgentConfig = toml::from_str(
            &(MINIMAL_AGENT_CONFIG.to_owned()
                + r#"
[tun]
proxy_udp = false
"#),
        )
        .unwrap();

        assert!(!config.tun.proxy_udp);
    }

    #[test]
    fn explicit_quic_policy_blocks_quic() {
        let config: AgentConfig = toml::from_str(
            &(MINIMAL_AGENT_CONFIG.to_owned()
                + r#"
[tun]
quic_policy = "block"
"#),
        )
        .unwrap();

        assert_eq!(config.tun.effective_quic_policy(), QuicPolicy::Block);
    }
}
