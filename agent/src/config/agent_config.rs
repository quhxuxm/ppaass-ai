use crate::direct_access::DirectAccessConfig;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub listen_addr: String,
    pub proxy_addrs: Vec<String>,
    pub username: String,
    pub private_key_path: String,
    #[serde(default = "default_async_runtime_stack_size_mb")]
    pub async_runtime_stack_size_mb: usize,

    #[serde(default = "default_pool_size")]
    pub pool_size: usize,

    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,

    /// 连接池中连接的最大存活时间（秒）。
    /// 超过此时间的连接会被丢弃并替换为新连接，避免因代理端的空闲超时
    /// 关闭连接导致请求失败。
    /// 应设为小于代理端 `idle_connection_timeout_secs` 的值
    /// （默认 90 秒，代理端默认 120 秒）。
    #[serde(default = "default_pool_max_connection_age_secs")]
    pub pool_max_connection_age_secs: u64,

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
/// 每个 TCP/UDP 流通过与 SOCKS5/HTTP 模式相同的连接池转发到代理。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunConfig {
    /// 启用 TUN 模式
    #[serde(default)]
    pub enabled: bool,

    /// TUN 设备名称（macOS 如 "utun8"，Linux 如 "tun0"）。
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
        }
    }
}

fn default_tun_name() -> String {
    "utun8".to_string()
}

fn default_tun_ipv4() -> String {
    "10.10.10.1/24".to_string()
}

fn default_tun_mtu() -> u16 {
    1500
}

fn default_pool_size() -> usize {
    10
}

fn default_connect_timeout_secs() -> u64 {
    30
}

fn default_pool_max_connection_age_secs() -> u64 {
    // 默认 90 秒 — 低于代理端默认的 idle_connection_timeout_secs (120 秒)。
    // 确保池中连接在代理端关闭之前被淘汰，避免使用过期连接导致请求失败。
    90
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_file() -> String {
    "agent.log".to_string()
}

fn default_async_runtime_stack_size_mb() -> usize {
    4
}

impl AgentConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: AgentConfig = toml::from_str(&content)?;
        Ok(config)
    }

    #[allow(dead_code)]
    pub fn save<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        let content = toml::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }
}
