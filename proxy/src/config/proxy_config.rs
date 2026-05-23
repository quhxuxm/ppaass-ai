use common::{TransportConfig, YamuxServerConfig};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub listen_addr: String,

    /// 用户配置文件路径。
    #[serde(default = "default_users_path")]
    pub users_path: String,

    #[serde(default = "default_async_runtime_stack_size_mb")]
    pub async_runtime_stack_size_mb: usize,

    /// 日志级别：trace、debug、info、warn、error
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// 文件日志目录（相比控制台输出性能更好）
    pub log_dir: Option<String>,

    /// 文件日志名
    #[serde(default = "default_log_file")]
    pub log_file: String,

    /// Tokio 运行时工作线程数（默认使用 CPU 核心数）
    #[serde(default)]
    pub runtime_threads: Option<usize>,

    /// 数据传输压缩模式：none、zstd、lz4、gzip
    #[serde(default = "default_compression_mode")]
    pub compression_mode: String,

    #[serde(default = "default_replay_attack_tolerance")]
    pub replay_attack_tolerance: i64,

    /// TCP/UDP 传输模式：auto/yamux 接受对应 Yamux 和 legacy，legacy 拒绝对应 Yamux 外层连接。
    #[serde(default)]
    pub transport: TransportConfig,

    /// 入站 Yamux acceptor 参数。proxy 只接受 agent 建立的 TCP/UDP Yamux 外层 session；
    /// 外层 session 数由 agent 端控制。
    #[serde(default)]
    pub yamux: YamuxServerConfig,

    #[serde(default)]
    pub forward_mode: bool,

    #[serde(default)]
    pub upstream_proxy_addrs: Option<Vec<String>>,

    #[serde(default)]
    pub upstream_username: Option<String>,

    #[serde(default)]
    pub upstream_private_key_path: Option<String>,

    /// 连接目标服务器时绑定的出站网络设备名。
    /// 为空时使用系统默认路由。
    #[serde(default)]
    pub outbound_interface: Option<String>,

    /// proxy 端处理 DNS 请求时使用的上游 DNS。
    /// 为空时读取系统默认 DNS。
    #[serde(default)]
    pub dns_upstream_addr: Option<String>,

    /// 上游代理连接超时时间（秒）
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,

    /// 已认证但尚未发送第一个 Connect 请求的预热连接空闲超时时间（秒）。
    /// 连接进入 legacy TCP relay、UDP relay 或 Yamux 外层 session 后不再使用该超时。
    #[serde(
        default = "default_pre_connect_idle_timeout_secs",
        alias = "idle_connection_timeout_secs"
    )]
    pub pre_connect_idle_timeout_secs: u64,

    /// TCP relay 空闲超时时间（秒）；建立 CONNECT 后若双向都无数据活动将被关闭。
    /// 0 表示不限制。
    #[serde(default = "default_tcp_relay_idle_timeout_secs")]
    pub tcp_relay_idle_timeout_secs: u64,

    /// Yamux TCP 子流空闲超时时间（秒）。
    /// 0 表示不限制；默认不限制，避免 WebSocket、SSH 等长连接被子流 idle 误杀。
    #[serde(default = "default_yamux_tcp_relay_idle_timeout_secs")]
    pub yamux_tcp_relay_idle_timeout_secs: u64,

    /// 认证超时时间（秒）- 未在该时间内完成认证握手的连接将被关闭。
    /// 这可以防止 agent 通过 TCP 建连后从未发送认证请求造成僵尸连接
    /// （例如半开连接、端口扫描器、异常客户端）。
    #[serde(default = "default_auth_timeout_secs")]
    pub auth_timeout_secs: u64,

    /// proxy 同时接受的 agent TCP 连接总数上限；0 表示不限制。
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// 单个用户同时占用的 agent TCP 连接数上限；0 表示不限制。
    #[serde(default = "default_max_connections_per_user")]
    pub max_connections_per_user: usize,

    /// 单个用户已认证但尚未发送 Connect 请求的预热连接数上限；0 表示不限制。
    #[serde(default = "default_max_idle_connections_per_user")]
    pub max_idle_connections_per_user: usize,

    /// 单条 UDP relay TCP 连接中允许同时存在的目标 UDP flow 数；0 表示不限制。
    #[serde(default = "default_max_udp_relay_flows_per_connection")]
    pub max_udp_relay_flows_per_connection: usize,

    /// proxy 全局同时存在的 UDP relay flow 数；每个 flow 持有一个 UDP socket，0 表示不限制。
    #[serde(default = "default_max_udp_relay_flows")]
    pub max_udp_relay_flows: usize,

    /// UDP relay 空闲超时时间（秒）；会话和 flow 在该时间内无数据活动将被关闭。
    #[serde(default = "default_udp_relay_idle_timeout_secs")]
    pub udp_relay_idle_timeout_secs: u64,

    /// UDP relay 每个内部队列最多缓存的包数量。
    #[serde(default = "default_udp_relay_channel_size")]
    pub udp_relay_channel_size: usize,

    /// proxy 全局 UDP relay 队列中允许积压的 payload 字节数；0 表示不限制。
    #[serde(default = "default_max_udp_relay_buffered_bytes")]
    pub max_udp_relay_buffered_bytes: usize,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_file() -> String {
    "proxy.log".to_string()
}

fn default_users_path() -> String {
    "users.toml".to_string()
}

fn default_compression_mode() -> String {
    "none".to_string()
}

fn default_replay_attack_tolerance() -> i64 {
    300
}

fn default_connect_timeout_secs() -> u64 {
    30
}

fn default_pre_connect_idle_timeout_secs() -> u64 {
    120
}

fn default_tcp_relay_idle_timeout_secs() -> u64 {
    300
}

fn default_yamux_tcp_relay_idle_timeout_secs() -> u64 {
    0
}

fn default_auth_timeout_secs() -> u64 {
    30
}

fn default_max_connections() -> usize {
    4096
}

fn default_max_connections_per_user() -> usize {
    1024
}

fn default_max_idle_connections_per_user() -> usize {
    128
}

fn default_max_udp_relay_flows_per_connection() -> usize {
    512
}

fn default_max_udp_relay_flows() -> usize {
    1024
}

fn default_udp_relay_idle_timeout_secs() -> u64 {
    60
}

fn default_udp_relay_channel_size() -> usize {
    256
}

fn default_max_udp_relay_buffered_bytes() -> usize {
    64 * 1024 * 1024
}

fn default_async_runtime_stack_size_mb() -> usize {
    4
}

impl ProxyConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        // 配置文件只负责反序列化和默认值填充，语义校验放在启动流程中做。
        let content = fs::read_to_string(path)?;
        let config: ProxyConfig = toml::from_str(&content)?;
        Ok(config)
    }

    /// 获取协议层的压缩模式
    pub fn get_compression_mode(&self) -> protocol::CompressionMode {
        // 未知压缩值回退到协议默认值，避免错误配置直接导致启动失败。
        self.compression_mode.parse().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yamux_tcp_relay_idle_timeout_defaults_to_unlimited() {
        let config: ProxyConfig = toml::from_str(
            r#"
listen_addr = "127.0.0.1:0"
tcp_relay_idle_timeout_secs = 300
"#,
        )
        .unwrap();

        assert_eq!(config.tcp_relay_idle_timeout_secs, 300);
        assert_eq!(config.yamux_tcp_relay_idle_timeout_secs, 0);
    }

    #[test]
    fn udp_relay_memory_defaults_are_bounded() {
        let config: ProxyConfig = toml::from_str(
            r#"
listen_addr = "127.0.0.1:0"
"#,
        )
        .unwrap();

        assert_eq!(config.max_udp_relay_flows_per_connection, 512);
        assert_eq!(config.max_udp_relay_flows, 1024);
        assert_eq!(config.udp_relay_channel_size, 256);
        assert_eq!(config.max_udp_relay_buffered_bytes, 64 * 1024 * 1024);
    }
}
