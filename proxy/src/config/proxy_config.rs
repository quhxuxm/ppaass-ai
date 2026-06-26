use common::YamuxServerConfig;
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

    /// Tokio 运行时工作线程数（默认 8）。
    /// 视频分片会同时触发 DNS、目标 TCP connect、协议编解码和 relay 任务，
    /// 4 线程在小型 VPS 上容易被瞬时并发打满，8 线程更适合作为通用性能默认值。
    #[serde(default = "default_runtime_threads")]
    pub runtime_threads: Option<usize>,

    /// 数据传输压缩模式：none、zstd、lz4、gzip
    #[serde(default = "default_compression_mode")]
    pub compression_mode: String,

    #[serde(default = "default_replay_attack_tolerance")]
    pub replay_attack_tolerance: i64,

    /// 入站 Yamux acceptor 参数。proxy 对每条 raw TCP 连接都直接维护一个 Yamux session；
    /// 外层 session 数由 agent 端控制。
    #[serde(default)]
    pub yamux: YamuxServerConfig,

    /// Yamux 外层 session 空闲超时时间（秒）。
    /// 当一条 raw Yamux TCP 连接没有任何活跃子流时，超过该时间后主动关闭；0 表示不限制。
    #[serde(default = "default_yamux_session_idle_timeout_secs")]
    pub yamux_session_idle_timeout_secs: u64,

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

    /// TCP relay 空闲超时时间（秒）；建立 CONNECT 后若双向都无数据活动将被关闭。
    /// 0 表示不限制。
    #[serde(default = "default_tcp_relay_idle_timeout_secs")]
    pub tcp_relay_idle_timeout_secs: u64,

    /// TCP relay 进入半关闭后的空闲回收时间（秒）。
    /// 浏览器/agent 请求方向已结束后，HTTPS/HTTP2 目标连接可能长时间不发 EOF；
    /// 这个值用于在响应方向也无活动时更快回收连接，0 表示回退到普通 TCP idle。
    #[serde(default = "default_tcp_relay_half_close_idle_timeout_secs")]
    pub tcp_relay_half_close_idle_timeout_secs: u64,

    /// 认证超时时间（秒）- 未在该时间内完成认证握手的连接将被关闭。
    /// 这可以防止 agent 通过 TCP 建连后从未发送认证请求造成僵尸连接
    /// （例如半开连接、端口扫描器、异常客户端）。
    #[serde(default = "default_auth_timeout_secs")]
    pub auth_timeout_secs: u64,

    /// UDP relay 空闲超时时间（秒）；会话和 flow 在该时间内无数据活动将被关闭。
    #[serde(default = "default_udp_relay_idle_timeout_secs")]
    pub udp_relay_idle_timeout_secs: u64,

    /// UDP relay 每个内部队列最多缓存的包数量。
    #[serde(default = "default_udp_relay_channel_size")]
    pub udp_relay_channel_size: usize,
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

fn default_tcp_relay_idle_timeout_secs() -> u64 {
    60
}

fn default_tcp_relay_half_close_idle_timeout_secs() -> u64 {
    30
}

fn default_yamux_session_idle_timeout_secs() -> u64 {
    300
}

fn default_auth_timeout_secs() -> u64 {
    30
}

fn default_udp_relay_idle_timeout_secs() -> u64 {
    60
}

fn default_udp_relay_channel_size() -> usize {
    64
}

fn default_async_runtime_stack_size_mb() -> usize {
    2
}

fn default_runtime_threads() -> Option<usize> {
    Some(8)
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
    fn tcp_relay_idle_timeout_defaults_to_recycle_stalled_streams() {
        let config: ProxyConfig = toml::from_str(
            r#"
	listen_addr = "127.0.0.1:0"
	tcp_relay_idle_timeout_secs = 60
	"#,
        )
        .unwrap();

        assert_eq!(config.tcp_relay_idle_timeout_secs, 60);
        assert_eq!(config.tcp_relay_half_close_idle_timeout_secs, 30);
        assert_eq!(config.yamux_session_idle_timeout_secs, 300);
    }

    #[test]
    fn udp_relay_queue_defaults_are_bounded() {
        let config: ProxyConfig = toml::from_str(
            r#"
listen_addr = "127.0.0.1:0"
"#,
        )
        .unwrap();

        assert_eq!(config.udp_relay_channel_size, 64);
    }
}
