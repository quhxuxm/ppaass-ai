use common::YamuxServerConfig;
use serde::{Deserialize, Deserializer, Serialize, de};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    pub listen_addr: String,

    /// 当前数据面实例的稳定标识，用于访问记录幂等键和运行日志。
    pub entry_id: String,

    /// Agent 可连接的公网 host:port；Entry 注册时上报给 Registry。
    pub advertised_address: String,

    /// Proxy Registry 控制面的 HTTP 或 HTTPS 基础地址。
    pub registry_url: String,

    /// 仅当前服务账号可读的控制面 Bearer Token 文件。
    pub registry_control_token_path: String,

    /// Entry 本地持久化的最后成功授权快照；不能放在版本 release 目录中。
    pub authorization_database_path: String,

    /// 单个控制面 HTTP 请求的超时时间。
    #[serde(default = "default_control_request_timeout_secs")]
    pub control_request_timeout_secs: u64,

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

    /// Framed TCP/TCP-Yamux 数据压缩模式：none、zstd、lz4、gzip。原生 UDP 不压缩。
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

    /// 连接目标服务器时绑定的出站网络设备名。
    /// 为空时使用系统默认路由。
    #[serde(default)]
    pub outbound_interface: Option<String>,

    /// proxy 端处理 DNS 请求时使用的上游 DNS。
    /// 为空时读取系统默认 DNS。
    #[serde(default)]
    pub dns_upstream_addr: Option<String>,

    /// 连接目标服务器的超时时间（秒）。
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

    /// 每条共享 UDP relay 同时存在的内层 flow/目标 socket 上限。
    /// 该限制同时适用于 TCP/Yamux 和原生 UDP 承载的共享 relay。
    #[serde(default = "default_udp_relay_max_flows")]
    pub udp_relay_max_flows: usize,

    /// 同时存在的已认证原生 UDP 会话上限。达到上限时拒绝新的认证，现有
    /// 会话继续工作，避免伪造源地址的握手耗尽内存。
    #[serde(default = "default_udp_session_limit")]
    pub udp_session_limit: usize,

    /// 单个用户名同时存在的已认证原生 UDP 会话上限。Agent 每个实例可维护
    /// 1..=8 个会话，因此该值需要为多设备和快速重启期间尚未回收的旧会话
    /// 留出余量。运行时仍会取它与全局 udp_session_limit 的较小值。
    #[serde(default = "default_udp_session_limit_per_username")]
    pub udp_session_limit_per_username: usize,

    /// 每个原生 UDP 会话从 listener 到会话任务的有界数据报队列大小。
    #[serde(default = "default_udp_session_channel_size")]
    pub udp_session_channel_size: usize,

    /// 每个已认证原生 UDP 会话允许同时存在的外层 flow 上限。
    /// 达到上限时已存在 flow 的重复 Connect 仍保持幂等，但不再为新 flow
    /// 创建队列、socket 或 worker 任务。
    #[serde(default = "default_udp_session_max_flows")]
    pub udp_session_max_flows: usize,

    /// 已建立的 TCP/Yamux relay 与原生 UDP 会话重新查询用户状态的间隔（秒）。
    /// 用于让管理员停用、权限撤销、密钥轮换和提前过期在 active relay 上生效。
    /// 安全边界固定为 1..=5 秒：可以缩短，但不能通过配置延后到 5 秒以上。
    #[serde(
        default = "default_udp_session_authorization_recheck_secs",
        deserialize_with = "deserialize_udp_session_authorization_recheck_secs"
    )]
    pub udp_session_authorization_recheck_secs: u64,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_file() -> String {
    "proxy.log".to_string()
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

fn default_control_request_timeout_secs() -> u64 {
    10
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

fn default_udp_relay_max_flows() -> usize {
    256
}

fn default_udp_session_limit() -> usize {
    4096
}

fn default_udp_session_limit_per_username() -> usize {
    64
}

fn default_udp_session_channel_size() -> usize {
    256
}

fn default_udp_session_max_flows() -> usize {
    256
}

fn default_udp_session_authorization_recheck_secs() -> u64 {
    5
}

fn deserialize_udp_session_authorization_recheck_secs<'de, D>(
    deserializer: D,
) -> std::result::Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let value = u64::deserialize(deserializer)?;
    if (1..=5).contains(&value) {
        Ok(value)
    } else {
        Err(de::Error::custom(
            "udp_session_authorization_recheck_secs must be between 1 and 5",
        ))
    }
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

    /// 获取 framed TCP/TCP-Yamux 协议的压缩模式。
    pub fn get_compression_mode(&self) -> protocol::CompressionMode {
        // 未知压缩值回退到协议默认值，避免错误配置直接导致启动失败。
        self.compression_mode.parse().unwrap_or_default()
    }

    pub fn effective_udp_session_limit_per_username(&self) -> usize {
        self.udp_session_limit_per_username
            .min(self.udp_session_limit)
    }
}
