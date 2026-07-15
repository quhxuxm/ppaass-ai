use std::time::Duration;

use common::{ClientConnectionConfig, QuicPolicy, TransportMode, YamuxConfig};
use protocol::CompressionMode;
use serde::{Deserialize, Serialize};
use socket2::Socket;

use crate::direct_access::DirectAccessConfig;
use crate::error::{AndroidAgentError, Result};

pub const ANDROID_SOCKET_BUFFER_SIZE: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidAgentConfig {
    pub proxy_addrs: Vec<String>,
    pub username: String,
    pub private_key_pem: String,

    #[serde(default)]
    pub transport_mode: TransportMode,

    /// UDP manager 维护的 QUIC 连接数。多条连接可以隔离拥塞窗口，
    /// 避免一个应用的丢包同时卡住所有应用。TCP 始终使用 direct framed TCP。
    #[serde(default = "default_quic_connection_pool_size")]
    pub quic_connection_pool_size: usize,

    #[serde(default = "default_async_runtime_stack_size_mb")]
    pub async_runtime_stack_size_mb: usize,

    #[serde(default = "default_runtime_threads")]
    pub runtime_threads: usize,

    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,

    #[serde(default = "default_http_proxy_max_concurrent_connects")]
    pub http_proxy_max_concurrent_connects: usize,

    #[serde(default = "default_compression_mode")]
    pub compression_mode: String,

    #[serde(default)]
    pub yamux: YamuxConfig,

    #[serde(default)]
    pub direct_access: DirectAccessConfig,

    #[serde(default)]
    pub tun: AndroidTunConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidTunConfig {
    #[serde(default = "default_tun_ipv4")]
    pub ipv4: String,

    #[serde(default = "default_tun_ipv6")]
    pub ipv6: Option<String>,

    #[serde(default = "default_tun_mtu")]
    pub mtu: u16,

    #[serde(default = "default_proxy_dns")]
    pub proxy_dns: bool,

    /// TUN 模式下 UDP/443 QUIC 的细粒度处理策略。
    #[serde(default)]
    pub quic_policy: Option<QuicPolicy>,
}

impl Default for AndroidTunConfig {
    fn default() -> Self {
        Self {
            ipv4: default_tun_ipv4(),
            ipv6: default_tun_ipv6(),
            mtu: default_tun_mtu(),
            proxy_dns: default_proxy_dns(),
            quic_policy: None,
        }
    }
}

impl AndroidTunConfig {
    /// 返回最终生效的 QUIC 策略。
    pub fn effective_quic_policy(&self) -> QuicPolicy {
        self.quic_policy.unwrap_or_default()
    }
}

impl AndroidAgentConfig {
    pub fn validate(&self) -> Result<()> {
        if self.proxy_addrs.is_empty() {
            return Err(AndroidAgentError::Connection(
                "proxy_addrs must contain at least one proxy endpoint".to_string(),
            ));
        }
        if self.username.trim().is_empty() {
            return Err(AndroidAgentError::Connection(
                "username must not be empty".to_string(),
            ));
        }
        if self.private_key_pem.trim().is_empty() {
            return Err(AndroidAgentError::Connection(
                "private_key_pem must not be empty".to_string(),
            ));
        }
        Ok(())
    }

    /// 限制连接池的 socket/内存开销，同时避免错误配置 0 导致轮询取模崩溃。
    pub fn effective_quic_connection_pool_size(&self) -> usize {
        self.quic_connection_pool_size.clamp(1, 8)
    }
}

impl ClientConnectionConfig for AndroidAgentConfig {
    fn remote_addr(&self) -> String {
        self.proxy_addrs.first().cloned().unwrap_or_default()
    }

    fn username(&self) -> String {
        self.username.clone()
    }

    fn private_key_pem(&self) -> std::result::Result<String, String> {
        Ok(self.private_key_pem.clone())
    }

    fn timeout_duration(&self) -> Duration {
        Duration::from_secs(self.connect_timeout_secs)
    }

    fn compression_mode(&self) -> CompressionMode {
        self.compression_mode.parse().unwrap_or_default()
    }

    fn tcp_socket_buffer_size(&self) -> Option<usize> {
        Some(ANDROID_SOCKET_BUFFER_SIZE)
    }

    #[cfg(unix)]
    fn protect_socket(&self, socket: &Socket, _dst: std::net::SocketAddr) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;

        crate::socket_protector::protect_fd(socket.as_raw_fd())
    }

    #[cfg(not(unix))]
    fn protect_socket(&self, _socket: &Socket, _dst: std::net::SocketAddr) -> std::io::Result<()> {
        Ok(())
    }
}

fn default_connect_timeout_secs() -> u64 {
    30
}

fn default_quic_connection_pool_size() -> usize {
    4
}

fn default_http_proxy_max_concurrent_connects() -> usize {
    16
}

fn default_compression_mode() -> String {
    "none".to_string()
}

fn default_async_runtime_stack_size_mb() -> usize {
    4
}

fn default_runtime_threads() -> usize {
    4
}

fn default_tun_ipv4() -> String {
    "10.10.10.2/24".to_string()
}

fn default_tun_ipv6() -> Option<String> {
    None
}

fn default_tun_mtu() -> u16 {
    1500
}

fn default_proxy_dns() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tun_allows_quic_by_default() {
        let config = AndroidTunConfig::default();

        assert_eq!(config.effective_quic_policy(), QuicPolicy::Allow);
    }

    #[test]
    fn agent_transport_defaults_to_quic() {
        let config: AndroidAgentConfig = serde_json::from_str(
            r#"{"proxy_addrs":["127.0.0.1:8080"],"username":"u","private_key_pem":"key"}"#,
        )
        .unwrap();
        assert_eq!(config.transport_mode, TransportMode::Quic);
    }

    #[test]
    fn quic_connection_pool_defaults_to_four_and_is_bounded() {
        let default_config: AndroidAgentConfig = serde_json::from_str(
            r#"{"proxy_addrs":["127.0.0.1:8080"],"username":"u","private_key_pem":"key"}"#,
        )
        .unwrap();
        assert_eq!(default_config.effective_quic_connection_pool_size(), 4);

        let disabled: AndroidAgentConfig = serde_json::from_str(
            r#"{"proxy_addrs":["127.0.0.1:8080"],"username":"u","private_key_pem":"key","quic_connection_pool_size":0}"#,
        )
        .unwrap();
        assert_eq!(disabled.effective_quic_connection_pool_size(), 1);

        let excessive: AndroidAgentConfig = serde_json::from_str(
            r#"{"proxy_addrs":["127.0.0.1:8080"],"username":"u","private_key_pem":"key","quic_connection_pool_size":64}"#,
        )
        .unwrap();
        assert_eq!(excessive.effective_quic_connection_pool_size(), 8);
    }

    #[test]
    fn explicit_quic_policy_blocks_quic() {
        let config: AndroidTunConfig = serde_json::from_str(r#"{"quic_policy":"block"}"#).unwrap();

        assert_eq!(config.effective_quic_policy(), QuicPolicy::Block);
    }
}
