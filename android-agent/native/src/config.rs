use std::time::Duration;

use common::{ClientConnectionConfig, QuicPolicy, TcpTransportMode, TransportConfig, YamuxConfig};
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

    #[serde(default = "default_async_runtime_stack_size_mb")]
    pub async_runtime_stack_size_mb: usize,

    #[serde(default = "default_runtime_threads")]
    pub runtime_threads: usize,

    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,

    #[serde(default = "default_compression_mode")]
    pub compression_mode: String,

    #[serde(default = "default_tcp_pool_size")]
    pub tcp_pool_size: usize,

    #[serde(default = "default_udp_pool_size")]
    pub udp_pool_size: usize,

    /// Android 默认 TCP 使用常规通道，避免浏览器/视频 App 的多个 TCP 分片连接
    /// 被 Yamux 塞进同一条外层 TCP 后互相队头阻塞；UDP 仍保持 auto。
    #[serde(default = "default_android_transport_config")]
    pub transport: TransportConfig,

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

    /// 旧配置项：true 时只允许命中直连规则的 UDP/443 QUIC。
    /// Android UI 目前仍写入该 bool；native 层会把它映射成细粒度策略。
    #[serde(default = "default_block_quic")]
    pub block_quic: bool,

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
            block_quic: default_block_quic(),
            quic_policy: None,
        }
    }
}

impl AndroidTunConfig {
    /// 返回最终生效的 QUIC 策略；显式 `quic_policy` 优先，旧 `block_quic`
    /// 只作为兼容兜底，避免 Android UI 还未升级时改变用户现有语义。
    pub fn effective_quic_policy(&self) -> QuicPolicy {
        self.quic_policy.unwrap_or({
            if self.block_quic {
                QuicPolicy::DirectIfRuleMatch
            } else {
                QuicPolicy::Allow
            }
        })
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

fn default_compression_mode() -> String {
    "none".to_string()
}

fn default_async_runtime_stack_size_mb() -> usize {
    4
}

fn default_runtime_threads() -> usize {
    4
}

fn default_android_transport_config() -> TransportConfig {
    TransportConfig {
        tcp_mode: TcpTransportMode::Legacy,
        udp_mode: TcpTransportMode::Auto,
    }
}

fn default_tcp_pool_size() -> usize {
    5
}

fn default_udp_pool_size() -> usize {
    5
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

fn default_block_quic() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tun_allows_quic_by_default() {
        let config = AndroidTunConfig::default();

        assert!(!config.block_quic);
        assert_eq!(config.effective_quic_policy(), QuicPolicy::Allow);
    }

    #[test]
    fn android_agent_defaults_tcp_to_legacy_transport() {
        let config: AndroidAgentConfig = serde_json::from_str(
            r#"{"proxy_addrs":["127.0.0.1:8080"],"username":"u","private_key_pem":"k"}"#,
        )
        .unwrap();

        assert_eq!(config.transport.tcp_mode, TcpTransportMode::Legacy);
        assert_eq!(config.transport.udp_mode, TcpTransportMode::Auto);
    }

    #[test]
    fn legacy_block_quic_maps_to_direct_if_rule_match() {
        let config: AndroidTunConfig = serde_json::from_str(r#"{"block_quic":true}"#).unwrap();

        assert_eq!(
            config.effective_quic_policy(),
            QuicPolicy::DirectIfRuleMatch
        );
    }

    #[test]
    fn explicit_quic_policy_overrides_legacy_block_quic() {
        let config: AndroidTunConfig =
            serde_json::from_str(r#"{"block_quic":true,"quic_policy":"block"}"#).unwrap();

        assert_eq!(config.effective_quic_policy(), QuicPolicy::Block);
    }
}
