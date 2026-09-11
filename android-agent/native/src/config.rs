use std::fmt;
use std::time::Duration;

use common::{
    ClientConnectionConfig, ProxyEndpointAffinity, QuicPolicy, TransportMode, YamuxConfig,
};
use protocol::CompressionMode;
use serde::{Deserialize, Serialize};
use socket2::Socket;
use std::sync::Arc;

use crate::direct_access::DirectAccessConfig;
use crate::error::{AndroidAgentError, Result};

pub const ANDROID_SOCKET_BUFFER_SIZE: usize = 1024 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AndroidAgentConfig {
    pub proxy_addrs: Vec<String>,
    #[serde(skip)]
    #[doc(hidden)]
    pub proxy_affinity: Arc<ProxyEndpointAffinity>,
    pub username: String,
    pub private_key_pem: String,

    #[serde(default)]
    pub transport_mode: TransportMode,

    /// UDP manager 维护的原生加密 UDP 会话数。每个会话拥有独立
    /// UDP socket、发送序号和重放窗口；TCP 始终使用 direct framed TCP。
    #[serde(default = "default_udp_session_pool_size")]
    pub udp_session_pool_size: usize,

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

struct RedactedPrivateKey;

impl fmt::Debug for RedactedPrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl fmt::Debug for AndroidAgentConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AndroidAgentConfig")
            .field("proxy_address_count", &self.proxy_addrs.len())
            .field("username", &self.username)
            .field("private_key_pem", &RedactedPrivateKey)
            .field("transport_mode", &self.transport_mode)
            .field("udp_session_pool_size", &self.udp_session_pool_size)
            .field(
                "async_runtime_stack_size_mb",
                &self.async_runtime_stack_size_mb,
            )
            .field("runtime_threads", &self.runtime_threads)
            .field("connect_timeout_secs", &self.connect_timeout_secs)
            .field(
                "http_proxy_max_concurrent_connects",
                &self.http_proxy_max_concurrent_connects,
            )
            .field("compression_mode", &self.compression_mode)
            .field("yamux", &self.yamux)
            .field("direct_access", &self.direct_access)
            .field("tun", &self.tun)
            .finish()
    }
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

    /// 限制 UDP 会话池的 socket/内存开销，同时避免错误配置 0。
    pub fn effective_udp_session_pool_size(&self) -> usize {
        self.udp_session_pool_size.clamp(1, 8)
    }
}

impl ClientConnectionConfig for AndroidAgentConfig {
    fn remote_addr(&self) -> String {
        self.proxy_affinity
            .ordered_candidates(&self.proxy_addrs)
            .into_iter()
            .next()
            .unwrap_or_default()
    }

    fn remote_addrs(&self) -> Vec<String> {
        self.proxy_affinity.ordered_candidates(&self.proxy_addrs)
    }

    fn record_remote_success(&self, remote_addr: &str) {
        self.proxy_affinity
            .record_success(&self.proxy_addrs, remote_addr);
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

    #[cfg(unix)]
    fn protect_udp_socket(
        &self,
        socket: &Socket,
        _dst: std::net::SocketAddr,
    ) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;

        crate::socket_protector::protect_fd_required(socket.as_raw_fd())
    }

    #[cfg(not(unix))]
    fn protect_socket(&self, _socket: &Socket, _dst: std::net::SocketAddr) -> std::io::Result<()> {
        Ok(())
    }

    #[cfg(not(unix))]
    fn protect_udp_socket(
        &self,
        _socket: &Socket,
        _dst: std::net::SocketAddr,
    ) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "native UDP VPN socket protection is unavailable on this platform",
        ))
    }
}

fn default_connect_timeout_secs() -> u64 {
    30
}

fn default_udp_session_pool_size() -> usize {
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
