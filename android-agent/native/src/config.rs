use std::time::Duration;

use common::{ClientConnectionConfig, TransportConfig, YamuxConfig};
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

    #[serde(default)]
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

    #[serde(default = "default_block_quic")]
    pub block_quic: bool,
}

impl Default for AndroidTunConfig {
    fn default() -> Self {
        Self {
            ipv4: default_tun_ipv4(),
            ipv6: default_tun_ipv6(),
            mtu: default_tun_mtu(),
            proxy_dns: default_proxy_dns(),
            block_quic: default_block_quic(),
        }
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
    true
}
