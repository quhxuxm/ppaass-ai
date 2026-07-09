//! agent 到 proxy 的 raw Yamux 外层连接创建。

use std::{fs::read_to_string, net::IpAddr, net::SocketAddr, time::Duration};

use crate::config::AgentConfig;
use crate::error::{AgentError, Result};
use common::{
    AuthenticatedConnection, BindInterface, ClientConnectionConfig, YamuxClientConnection,
};
use protocol::{Address, CompressionMode, TransportProtocol};
use tracing::instrument;

// 桌面端 agent 到 proxy 的 TCP 缓冲。
const DESKTOP_PROXY_SOCKET_BUFFER_SIZE: usize = 1024 * 1024;

#[derive(Debug)]
pub(super) struct AgentClientConfig<'a> {
    config: &'a AgentConfig,
    bind_ip: Option<IpAddr>,
    bind_interface: Option<BindInterface>,
}

impl<'a> AgentClientConfig<'a> {
    pub(super) fn new(
        config: &'a AgentConfig,
        bind_ip: Option<IpAddr>,
        bind_interface: Option<BindInterface>,
    ) -> Self {
        Self {
            config,
            bind_ip,
            bind_interface,
        }
    }
}

impl<'a> ClientConnectionConfig for AgentClientConfig<'a> {
    fn remote_addr(&self) -> String {
        use rand::prelude::*;
        let mut rng = rand::rng();
        self.config
            .proxy_addrs
            .choose(&mut rng)
            .cloned()
            .unwrap_or_default()
    }

    fn username(&self) -> String {
        self.config.username.clone()
    }

    fn private_key_pem(&self) -> std::result::Result<String, String> {
        read_to_string(&self.config.private_key_path).map_err(|e| e.to_string())
    }

    fn timeout_duration(&self) -> Duration {
        Duration::from_secs(self.config.connect_timeout_secs)
    }

    fn compression_mode(&self) -> CompressionMode {
        self.config.get_compression_mode()
    }

    fn bind_addr(&self) -> Option<SocketAddr> {
        self.bind_ip.map(|ip| SocketAddr::new(ip, 0))
    }

    fn bind_interface(&self) -> Option<BindInterface> {
        self.bind_interface.clone()
    }

    fn tcp_socket_buffer_size(&self) -> Option<usize> {
        Some(DESKTOP_PROXY_SOCKET_BUFFER_SIZE)
    }
}

#[instrument(skip(config))]
pub(super) async fn new_yamux_connection(
    config: &AgentConfig,
    bind_ip: Option<IpAddr>,
    bind_interface: Option<BindInterface>,
    transport: TransportProtocol,
) -> Result<YamuxClientConnection> {
    let config_adapter = AgentClientConfig::new(config, bind_ip, bind_interface);
    let yamux_settings = config.yamux.udp_settings();
    YamuxClientConnection::connect_for(&config_adapter, transport, yamux_settings)
        .await
        .map_err(|e| AgentError::Connection(e.to_string()))
}

#[instrument(skip(config))]
pub(super) async fn new_direct_tcp_target_stream(
    config: &AgentConfig,
    bind_ip: Option<IpAddr>,
    bind_interface: Option<BindInterface>,
    address: Address,
) -> Result<(common::ClientStream, String)> {
    let config_adapter = AgentClientConfig::new(config, bind_ip, bind_interface);
    let connection = AuthenticatedConnection::connect(&config_adapter)
        .await
        .map_err(|e| AgentError::Connection(e.to_string()))?;
    connection
        .connect_to_target(address, TransportProtocol::Tcp)
        .await
        .map_err(|e| AgentError::Connection(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::ClientConnectionConfig;

    const MINIMAL_AGENT_CONFIG: &str = r#"
listen_addr = "0.0.0.0:10080"
proxy_addrs = ["127.0.0.1:8080"]
username = "user1"
private_key_path = "keys/user1.pem"
compression_mode = "gzip"
"#;

    #[test]
    fn connection_config_adapter_forwards_compression_mode() {
        let config: AgentConfig = toml::from_str(MINIMAL_AGENT_CONFIG).unwrap();
        let adapter = AgentClientConfig::new(&config, None, None);

        assert_eq!(adapter.compression_mode(), CompressionMode::Gzip);
    }
}
