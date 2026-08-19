//! agent 到 proxy 的 raw Yamux 外层连接创建。

use std::{fs::read_to_string, net::IpAddr, net::SocketAddr, time::Duration};

use crate::config::AgentConfig;
use crate::error::{AgentError, Result};
use common::{
    AuthenticatedConnection, BindInterface, ClientConnectionConfig, ProxyEndpointAffinity,
    YamuxClientConnection,
};
use protocol::{Address, CompressionMode, TransportProtocol};
use tracing::instrument;

// 桌面端 agent 到 proxy 的 TCP 缓冲。
const DESKTOP_PROXY_SOCKET_BUFFER_SIZE: usize = 1024 * 1024;

#[derive(Debug)]
pub struct AgentClientConfig<'a> {
    config: &'a AgentConfig,
    proxy_addrs: &'a [String],
    bind_ip: Option<IpAddr>,
    bind_interface: Option<BindInterface>,
    proxy_affinity: std::sync::Arc<ProxyEndpointAffinity>,
}

impl<'a> AgentClientConfig<'a> {
    pub fn new(
        config: &'a AgentConfig,
        proxy_addrs: &'a [String],
        bind_ip: Option<IpAddr>,
        bind_interface: Option<BindInterface>,
    ) -> Self {
        Self::new_with_affinity(
            config,
            proxy_addrs,
            bind_ip,
            bind_interface,
            std::sync::Arc::new(ProxyEndpointAffinity::default()),
        )
    }

    pub fn new_with_affinity(
        config: &'a AgentConfig,
        proxy_addrs: &'a [String],
        bind_ip: Option<IpAddr>,
        bind_interface: Option<BindInterface>,
        proxy_affinity: std::sync::Arc<ProxyEndpointAffinity>,
    ) -> Self {
        Self {
            config,
            proxy_addrs,
            bind_ip,
            bind_interface,
            proxy_affinity,
        }
    }
}

impl<'a> ClientConnectionConfig for AgentClientConfig<'a> {
    fn remote_addr(&self) -> String {
        self.proxy_affinity
            .ordered_candidates(self.proxy_addrs)
            .into_iter()
            .next()
            .unwrap_or_default()
    }

    fn remote_addrs(&self) -> Vec<String> {
        self.proxy_affinity.ordered_candidates(self.proxy_addrs)
    }

    fn record_remote_success(&self, remote_addr: &str) {
        self.proxy_affinity
            .record_success(self.proxy_addrs, remote_addr);
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

#[instrument(skip(config, proxy_addrs))]
pub(super) async fn new_yamux_connection(
    config: &AgentConfig,
    proxy_addrs: &[String],
    bind_ip: Option<IpAddr>,
    bind_interface: Option<BindInterface>,
    proxy_affinity: std::sync::Arc<ProxyEndpointAffinity>,
    transport: TransportProtocol,
) -> Result<YamuxClientConnection> {
    let config_adapter = AgentClientConfig::new_with_affinity(
        config,
        proxy_addrs,
        bind_ip,
        bind_interface,
        proxy_affinity,
    );
    let yamux_settings = config.yamux.udp_settings();
    YamuxClientConnection::connect_for(&config_adapter, transport, yamux_settings)
        .await
        .map_err(|e| AgentError::Connection(e.to_string()))
}

#[instrument(skip(config, proxy_addrs))]
pub(super) async fn new_direct_tcp_target_stream(
    config: &AgentConfig,
    proxy_addrs: &[String],
    bind_ip: Option<IpAddr>,
    bind_interface: Option<BindInterface>,
    proxy_affinity: std::sync::Arc<ProxyEndpointAffinity>,
    address: Address,
) -> Result<(common::ClientStream, String)> {
    let config_adapter = AgentClientConfig::new_with_affinity(
        config,
        proxy_addrs,
        bind_ip,
        bind_interface,
        proxy_affinity,
    );
    let connection = AuthenticatedConnection::connect(&config_adapter)
        .await
        .map_err(|e| AgentError::Connection(e.to_string()))?;
    connection
        .connect_to_target(address, TransportProtocol::Tcp)
        .await
        .map_err(|e| AgentError::Connection(e.to_string()))
}
