use super::connected_stream::ConnectedStream;
use crate::config::AgentConfig;
use crate::error::{AgentError, Result};
use common::{AuthenticatedConnection, ClientConnectionConfig};
use protocol::Address;
use tracing::{debug, info};

/// Configuration adapter for ClientConnection trait
#[derive(Debug)]
struct AgentClientConfig<'a> {
    config: &'a AgentConfig,
}

impl<'a> AgentClientConfig<'a> {
    fn new(config: &'a AgentConfig) -> Self {
        Self { config }
    }
}

impl<'a> ClientConnectionConfig for AgentClientConfig<'a> {
    fn remote_addr(&self) -> String {
        self.config.proxy_addr.clone()
    }

    fn username(&self) -> String {
        self.config.username.clone()
    }

    fn private_key_pem(&self) -> std::result::Result<String, String> {
        std::fs::read_to_string(&self.config.private_key_path).map_err(|e| e.to_string())
    }

    fn timeout_duration(&self) -> Option<std::time::Duration> {
        Some(std::time::Duration::from_secs(
            self.config.connect_timeout_secs,
        ))
    }
}

/// A single-use authenticated connection to the proxy
/// This connection is used for one request and then discarded
pub struct ProxyConnection {
    auth_conn: AuthenticatedConnection,
}

impl ProxyConnection {
    /// Create a new authenticated connection to the proxy
    /// This performs just the authentication handshake without connecting to a target
    /// Used for connection pool prewarming
    pub async fn new(config: &AgentConfig) -> Result<Self> {
        debug!("Creating new proxy connection: {}", config.proxy_addr);
        let config_adapter = AgentClientConfig::new(config);

        let auth_conn = AuthenticatedConnection::authenticate_only(&config_adapter)
            .await
            .map_err(|e| AgentError::Connection(e.to_string()))?;

        info!("Authentication successful");

        Ok(Self { auth_conn })
    }

    /// Connect to a target address and return a bidirectional stream handle
    pub async fn connect_target(
        self,
        address: Address,
        transport: protocol::TransportProtocol,
    ) -> Result<ConnectedStream> {
        debug!("Connecting to target: {:?}", address);

        let (stream, request_id) = self
            .auth_conn
            .connect_to_target(address.clone(), transport)
            .await
            .map_err(|e| AgentError::Connection(e.to_string()))?;

        info!("Connected to target: {:?}", address);

        // Extract components from ClientStream for ConnectedStream
        Ok(ConnectedStream::new(
            stream.writer,
            stream.reader,
            request_id,
        ))
    }
}
