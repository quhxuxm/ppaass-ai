/// Connection to an upstream proxy
/// Acts as a client (Agent) to the next hop
use crate::config::ProxyConfig;
use crate::error::{ProxyError, Result};
use common::{ClientConnection, ClientConnectionConfig, ClientStream};
use protocol::{Address, TransportProtocol};
use std::{fmt::Debug, fs::read_to_string, time::Duration};
use tracing::debug;

/// Configuration adapter for ClientConnection trait
#[derive(Debug)]
struct ProxyClientConfig<'a> {
    config: &'a ProxyConfig,
}

impl<'a> ProxyClientConfig<'a> {
    fn new(config: &'a ProxyConfig) -> Result<Self> {
        config
            .upstream_proxy_addrs
            .as_ref()
            .and_then(|addrs| if addrs.is_empty() { None } else { Some(()) })
            .ok_or_else(|| {
                ProxyError::Configuration(
                    "Upstream proxy addresses not configured or empty".to_string(),
                )
            })?;
        config.upstream_username.as_ref().ok_or_else(|| {
            ProxyError::Configuration("Upstream username not configured".to_string())
        })?;
        config.upstream_private_key_path.as_ref().ok_or_else(|| {
            ProxyError::Configuration("Upstream private key path not configured".to_string())
        })?;

        Ok(Self { config })
    }
}

impl<'a> ClientConnectionConfig for ProxyClientConfig<'a> {
    fn remote_addr(&self) -> String {
        use rand::prelude::*;
        let mut rng = rand::rng();
        self.config
            .upstream_proxy_addrs
            .as_ref()
            .expect("validated in ProxyClientConfig::new")
            .choose(&mut rng)
            .cloned()
            .expect("validated non-empty in ProxyClientConfig::new")
    }

    fn username(&self) -> String {
        self.config
            .upstream_username
            .as_ref()
            .cloned()
            .expect("validated in ProxyClientConfig::new")
    }

    fn private_key_pem(&self) -> std::result::Result<String, String> {
        let path = self
            .config
            .upstream_private_key_path
            .as_ref()
            .ok_or_else(|| "Private key path not configured".to_string())?;

        read_to_string(path).map_err(|e| e.to_string())
    }

    fn timeout_duration(&self) -> Duration {
        Duration::from_secs(self.config.connect_timeout_secs)
    }
}

/// Connection to an upstream proxy
pub struct UpstreamConnection {
    stream: ClientStream,
}

impl UpstreamConnection {
    /// Establish a connection to the upstream proxy
    pub async fn connect(
        config: &ProxyConfig,
        target_address: Address,
        transport: TransportProtocol,
    ) -> Result<Self> {
        let config_adapter = ProxyClientConfig::new(config)?;

        debug!("Connecting to upstream proxy");

        let client_conn = ClientConnection::connect(&config_adapter, target_address, transport)
            .await
            .map_err(|e| ProxyError::Connection(e.to_string()))?;

        Ok(Self {
            stream: client_conn.into_stream(),
        })
    }

    /// Convert into an AsyncRead + AsyncWrite stream
    pub fn into_stream(self) -> ClientStream {
        self.stream
    }
}
