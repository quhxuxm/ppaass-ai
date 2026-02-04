use super::connected_stream::ConnectedStream;
use crate::config::AgentConfig;
use crate::error::{AgentError, Result};
use futures::{SinkExt, StreamExt};
use protocol::{
    Address, AgentCodec, AuthRequest, ConnectRequest, ProxyRequest, ProxyResponse,
    crypto::{AesGcmCipher, RsaKeyPair},
    CipherState,
};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use futures::stream::{SplitSink, SplitStream};
use tracing::{debug, info};

type FramedWriter = SplitSink<Framed<TcpStream, AgentCodec>, ProxyRequest>;
type FramedReader = SplitStream<Framed<TcpStream, AgentCodec>>;

/// A single-use authenticated connection to the proxy
/// This connection is used for one request and then discarded
pub struct ProxyConnection {
    writer: FramedWriter,
    reader: FramedReader,
}

impl ProxyConnection {
    /// Create a new authenticated connection to the proxy
    pub async fn new(config: &AgentConfig) -> Result<Self> {
        debug!("Creating new connection to proxy: {}", config.proxy_addr);

        let stream = TcpStream::connect(&config.proxy_addr)
            .await
            .map_err(|e| AgentError::Connection(e.to_string()))?;

        let cipher_state = Arc::new(CipherState::new());
        let framed = Framed::new(stream, AgentCodec::new(Some(cipher_state.clone())));
        let (mut writer, mut reader) = framed.split();

        // Generate AES key for the session
        let aes_cipher = AesGcmCipher::new();
        let aes_key = *aes_cipher.key();

        // Load user's private key to encrypt the AES key
        let private_key_pem = std::fs::read_to_string(&config.private_key_path).map_err(|e| {
            AgentError::Authentication(format!("Failed to read private key: {}", e))
        })?;

        let rsa_keypair = RsaKeyPair::from_private_key_pem(&private_key_pem)?;
        let encrypted_aes_key = rsa_keypair.encrypt_with_private_key(&aes_key)?;

        // Send auth request
        let auth_request = AuthRequest {
            username: config.username.clone(),
            timestamp: common::current_timestamp(),
            encrypted_aes_key,
        };

        debug!("[AUTH] Sending auth request");
        writer
            .send(ProxyRequest::Auth(auth_request))
            .await
            .map_err(|e| AgentError::Connection(format!("Failed to send auth request: {}", e)))?;

        // Wait for auth response with timeout
        let response =
            match tokio::time::timeout(std::time::Duration::from_secs(10), reader.next()).await {
                Ok(Some(Ok(resp))) => resp,
                Ok(Some(Err(e))) => {
                    return Err(AgentError::Connection(format!(
                        "Failed to read auth response: {}",
                        e
                    )));
                }
                Ok(None) => {
                    return Err(AgentError::Connection(
                        "Connection closed during auth".to_string(),
                    ));
                }
                Err(_) => {
                    return Err(AgentError::Authentication("Auth timeout".to_string()));
                }
            };

        match response {
            ProxyResponse::Auth(auth_resp) => {
                if !auth_resp.success {
                    return Err(AgentError::Authentication(auth_resp.message));
                }
                info!("Authentication successful");

                // Set the cipher key in the state for subsequent messages
                cipher_state.set_cipher(Arc::new(aes_cipher));
            }
            _ => {
                return Err(AgentError::Authentication(
                    "Unexpected auth response".to_string(),
                ));
            }
        }

        Ok(Self {
            writer,
            reader,
        })
    }

    /// Connect to a target address and return a bidirectional stream handle
    pub async fn connect_target(
        mut self,
        address: Address,
        transport: protocol::TransportProtocol,
    ) -> Result<ConnectedStream> {
        let request_id = common::generate_id();

        let connect_request = ConnectRequest {
            request_id: request_id.clone(),
            address: address.clone(),
            transport,
        };

        // Encryption and serialization is now handled by the codec
        debug!("[CONNECT] Sending connect request for {:?}", address);
        self.writer.send(ProxyRequest::Connect(connect_request)).await.map_err(|e| {
            AgentError::Connection(format!("Failed to send connect request: {}", e))
        })?;

        // Wait for connect response with timeout
        let response = match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            self.reader.next(),
        )
        .await
        {
            Ok(Some(Ok(resp))) => resp,
            Ok(Some(Err(e))) => {
                return Err(AgentError::Connection(format!(
                    "Failed to read connect response: {}",
                    e
                )));
            }
            Ok(None) => {
                return Err(AgentError::Connection(
                    "Connection closed during connect".to_string(),
                ));
            }
            Err(_) => {
                return Err(AgentError::Connection("Connect timeout".to_string()));
            }
        };

        match response {
            ProxyResponse::Connect(connect_resp) => {
                if !connect_resp.success {
                    return Err(AgentError::Connection(connect_resp.message));
                }
                info!("Connected to target: {:?}", address);
            }
            _ => {
                return Err(AgentError::Connection(
                    "Unexpected connect response".to_string(),
                ));
            }
        }

        Ok(ConnectedStream::new(self.writer, self.reader, request_id))
    }
}
