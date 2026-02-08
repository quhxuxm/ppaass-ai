use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use protocol::{
    Address, AgentCodec, AuthRequest, ConnectRequest, ProxyRequest, ProxyResponse,
    TransportProtocol,
    crypto::{AesGcmCipher, RsaKeyPair},
};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use tracing::{debug, info};

use super::config::ClientConnectionConfig;
use super::stream::ClientStream;

type FramedWriter = SplitSink<Framed<TcpStream, AgentCodec>, ProxyRequest>;
type FramedReader = SplitStream<Framed<TcpStream, AgentCodec>>;

/// An authenticated client connection to a remote proxy
/// Can be used to send connect requests to the remote proxy, or converted into a stream
pub struct AuthenticatedConnection {
    writer: FramedWriter,
    reader: FramedReader,
}

impl AuthenticatedConnection {
    /// Establish an authenticated connection to a remote proxy without immediately connecting to a target
    /// This is useful for connection pooling where connections are prewarmed with just authentication
    pub async fn authenticate_only<C>(config: &C) -> Result<Self, std::io::Error>
    where
        C: ClientConnectionConfig,
    {
        let remote_addr = config.remote_addr();
        let username = config.username();
        let timeout = config.timeout_duration();

        debug!("Connecting to remote proxy: {}", remote_addr);

        // 1. TCP Connect
        let stream = match tokio::time::timeout(timeout, TcpStream::connect(&remote_addr)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Connection timeout",
                ));
            }
        };

        // 2. Setup Codec
        let framed = Framed::new(stream, AgentCodec::new());
        let (mut writer, mut reader) = framed.split();

        // 3. Prepare Auth
        let aes_cipher = AesGcmCipher::new();
        let aes_key = *aes_cipher.key();

        let private_key_pem = config
            .private_key_pem()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let rsa_keypair = RsaKeyPair::from_private_key_pem(&private_key_pem)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        let encrypted_aes_key = rsa_keypair
            .encrypt_with_private_key(&aes_key)
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        let auth_request = AuthRequest {
            username,
            timestamp: crate::current_timestamp(),
            encrypted_aes_key,
        };

        // 4. Send Auth
        writer
            .send(ProxyRequest::Auth(auth_request))
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        // 5. Read Auth Response
        let response = match tokio::time::timeout(timeout, reader.next()).await {
            Ok(Some(Ok(resp))) => resp,
            Ok(Some(Err(e))) => return Err(e),
            Ok(None) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "Remote closed connection during auth",
                ));
            }
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Auth response timeout",
                ));
            }
        };

        if let ProxyResponse::Auth(auth_resp) = response {
            if !auth_resp.success {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("Auth failed: {}", auth_resp.message),
                ));
            }
            info!("Authenticated with remote proxy");
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Expected AuthResponse",
            ));
        }

        Ok(Self { writer, reader })
    }

    /// Connect to a target through the authenticated connection
    pub async fn connect_to_target(
        mut self,
        address: Address,
        transport: TransportProtocol,
    ) -> Result<(ClientStream, String), std::io::Error> {
        // 6. Send Connect Request
        let request_id = crate::generate_id();
        let connect_request = ConnectRequest {
            request_id: request_id.clone(),
            address: address.clone(),
            transport,
        };

        self.writer
            .send(ProxyRequest::Connect(connect_request))
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        // 7. Read Connect Response
        let response = self
            .reader
            .next()
            .await
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "Remote closed connection during connect",
                )
            })
            .and_then(|r| r)?;

        if let ProxyResponse::Connect(connect_resp) = response {
            if !connect_resp.success {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    format!("Connect failed: {}", connect_resp.message),
                ));
            }
            info!("Connected to target through remote proxy");
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Expected ConnectResponse",
            ));
        }

        Ok((
            ClientStream {
                writer: self.writer,
                reader: self.reader,
                stream_id: request_id.clone(),
                read_buf: Vec::new(),
                read_pos: 0,
            },
            request_id,
        ))
    }
}
