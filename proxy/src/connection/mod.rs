mod agent_io;
mod response_sink;
mod upstream;

pub use agent_io::AgentIo;
pub use response_sink::BytesToProxyResponseSink;
// UpstreamConnection is exported at the end of the file after ServerConnection definition

use crate::bandwidth::BandwidthMonitor;
use crate::config::{ProxyConfig, UserConfig};
use crate::connection::upstream::UpstreamConnection;
use crate::error::{ProxyError, Result};
use bytes::Bytes;
use futures::{
    stream::{SplitSink, SplitStream}, SinkExt,
    StreamExt,
};
use protocol::{
    crypto::{AesGcmCipher, RsaKeyPair}, Address, AuthRequest, AuthResponse, CipherState, CompressionMode,
    ConnectRequest, ConnectResponse, ProxyRequest, ProxyResponse, ServerCodec,
    TransportProtocol,
};
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_util::codec::Framed;
use tokio_util::io::{SinkWriter, StreamReader};
use tracing::{debug, error, info, instrument};

type FramedWriter = SplitSink<Framed<TcpStream, ServerCodec>, ProxyResponse>;
type FramedReader = SplitStream<Framed<TcpStream, ServerCodec>>;

pub struct ServerConnection {
    writer: FramedWriter,
    reader: FramedReader,
    user_config: Option<UserConfig>,
    bandwidth_monitor: Arc<BandwidthMonitor>,
    cipher_state: Arc<CipherState>,
    pending_auth_request: Option<AuthRequest>,
    proxy_config: Arc<ProxyConfig>,
}

impl ServerConnection {
    pub fn new(
        stream: TcpStream,
        bandwidth_monitor: Arc<BandwidthMonitor>,
        compression_mode: CompressionMode,
        proxy_config: Arc<ProxyConfig>,
    ) -> Self {
        let cipher_state = Arc::new(CipherState::with_compression(compression_mode));
        let framed = Framed::new(stream, ServerCodec::new(Some(cipher_state.clone())));
        let (writer, reader) = framed.split();

        Self {
            writer,
            reader,
            user_config: None,
            bandwidth_monitor,
            cipher_state,
            pending_auth_request: None,
            proxy_config,
        }
    }

    async fn read_request(&mut self) -> Result<Option<ProxyRequest>> {
        match self.reader.next().await {
            Some(Ok(req)) => Ok(Some(req)),
            Some(Err(e)) => Err(ProxyError::Protocol(protocol::ProtocolError::Io(e))),
            None => Ok(None), // Connection closed
        }
    }

    /// Peek at the auth request to get the username without completing authentication
    #[instrument(skip(self))]
    pub async fn peek_auth_username(&mut self) -> Result<String> {
        // Receive auth request
        // First request is always AuthRequest?
        let request = match self.read_request().await? {
            Some(req) => req,
            None => return Err(ProxyError::Connection("Connection closed".to_string())),
        };

        if let ProxyRequest::Auth(auth_request) = request {
            let username = auth_request.username.clone();
            debug!(
                "[AUTH REQUEST] username={}, timestamp={}, encrypted_aes_key_len={}",
                auth_request.username,
                auth_request.timestamp,
                auth_request.encrypted_aes_key.len()
            );
            // Store the auth request for later use
            self.pending_auth_request = Some(auth_request);
            Ok(username)
        } else {
            Err(ProxyError::Authentication(
                "Expected auth request".to_string(),
            ))
        }
    }

    /// Send an authentication error response
    #[instrument(skip(self))]
    pub async fn send_auth_error(&mut self, message: &str) -> Result<()> {
        let auth_response = AuthResponse {
            success: false,
            message: message.to_string(),
            session_id: None,
        };

        self.send_response(ProxyResponse::Auth(auth_response)).await
    }

    #[instrument(skip(self, proxy_config, user_config))]
    pub async fn authenticate(
        &mut self,
        proxy_config: &ProxyConfig,
        user_config: UserConfig,
    ) -> Result<()> {
        info!(
            "Authenticating connection for user: {}",
            user_config.username
        );

        // Use the pending auth request that was read in peek_auth_username
        let auth_request = self
            .pending_auth_request
            .take()
            .ok_or_else(|| ProxyError::Authentication("No pending auth request".to_string()))?;

        debug!(
            "[AUTH REQUEST] Processing: username={}, timestamp={}, encrypted_aes_key_len={}, encrypted_aes_key_hex={}",
            auth_request.username,
            auth_request.timestamp,
            auth_request.encrypted_aes_key.len(),
            hex::encode(&auth_request.encrypted_aes_key)
        );

        // Verify username matches
        if auth_request.username != user_config.username {
            self.send_auth_error("Username mismatch").await?;
            return Err(ProxyError::Authentication("Username mismatch".to_string()));
        }

        // Verify timestamp to prevent replay attacks
        let current_time = common::current_timestamp();
        if (current_time - auth_request.timestamp).abs() > proxy_config.replay_attack_tolerance {
            // 5 minutes tolerance
            self.send_auth_error("Timestamp expired").await?;
            return Err(ProxyError::Authentication("Timestamp expired".to_string()));
        }

        // Decrypt AES key using user's public key
        let user_public_key = RsaKeyPair::from_public_key_pem(&user_config.public_key_pem)
            .map_err(|e| ProxyError::Authentication(format!("Invalid public key: {}", e)))?;

        let aes_key_bytes = protocol::crypto::decrypt_with_public_key(
            &user_public_key,
            &auth_request.encrypted_aes_key,
        )
        .map_err(|e| {
            error!("Failed to decrypt AES key: {}", e);
            ProxyError::Authentication(format!("Failed to decrypt AES key: {}", e))
        })?;

        debug!(
            "[AUTH REQUEST] Decrypted AES key_len={}, aes_key_hex={}",
            aes_key_bytes.len(),
            hex::encode(&aes_key_bytes)
        );

        // Convert to fixed-size array
        let aes_key: [u8; 32] = aes_key_bytes
            .try_into()
            .map_err(|_| ProxyError::Authentication("Invalid AES key length".to_string()))?;

        let aes_cipher = AesGcmCipher::from_key(aes_key);

        let session_id = common::generate_id();

        // Send auth response
        let auth_response = AuthResponse {
            success: true,
            message: "Authentication successful".to_string(),
            session_id: Some(session_id.clone()),
        };

        debug!(
            "[AUTH RESPONSE] Sending: success=true, session_id={:?}",
            auth_response.session_id
        );

        self.send_response(ProxyResponse::Auth(auth_response))
            .await?;

        self.user_config = Some(user_config);

        // Update cipher state for future messages
        self.cipher_state.set_cipher(Arc::new(aes_cipher));

        info!("Authentication successful");
        Ok(())
    }

    async fn send_response(&mut self, response: ProxyResponse) -> Result<()> {
        self.writer
            .send(response)
            .await
            .map_err(|e| ProxyError::Connection(format!("Failed to send response: {}", e)))?;
        Ok(())
    }

    pub async fn handle_request(&mut self) -> Result<()> {
        // Only loops for initial requests (Auth, Connect)
        // Once connected, it hands over to relay and returns.
        loop {
            match self.reader.next().await {
                Some(Ok(req)) => {
                    match req {
                        ProxyRequest::Connect(connect_request) => {
                            debug!(
                                "[CONNECT REQUEST] request_id={}, address={:?}",
                                connect_request.request_id, connect_request.address
                            );
                            self.handle_connect(connect_request).await?;
                            // After relay finishes (connection closed),
                            // we return to close connection
                            return Ok(());
                        }
                        ProxyRequest::Auth(auth_request) => {
                            debug!(
                                "Unexpected Auth request in process loop: {:?}",
                                auth_request.username
                            );
                        }
                        _ => {
                            error!("Unexpected request type before Connect");
                        }
                    }
                }
                Some(Err(e)) => return Err(ProxyError::Protocol(protocol::ProtocolError::Io(e))),
                None => return Ok(()), // Agent connection closed
            }
        }
    }

    async fn handle_connect(&mut self, connect_request: ConnectRequest) -> Result<()> {
        info!("Connect request: {:?}", connect_request.address);

        // Check user bandwidth limit
        if let Some(user_config) = &self.user_config
            && !self
                .bandwidth_monitor
                .check_limit(&user_config.username)
                .await
        {
            return self
                .send_connect_error(
                    connect_request.request_id,
                    "Bandwidth limit exceeded".to_string(),
                )
                .await;
        }

        // Check if forwarding mode is enabled
        if self.proxy_config.forward_mode {
            info!("Forwarding request to upstream proxy");

            // Connect to upstream proxy
            match UpstreamConnection::connect(
                &self.proxy_config,
                connect_request.address.clone(),
                connect_request.transport,
            )
            .await
            {
                Ok(upstream_conn) => {
                    info!("Connected to upstream proxy");

                    let connect_response = ConnectResponse {
                        request_id: connect_request.request_id.clone(),
                        success: true,
                        message: "Connected through upstream".to_string(),
                    };

                    self.send_response(ProxyResponse::Connect(connect_response))
                        .await?;

                    // Convert upstream connection to IO stream
                    let mut stream = upstream_conn.into_stream();

                    // Relay data
                    self.relay(connect_request.request_id, &mut stream).await?;
                }
                Err(e) => {
                    error!("Failed to connect to upstream: {}", e);
                    self.send_connect_error(
                        connect_request.request_id,
                        format!("Upstream error: {}", e),
                    )
                    .await?;
                }
            }
            return Ok(());
        }

        // Connect to target
        let target_addr = match &connect_request.address {
            Address::Domain { host, port } => format!("{}:{}", host, port),
            Address::Ipv4 { addr, port } => {
                format!("{}.{}.{}.{}:{}", addr[0], addr[1], addr[2], addr[3], port)
            }
            Address::Ipv6 { addr, port } => {
                format!(
                    "[{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}]:{}",
                    u16::from_be_bytes([addr[0], addr[1]]),
                    u16::from_be_bytes([addr[2], addr[3]]),
                    u16::from_be_bytes([addr[4], addr[5]]),
                    u16::from_be_bytes([addr[6], addr[7]]),
                    u16::from_be_bytes([addr[8], addr[9]]),
                    u16::from_be_bytes([addr[10], addr[11]]),
                    u16::from_be_bytes([addr[12], addr[13]]),
                    u16::from_be_bytes([addr[14], addr[15]]),
                    port
                )
            }
        };

        match connect_request.transport {
            TransportProtocol::Tcp => {
                match TcpStream::connect(&target_addr).await {
                    Ok(mut target_stream) => {
                        info!("Connected to target (TCP): {}", target_addr);

                        let connect_response = ConnectResponse {
                            request_id: connect_request.request_id.clone(),
                            success: true,
                            message: "Connected".to_string(),
                        };

                        self.send_response(ProxyResponse::Connect(connect_response))
                            .await?;

                        // Handover to bidirectional relay
                        self.relay(connect_request.request_id, &mut target_stream)
                            .await?;
                    }
                    Err(e) => {
                        error!("Failed to connect to target (TCP): {}", e);
                        self.send_connect_error(
                            connect_request.request_id,
                            format!("Failed to connect: {}", e),
                        )
                        .await?;
                    }
                }
            }
            TransportProtocol::Udp => {
                // Bind to any available port
                match UdpSocket::bind("0.0.0.0:0").await {
                    Ok(socket) => {
                        if let Err(e) = socket.connect(&target_addr).await {
                            error!("Failed to connect to target (UDP): {}", e);
                            self.send_connect_error(
                                connect_request.request_id,
                                format!("Failed to connect UDP: {}", e),
                            )
                            .await?;
                            return Ok(());
                        }

                        info!("Connected to target (UDP): {}", target_addr);

                        let connect_response = ConnectResponse {
                            request_id: connect_request.request_id.clone(),
                            success: true,
                            message: "Connected".to_string(),
                        };

                        self.send_response(ProxyResponse::Connect(connect_response))
                            .await?;

                        self.relay_udp(connect_request.request_id, socket).await?;
                    }
                    Err(e) => {
                        error!("Failed to bind UDP socket: {}", e);
                        self.send_connect_error(
                            connect_request.request_id,
                            format!("Failed to bind UDP: {}", e),
                        )
                        .await?;
                    }
                }
            }
        }

        Ok(())
    }

    #[instrument(skip(self, udp_socket))]
    async fn relay_udp(&mut self, stream_id: String, udp_socket: UdpSocket) -> Result<()> {
        let username = self.user_config.as_ref().map(|c| c.username.clone());
        let monitor_stream = self.bandwidth_monitor.clone();
        let username_stream = username.clone();

        // Use a custom Sink implementation
        let sink = BytesToProxyResponseSink {
            inner: &mut self.writer,
            stream_id: stream_id.clone(),
            username: username.clone(),
            bandwidth_monitor: self.bandwidth_monitor.clone(),
        };

        let stream = (&mut self.reader).filter_map(move |res| {
            let user = username_stream.as_ref();
            let monitor = &monitor_stream;

            let result = match res {
                Ok(ProxyRequest::Data(packet)) => {
                    if !packet.data.is_empty() {
                        if let Some(u) = user {
                            monitor.record_received(u, packet.data.len() as u64);
                        }
                        Some(Ok(Bytes::from(packet.data)))
                    } else {
                        None
                    }
                }
                Ok(_) => None,
                Err(e) => Some(Err(io::Error::other(e))),
            };

            futures::future::ready(result)
        });

        let writer = SinkWriter::new(sink);
        let reader = StreamReader::new(stream);

        let agent_io = AgentIo { reader, writer };

        let udp_socket = Arc::new(udp_socket);
        let udp_recv = udp_socket.clone();
        let udp_send = udp_socket.clone();

        let (mut agent_reader, mut agent_writer) = tokio::io::split(agent_io);

        let agent_to_udp = async {
            let mut buf = [0u8; 65535];
            loop {
                match agent_reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        let data = &buf[..n];
                        debug!(
                            "Receive UDP data from agent for target: {:?}\n{}",
                            udp_socket.peer_addr(),
                            pretty_hex::pretty_hex(&data)
                        );
                        if let Err(e) = udp_send.send(data).await {
                            debug!("UDP send error: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("Agent read error: {}", e);
                        break;
                    }
                }
            }
        };

        let udp_to_agent = async {
            let mut buf = [0u8; 65535];
            loop {
                match udp_recv.recv(&mut buf).await {
                    Ok(n) => {
                        let data = &buf[..n];
                        debug!(
                            "Receive UDP data from target to agent: {:?}\n{}",
                            udp_socket.peer_addr(),
                            pretty_hex::pretty_hex(&data)
                        );
                        if let Err(e) = agent_writer.write_all(data).await {
                            debug!("Agent write error: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("UDP recv error: {}", e);
                        break;
                    }
                }
            }
        };

        tokio::select! {
            _ = agent_to_udp => {},
            _ = udp_to_agent => {}
        }

        debug!("UDP Relay finished");
        Ok(())
    }

    async fn relay<S>(&mut self, stream_id: String, target_stream: &mut S) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        let username = self.user_config.as_ref().map(|c| c.username.clone());
        let monitor_stream = self.bandwidth_monitor.clone();
        let username_stream = username.clone();

        // Use a custom Sink implementation to avoid HRTB issues with SinkExt::with and closures
        let sink = BytesToProxyResponseSink {
            inner: &mut self.writer,
            stream_id: stream_id.clone(),
            username: username.clone(),
            bandwidth_monitor: self.bandwidth_monitor.clone(),
        };

        let stream = (&mut self.reader).filter_map(move |res| {
            let user = username_stream.as_ref();
            let monitor = &monitor_stream;

            let result = match res {
                Ok(ProxyRequest::Data(packet)) => {
                    if !packet.data.is_empty() {
                        if let Some(u) = user {
                            monitor.record_received(u, packet.data.len() as u64);
                        }
                        Some(Ok(Bytes::from(packet.data)))
                    } else {
                        // Empty data or is_end=true: ignore, let TCP FIN handle EOF
                        None
                    }
                }
                Ok(_) => None, // Ignore non-Data packets
                Err(e) => Some(Err(io::Error::other(e))),
            };

            futures::future::ready(result)
        });

        let writer = SinkWriter::new(sink);
        let reader = StreamReader::new(stream);

        let mut agent_io = AgentIo { reader, writer };

        match tokio::io::copy_bidirectional(target_stream, &mut agent_io).await {
            Ok((up, down)) => debug!("Relay finished: {} up, {} down", up, down),
            Err(e) => debug!("Relay error: {}", e),
        }

        Ok(())
    }

    async fn send_connect_error(&mut self, request_id: String, message: String) -> Result<()> {
        let connect_response = ConnectResponse {
            request_id,
            success: false,
            message,
        };

        self.send_response(ProxyResponse::Connect(connect_response))
            .await
    }
}
