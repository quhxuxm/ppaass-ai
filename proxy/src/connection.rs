use crate::bandwidth::BandwidthMonitor;
use crate::config::UserConfig;
use crate::error::{ProxyError, Result};
use futures::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use protocol::{
    Address, AuthRequest, AuthResponse, ConnectRequest, ConnectResponse, DataPacket, Message,
    MessageType, ProxyCodec, ProxyRequest, ProxyResponse,
    crypto::{AesGcmCipher, RsaKeyPair},
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
use tokio_util::codec::Framed;
use tracing::{debug, error, info};

type FramedWriter = SplitSink<Framed<TcpStream, ProxyCodec>, Message>;
type FramedReader = SplitStream<Framed<TcpStream, ProxyCodec>>;

/// Context for the bidirectional relay task containing shared resources
struct RelayContext {
    stream_id: String,
    writer: Arc<Mutex<FramedWriter>>,
    aes_cipher: Arc<AesGcmCipher>,
    bandwidth_monitor: Arc<BandwidthMonitor>,
    username: Option<String>,
}

impl RelayContext {
    /// Send a data packet to the agent
    async fn send_data_packet(&self, data_packet: DataPacket) -> Result<()> {
        let payload = serde_json::to_vec(&ProxyResponse::Data(data_packet))
            .map_err(|e| ProxyError::Protocol(protocol::ProtocolError::Serialization(e)))?;

        let encrypted_payload = self.aes_cipher.encrypt(&payload)?;
        let message = Message::new(MessageType::Data, encrypted_payload);

        let mut w = self.writer.lock().await;
        w.send(message)
            .await
            .map_err(|e| ProxyError::Protocol(protocol::ProtocolError::Io(e)))?;

        Ok(())
    }

    /// Send end-of-stream packet to agent
    async fn send_end_packet(&self) {
        let end_packet = DataPacket {
            stream_id: self.stream_id.clone(),
            data: vec![],
            is_end: true,
        };
        let _ = self.send_data_packet(end_packet).await;
    }
}

pub struct ProxyConnection {
    writer: Arc<Mutex<FramedWriter>>,
    reader: Arc<Mutex<FramedReader>>,
    user_config: Option<UserConfig>,
    aes_cipher: Option<Arc<AesGcmCipher>>,
    bandwidth_monitor: Arc<BandwidthMonitor>,
    // Store channels for sending data to target streams (for bidirectional copy)
    target_senders: HashMap<String, mpsc::Sender<Vec<u8>>>,
    // Store shutdown senders to signal end of stream
    target_shutdown: HashMap<String, mpsc::Sender<()>>,
    pending_auth_request: Option<AuthRequest>,
}

impl ProxyConnection {
    pub fn new(stream: TcpStream, bandwidth_monitor: Arc<BandwidthMonitor>) -> Self {
        let framed = Framed::new(stream, ProxyCodec::new());
        let (writer, reader) = framed.split();
        Self {
            writer: Arc::new(Mutex::new(writer)),
            reader: Arc::new(Mutex::new(reader)),
            user_config: None,
            aes_cipher: None,
            bandwidth_monitor,
            target_senders: HashMap::new(),
            target_shutdown: HashMap::new(),
            pending_auth_request: None,
        }
    }

    async fn send_message(&self, message: Message) -> Result<()> {
        let mut w = self.writer.lock().await;
        w.send(message)
            .await
            .map_err(|e| ProxyError::Protocol(protocol::ProtocolError::Io(e)))?;
        Ok(())
    }

    /// Send an encrypted data packet to the agent
    async fn send_encrypted_data_packet(&self, data_packet: DataPacket) -> Result<()> {
        let aes_cipher = self
            .aes_cipher
            .as_ref()
            .ok_or_else(|| ProxyError::Authentication("Not authenticated".to_string()))?;

        let payload = serde_json::to_vec(&ProxyResponse::Data(data_packet))
            .map_err(|e| ProxyError::Protocol(protocol::ProtocolError::Serialization(e)))?;

        let encrypted_payload = aes_cipher.encrypt(&payload)?;
        let message = Message::new(MessageType::Data, encrypted_payload);

        self.send_message(message).await
    }

    async fn read_message(&self) -> Result<Option<Message>> {
        let mut r = self.reader.lock().await;
        match r.next().await {
            Some(Ok(msg)) => Ok(Some(msg)),
            Some(Err(e)) => Err(ProxyError::Protocol(protocol::ProtocolError::Io(e))),
            None => Ok(None), // Connection closed
        }
    }

    /// Peek at the auth request to get the username without completing authentication
    pub async fn peek_auth_username(&mut self) -> Result<String> {
        // Receive auth request
        let msg = match self.read_message().await? {
            Some(msg) => msg,
            None => return Err(ProxyError::Connection("Connection closed".to_string())),
        };

        debug!(
            "[AUTH REQUEST] Received message: type={:?}, payload_len={}, payload_hex={}",
            msg.message_type,
            msg.payload.len(),
            hex::encode(&msg.payload)
        );

        let request: ProxyRequest = serde_json::from_slice(&msg.payload)
            .map_err(|e| ProxyError::Protocol(protocol::ProtocolError::Serialization(e)))?;

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
    pub async fn send_auth_error(&mut self, message: &str) -> Result<()> {
        let auth_response = AuthResponse {
            success: false,
            message: message.to_string(),
            session_id: None,
        };

        let payload = serde_json::to_vec(&ProxyResponse::Auth(auth_response))
            .map_err(|e| ProxyError::Protocol(protocol::ProtocolError::Serialization(e)))?;

        let message = Message::new(MessageType::AuthResponse, payload);
        self.send_message(message).await
    }

    pub async fn authenticate(&mut self, user_config: UserConfig) -> Result<()> {
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
        if (current_time - auth_request.timestamp).abs() > 300 {
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

        let payload = serde_json::to_vec(&ProxyResponse::Auth(auth_response))
            .map_err(|e| ProxyError::Protocol(protocol::ProtocolError::Serialization(e)))?;

        debug!(
            "[AUTH RESPONSE] Sending: success=true, session_id={}, payload_hex={}",
            session_id,
            hex::encode(&payload)
        );

        let message = Message::new(MessageType::AuthResponse, payload);
        self.send_message(message).await?;

        self.user_config = Some(user_config);
        self.aes_cipher = Some(Arc::new(aes_cipher));

        info!("Authentication successful");
        Ok(())
    }

    pub async fn handle_request(&mut self) -> Result<bool> {
        // Receive encrypted message
        let msg = match self.read_message().await? {
            Some(msg) => msg,
            None => return Ok(false), // Connection closed
        };

        debug!(
            "[REQUEST] Received message: type={:?}, payload_len={}, payload_hex={}",
            msg.message_type,
            msg.payload.len(),
            hex::encode(&msg.payload)
        );

        // Decrypt payload
        let aes_cipher = self
            .aes_cipher
            .as_ref()
            .ok_or_else(|| ProxyError::Authentication("Not authenticated".to_string()))?;

        let decrypted_payload = aes_cipher.decrypt(&msg.payload)?;

        debug!(
            "[REQUEST] Decrypted payload_len={}, payload_hex={}",
            decrypted_payload.len(),
            hex::encode(&decrypted_payload)
        );

        let request: ProxyRequest = serde_json::from_slice(&decrypted_payload)
            .map_err(|e| ProxyError::Protocol(protocol::ProtocolError::Serialization(e)))?;

        match request {
            ProxyRequest::Connect(ref connect_request) => {
                debug!(
                    "[CONNECT REQUEST] request_id={}, address={:?}",
                    connect_request.request_id, connect_request.address
                );
                self.handle_connect(connect_request.clone()).await?;
            }
            ProxyRequest::Data(ref data_packet) => {
                debug!(
                    "[DATA REQUEST] stream_id={}, data_len={}, is_end={}, data_hex={}",
                    data_packet.stream_id,
                    data_packet.data.len(),
                    data_packet.is_end,
                    hex::encode(&data_packet.data)
                );
                self.handle_data(data_packet.clone()).await?;
            }
            _ => {
                error!("Unexpected request type");
            }
        }

        Ok(true)
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

        match TcpStream::connect(&target_addr).await {
            Ok(stream) => {
                info!("Connected to target: {}", target_addr);

                let stream_id = connect_request.request_id.clone();

                // Create channels for bidirectional communication
                // Data channel: main task -> relay task (agent -> target)
                let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(32);
                // Shutdown channel: main task -> relay task
                let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

                // Store senders for this stream
                self.target_senders.insert(stream_id.clone(), data_tx);
                self.target_shutdown.insert(stream_id.clone(), shutdown_tx);

                // Create relay context with shared resources
                let ctx = RelayContext {
                    stream_id,
                    writer: self.writer.clone(),
                    aes_cipher: self.aes_cipher.clone().unwrap(),
                    bandwidth_monitor: self.bandwidth_monitor.clone(),
                    username: self.user_config.as_ref().map(|c| c.username.clone()),
                };

                // Spawn bidirectional relay task
                tokio::spawn(async move {
                    Self::bidirectional_relay_task(ctx, stream, data_rx, shutdown_rx).await;
                });

                let connect_response = ConnectResponse {
                    request_id: connect_request.request_id,
                    success: true,
                    message: "Connected".to_string(),
                };

                self.send_response(ProxyResponse::Connect(connect_response))
                    .await?;
            }
            Err(e) => {
                error!("Failed to connect to target: {}", e);
                self.send_connect_error(
                    connect_request.request_id,
                    format!("Failed to connect: {}", e),
                )
                .await?;
            }
        }

        Ok(())
    }

    /// Bidirectional relay task using tokio::io::copy_bidirectional pattern
    /// This handles both directions efficiently:
    /// - Agent -> Target: receives data from channel and writes to target
    /// - Target -> Agent: reads from target and sends encrypted data to agent
    async fn bidirectional_relay_task(
        ctx: RelayContext,
        target_stream: TcpStream,
        mut data_rx: mpsc::Receiver<Vec<u8>>,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) {
        let (mut target_reader, mut target_writer) = tokio::io::split(target_stream);
        let mut read_buffer = vec![0u8; 8192];
        let mut agent_closed = false;
        let mut target_closed = false;

        loop {
            if agent_closed && target_closed {
                break;
            }

            tokio::select! {
                // Receive data from agent (via channel) and write to target
                data = data_rx.recv(), if !agent_closed => {
                    match data {
                        Some(data) if data.is_empty() => {
                            // End of stream from agent
                            debug!("[RELAY] Agent signaled end of stream for: {}", ctx.stream_id);
                            let _ = target_writer.shutdown().await;
                            agent_closed = true;
                        }
                        Some(data) => {
                            debug!("[RELAY] {} bytes agent -> target for: {}", data.len(), ctx.stream_id);
                            if let Err(e) = target_writer.write_all(&data).await {
                                error!("Failed to write to target: {}", e);
                                agent_closed = true;
                            }
                        }
                        None => {
                            // Channel closed
                            debug!("[RELAY] Data channel closed for: {}", ctx.stream_id);
                            let _ = target_writer.shutdown().await;
                            agent_closed = true;
                        }
                    }
                }

                // Read from target and send to agent
                result = target_reader.read(&mut read_buffer), if !target_closed => {
                    match result {
                        Ok(0) => {
                            // Target closed
                            debug!("[RELAY] Target closed for: {}", ctx.stream_id);
                            ctx.send_end_packet().await;
                            target_closed = true;
                        }
                        Ok(n) => {
                            debug!("[RELAY] {} bytes target -> agent for: {}", n, ctx.stream_id);

                            // Record bandwidth
                            if let Some(ref user) = ctx.username {
                                ctx.bandwidth_monitor.record_sent(user, n as u64);
                                if !ctx.bandwidth_monitor.check_limit(user).await {
                                    ctx.send_end_packet().await;
                                    target_closed = true;
                                    continue;
                                }
                            }

                            let data_packet = DataPacket {
                                stream_id: ctx.stream_id.clone(),
                                data: read_buffer[..n].to_vec(),
                                is_end: false,
                            };
                            if let Err(e) = ctx.send_data_packet(data_packet).await {
                                error!("Failed to send data to agent: {}", e);
                                target_closed = true;
                            }
                        }
                        Err(e) => {
                            error!("[RELAY] Error reading from target: {}", e);
                            ctx.send_end_packet().await;
                            target_closed = true;
                        }
                    }
                }

                // Handle shutdown signal
                _ = shutdown_rx.recv() => {
                    debug!("[RELAY] Shutdown signal received for: {}", ctx.stream_id);
                    let _ = target_writer.shutdown().await;
                    break;
                }
            }
        }

        info!("[RELAY] Relay task ended for stream: {}", ctx.stream_id);
    }

    async fn handle_data(&mut self, data_packet: DataPacket) -> Result<()> {
        debug!(
            "[AGENT->TARGET] Data packet for stream: {}, size: {}, is_end: {}",
            data_packet.stream_id,
            data_packet.data.len(),
            data_packet.is_end
        );

        // Record bandwidth usage and enforce limit
        if let Some(user_config) = &self.user_config {
            self.bandwidth_monitor
                .record_received(&user_config.username, data_packet.data.len() as u64);
            if !self
                .bandwidth_monitor
                .check_limit(&user_config.username)
                .await
            {
                let end_packet = DataPacket {
                    stream_id: data_packet.stream_id.clone(),
                    data: vec![],
                    is_end: true,
                };
                let _ = self.send_encrypted_data_packet(end_packet).await;
                // Signal shutdown to relay task
                if let Some(shutdown_tx) = self.target_shutdown.remove(&data_packet.stream_id) {
                    let _ = shutdown_tx.send(()).await;
                }
                self.target_senders.remove(&data_packet.stream_id);
                return Ok(());
            }
        }

        // Get the data sender channel for this stream_id
        let data_sender = self.target_senders.get(&data_packet.stream_id).cloned();

        match data_sender {
            Some(sender) => {
                // Send data to relay task via channel
                if data_packet.is_end {
                    // Send empty data to signal end of stream
                    debug!("[AGENT->TARGET] End of stream, sending shutdown signal");
                    if sender.send(vec![]).await.is_err() {
                        debug!("Channel closed for stream: {}", data_packet.stream_id);
                    }
                    self.target_senders.remove(&data_packet.stream_id);
                    self.target_shutdown.remove(&data_packet.stream_id);
                } else if !data_packet.data.is_empty() {
                    debug!(
                        "[AGENT->TARGET] Forwarding {} bytes via channel",
                        data_packet.data.len()
                    );
                    if sender.send(data_packet.data).await.is_err() {
                        error!("Failed to send data to relay task");
                        self.target_senders.remove(&data_packet.stream_id);
                        self.target_shutdown.remove(&data_packet.stream_id);
                    }
                }
            }
            None => {
                // This can happen if the relay task already closed the connection
                debug!(
                    "No channel found for stream_id: {} (may already be closed)",
                    data_packet.stream_id
                );
            }
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

    async fn send_response(&self, response: ProxyResponse) -> Result<()> {
        let payload = serde_json::to_vec(&response)
            .map_err(|e| ProxyError::Protocol(protocol::ProtocolError::Serialization(e)))?;

        debug!(
            "[RESPONSE] Plain payload_len={}, payload_hex={}",
            payload.len(),
            hex::encode(&payload)
        );

        // Encrypt payload
        let aes_cipher = self
            .aes_cipher
            .as_ref()
            .ok_or_else(|| ProxyError::Authentication("Not authenticated".to_string()))?;

        let encrypted_payload = aes_cipher.encrypt(&payload)?;
        let payload_len = encrypted_payload.len();

        debug!(
            "[RESPONSE] Encrypted payload_len={}, payload_hex={}",
            payload_len,
            hex::encode(&encrypted_payload)
        );

        let message = Message::new(MessageType::Data, encrypted_payload);

        // Use codec to encode message with length-delimited framing
        self.send_message(message).await?;

        debug!("[RESPONSE] Message sent successfully");

        // Record bandwidth usage
        if let Some(user_config) = &self.user_config {
            self.bandwidth_monitor
                .record_sent(&user_config.username, payload_len as u64);
        }

        Ok(())
    }
}
