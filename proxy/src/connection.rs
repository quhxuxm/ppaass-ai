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
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_util::codec::Framed;
use tracing::{debug, error, info};

type FramedWriter = SplitSink<Framed<TcpStream, ProxyCodec>, Message>;
type FramedReader = SplitStream<Framed<TcpStream, ProxyCodec>>;

pub struct ProxyConnection {
    writer: Arc<Mutex<FramedWriter>>,
    reader: Arc<Mutex<FramedReader>>,
    user_config: Option<UserConfig>,
    aes_cipher: Option<Arc<AesGcmCipher>>,
    bandwidth_monitor: Arc<BandwidthMonitor>,
    // Store write half of target streams, read half is handled by spawned tasks
    target_writers: HashMap<String, Arc<Mutex<WriteHalf<TcpStream>>>>,
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
            target_writers: HashMap::new(),
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
            ProxyRequest::Heartbeat => {
                debug!("[HEARTBEAT REQUEST]");
                self.handle_heartbeat().await?;
            }
            ProxyRequest::Disconnect(ref stream_id) => {
                debug!("[DISCONNECT REQUEST] stream_id={}", stream_id);
                info!("Disconnect request for stream: {}", stream_id);
                self.target_writers.remove(stream_id);
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

                // Split target stream into read and write halves
                let (target_reader, target_writer) = tokio::io::split(stream);

                // Store the write half for sending data to target
                let stream_id = connect_request.request_id.clone();
                self.target_writers
                    .insert(stream_id.clone(), Arc::new(Mutex::new(target_writer)));

                // Spawn a task to continuously read from target and send to agent
                let writer = self.writer.clone();
                let aes_cipher = self.aes_cipher.clone().unwrap();
                let bandwidth_monitor = self.bandwidth_monitor.clone();
                let username = self.user_config.as_ref().map(|c| c.username.clone());

                tokio::spawn(async move {
                    Self::target_reader_task(
                        stream_id,
                        target_reader,
                        writer,
                        aes_cipher,
                        bandwidth_monitor,
                        username,
                    )
                    .await;
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

    /// Background task that continuously reads from target and sends data back to agent
    async fn target_reader_task(
        stream_id: String,
        mut target_reader: ReadHalf<TcpStream>,
        writer: Arc<Mutex<FramedWriter>>,
        aes_cipher: Arc<AesGcmCipher>,
        bandwidth_monitor: Arc<BandwidthMonitor>,
        username: Option<String>,
    ) {
        let mut buffer = vec![0u8; 16384];

        loop {
            match target_reader.read(&mut buffer).await {
                Ok(0) => {
                    // Target closed connection
                    debug!(
                        "[TARGET->AGENT] Target closed connection for stream: {}",
                        stream_id
                    );
                    let end_packet = DataPacket {
                        stream_id: stream_id.clone(),
                        data: vec![],
                        is_end: true,
                    };
                    if let Err(e) = Self::send_data_packet(&writer, &aes_cipher, end_packet).await {
                        error!("Failed to send end packet: {}", e);
                    }
                    break;
                }
                Ok(n) => {
                    debug!(
                        "[TARGET->AGENT] Read {} bytes from target for stream: {}",
                        n, stream_id
                    );

                    // Record bandwidth and enforce limit
                    if let Some(ref user) = username {
                        bandwidth_monitor.record_sent(user, n as u64);
                        if !bandwidth_monitor.check_limit(user).await {
                            let end_packet = DataPacket {
                                stream_id: stream_id.clone(),
                                data: vec![],
                                is_end: true,
                            };
                            if let Err(e) =
                                Self::send_data_packet(&writer, &aes_cipher, end_packet).await
                            {
                                error!("Failed to send end packet: {}", e);
                            }
                            break;
                        }
                    }

                    let data_packet = DataPacket {
                        stream_id: stream_id.clone(),
                        data: buffer[..n].to_vec(),
                        is_end: false,
                    };

                    if let Err(e) = Self::send_data_packet(&writer, &aes_cipher, data_packet).await
                    {
                        error!("Failed to send data packet: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    error!("[TARGET->AGENT] Error reading from target: {}", e);
                    let end_packet = DataPacket {
                        stream_id: stream_id.clone(),
                        data: vec![],
                        is_end: true,
                    };
                    let _ = Self::send_data_packet(&writer, &aes_cipher, end_packet).await;
                    break;
                }
            }
        }

        debug!(
            "[TARGET->AGENT] Reader task ended for stream: {}",
            stream_id
        );
    }

    /// Helper to send a data packet to the agent
    async fn send_data_packet(
        writer: &Arc<Mutex<FramedWriter>>,
        aes_cipher: &AesGcmCipher,
        data_packet: DataPacket,
    ) -> Result<()> {
        let payload = serde_json::to_vec(&ProxyResponse::Data(data_packet))
            .map_err(|e| ProxyError::Protocol(protocol::ProtocolError::Serialization(e)))?;

        let encrypted_payload = aes_cipher.encrypt(&payload)?;
        let message = Message::new(MessageType::Data, encrypted_payload);

        let mut w = writer.lock().await;
        w.send(message)
            .await
            .map_err(|e| ProxyError::Protocol(protocol::ProtocolError::Io(e)))?;

        Ok(())
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
                if let Some(aes_cipher) = &self.aes_cipher {
                    let end_packet = DataPacket {
                        stream_id: data_packet.stream_id.clone(),
                        data: vec![],
                        is_end: true,
                    };
                    let _ = Self::send_data_packet(&self.writer, aes_cipher, end_packet).await;
                }
                if let Some(writer) = self.target_writers.remove(&data_packet.stream_id) {
                    let mut w = writer.lock().await;
                    let _ = w.shutdown().await;
                }
                return Ok(());
            }
        }

        // Get the target writer for this stream_id (clone the Arc to avoid borrow issues)
        let target_writer = self.target_writers.get(&data_packet.stream_id).cloned();

        match target_writer {
            Some(writer) => {
                // Forward data to target
                if !data_packet.data.is_empty() {
                    debug!(
                        "[AGENT->TARGET] Forwarding {} bytes to target",
                        data_packet.data.len()
                    );
                    let mut w = writer.lock().await;
                    if let Err(e) = w.write_all(&data_packet.data).await {
                        error!("Failed to write to target: {}", e);
                        drop(w); // Drop the lock before removing
                        self.target_writers.remove(&data_packet.stream_id);
                        return Ok(());
                    }
                    let _ = w.flush().await;
                }

                // If this is the last data packet, shutdown write side and remove the stream
                if data_packet.is_end {
                    debug!("[AGENT->TARGET] End of stream, shutting down write side");
                    let mut w = writer.lock().await;
                    // Shutdown write side to signal end of request to HTTP server
                    let _ = w.shutdown().await;
                    drop(w);
                    self.target_writers.remove(&data_packet.stream_id);
                }
                // Note: We don't send a response here - the reader task handles sending data back
            }
            None => {
                // This can happen if the reader task already closed the connection
                debug!(
                    "No target stream found for stream_id: {} (may already be closed)",
                    data_packet.stream_id
                );
            }
        }

        Ok(())
    }

    async fn handle_heartbeat(&mut self) -> Result<()> {
        debug!("Heartbeat received");
        self.send_response(ProxyResponse::Heartbeat).await?;
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
