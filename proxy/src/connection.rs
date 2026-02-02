use crate::bandwidth::BandwidthMonitor;
use crate::config::UserConfig;
use crate::error::{ProxyError, Result};
use futures::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use protocol::{
    Address, AuthRequest, AuthResponse, ConnectRequest, ConnectResponse, DataPacket, ProxyRequest,
    ProxyResponse, ServerCodec,
    crypto::{AesGcmCipher, RsaKeyPair},
    CipherState,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_util::codec::Framed;
use tokio_util::io::{SinkWriter, StreamReader};
use tokio_util::sync::PollSender;
use tracing::{debug, error, info};
use std::pin::Pin;
use std::task::{Context, Poll};
use futures::{Sink, Stream};
use bytes::Bytes;

type FramedWriter = SplitSink<Framed<TcpStream, ServerCodec>, ProxyResponse>;
type FramedReader = SplitStream<Framed<TcpStream, ServerCodec>>;

/// Context for the bidirectional relay task containing shared resources
struct RelayContext {
    stream_id: String,
    write_tx: mpsc::Sender<ProxyResponse>,
    bandwidth_monitor: Arc<BandwidthMonitor>,
    username: Option<String>,
}

impl RelayContext {
    /// Send a data packet to the agent
    async fn send_data_packet(&self, data_packet: DataPacket) -> Result<()> {
        // Encryption and serialization is handled by the codec
        self.write_tx
            .send(ProxyResponse::Data(data_packet))
            .await
            .map_err(|e| ProxyError::Connection(format!("Failed to send data packet: {}", e)))?;

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
    write_tx: mpsc::Sender<ProxyResponse>,
    reader: FramedReader,
    user_config: Option<UserConfig>,
    bandwidth_monitor: Arc<BandwidthMonitor>,
    cipher_state: Arc<CipherState>,
    // Store channels for sending data to target streams (for bidirectional copy)
    target_senders: HashMap<String, mpsc::Sender<Vec<u8>>>,
    // Store shutdown senders to signal end of stream
    target_shutdown: HashMap<String, mpsc::Sender<()>>,
    pending_auth_request: Option<AuthRequest>,
}

impl ProxyConnection {
    pub fn new(stream: TcpStream, bandwidth_monitor: Arc<BandwidthMonitor>) -> Self {
        let cipher_state = Arc::new(CipherState::new());
        let framed = Framed::new(stream, ServerCodec::new(Some(cipher_state.clone())));
        let (writer, reader) = framed.split();

        // Spawn write loop
        let (write_tx, write_rx) = mpsc::channel(32);
        tokio::spawn(Self::write_loop(writer, write_rx));

        Self {
            write_tx,
            reader,
            user_config: None,
            bandwidth_monitor,
            cipher_state,
            target_senders: HashMap::new(),
            target_shutdown: HashMap::new(),
            pending_auth_request: None,
        }
    }

    async fn write_loop(mut writer: FramedWriter, mut rx: mpsc::Receiver<ProxyResponse>) {
        while let Some(response) = rx.recv().await {
            if let Err(e) = writer.send(response).await {
                error!("Failed to write response to socket: {}", e);
                break;
            }
        }
    }

    async fn send_response_internal(&self, response: ProxyResponse) -> Result<()> {
        self.write_tx
            .send(response)
            .await
            .map_err(|e| ProxyError::Connection(format!("Failed to send response: {}", e)))?;
        Ok(())
    }

    /// Send an encrypted data packet to the agent
    async fn send_encrypted_data_packet(&self, data_packet: DataPacket) -> Result<()> {
        if self.user_config.is_none() {
            return Err(ProxyError::Authentication("Not authenticated".to_string()));
        }

        // Encryption and serialization is handled by the codec
        self.send_response_internal(ProxyResponse::Data(data_packet)).await
    }

    async fn read_request(&mut self) -> Result<Option<ProxyRequest>> {
        match self.reader.next().await {
            Some(Ok(req)) => Ok(Some(req)),
            Some(Err(e)) => Err(ProxyError::Protocol(protocol::ProtocolError::Io(e))),
            None => Ok(None), // Connection closed
        }
    }

    /// Peek at the auth request to get the username without completing authentication
    pub async fn peek_auth_username(&mut self) -> Result<String> {
        // Receive auth request
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
    pub async fn send_auth_error(&mut self, message: &str) -> Result<()> {
        let auth_response = AuthResponse {
            success: false,
            message: message.to_string(),
            session_id: None,
        };

        self.send_response_internal(ProxyResponse::Auth(auth_response)).await
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

        let payload = serde_json::to_vec(&ProxyResponse::Auth(auth_response.clone()))
            .map_err(|e| ProxyError::Protocol(protocol::ProtocolError::Serialization(e)))?;

        debug!(
            "[AUTH RESPONSE] Sending: success=true, session_id={:?}, payload_hex={}",
            auth_response.session_id,
            hex::encode(&payload)
        );

        self.send_response_internal(ProxyResponse::Auth(auth_response)).await?;

        self.user_config = Some(user_config);

        // Update cipher state for future messages
        self.cipher_state.set_cipher(Arc::new(aes_cipher));

        info!("Authentication successful");
        Ok(())
    }

    pub async fn handle_request(&mut self) -> Result<bool> {
        // Receive encrypted message (decrypted by codec)
        let request = match self.read_request().await? {
            Some(req) => req,
            None => return Ok(false), // Connection closed
        };

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
                    write_tx: self.write_tx.clone(),
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
        mut target_stream: TcpStream,
        data_rx: mpsc::Receiver<Vec<u8>>,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) {
        let write_tx = ctx.write_tx.clone();

        // Agent write: Send wrapper (implements Sink)
        struct AgentSink {
            tx: PollSender<ProxyResponse>,
            stream_id: String,
        }

        impl Sink<&[u8]> for AgentSink {
            type Error = std::io::Error;

            fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.tx).poll_ready(cx).map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }

            fn start_send(mut self: Pin<&mut Self>, item: &[u8]) -> std::io::Result<()> {
                let packet = DataPacket {
                    stream_id: self.stream_id.clone(),
                    data: item.to_vec(),
                    is_end: false,
                };
                Pin::new(&mut self.tx).start_send(ProxyResponse::Data(packet))
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }

            fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.tx).poll_flush(cx).map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }

            fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
                let packet = DataPacket {
                    stream_id: self.stream_id.clone(),
                    data: vec![],
                    is_end: true,
                };
                // Try to send close packet, but ignore errors if pipe broken
                let _ = Pin::new(&mut self.tx).start_send(ProxyResponse::Data(packet));
                Pin::new(&mut self.tx).poll_close(cx).map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
        }

        // Agent read: Receiver wrapper
        struct AgentSource {
            rx: mpsc::Receiver<Vec<u8>>,
        }

        impl Stream for AgentSource {
            type Item = std::io::Result<Bytes>;

            fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
                match self.rx.poll_recv(cx) {
                    Poll::Ready(Some(data)) if !data.is_empty() => {
                        Poll::Ready(Some(Ok(Bytes::from(data))))
                    },
                    Poll::Ready(Some(_)) => Poll::Ready(None), // Empty data signals EOF
                    Poll::Ready(None) => Poll::Ready(None),
                    Poll::Pending => Poll::Pending,
                }
            }
        }

        // Combine into AsyncRead + AsyncWrite
        let agent_sink = AgentSink {
            tx: PollSender::new(write_tx),
            stream_id: ctx.stream_id.clone(),
        };
        let agent_writer = SinkWriter::new(agent_sink);

        let agent_source = AgentSource {
            rx: data_rx,
        };
        let agent_reader = StreamReader::new(agent_source);

        // We need to implement a combined IO object or wrap separate writer/reader
        // Since copy_bidirectional takes AsyncRead + AsyncWrite, we use tokio::io::join? No, that's for futures.
        // We can use helper struct that composes reader and writer.

        struct AgentIo<R, W> {
            reader: R,
            writer: W,
        }

        impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncRead for AgentIo<R, W> {
            fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.reader).poll_read(cx, buf)
            }
        }

        impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncWrite for AgentIo<R, W> {
            fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
                Pin::new(&mut self.writer).poll_write(cx, buf)
            }

            fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.writer).poll_flush(cx)
            }

            fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.writer).poll_shutdown(cx)
            }
        }

        let mut agent_io = AgentIo {
            reader: agent_reader,
            writer: agent_writer,
        };

        // Also handling shutdown_rx via select?
        // copy_bidirectional finishes when one side closes.
        // But shutdown_rx can come from outside (client disconnects forcefully).
        // Since we are now using copy_bidirectional, we block on it.
        // We can run copy_bidirectional in a select with shutdown_rx.

        tokio::select! {
            res = tokio::io::copy_bidirectional(&mut target_stream, &mut agent_io) => {
                match res {
                    Ok((target_to_agent, agent_to_target)) => {
                        debug!("Relay finished: {} up, {} down", agent_to_target, target_to_agent);
                        // Record bandwidth for the final flush
                        if let Some(ref user) = ctx.username {
                            // target_to_agent bytes were sent to agent
                            ctx.bandwidth_monitor.record_sent(user, target_to_agent as u64);
                            // bandwidth checks are done during transfer inside codec? NO.
                            // Previously bandwidth checks were inside loop.
                            // With copy_bidirectional, we lose per-chunk access unless we wrap streams.
                            // We can wrap AgentSink to record bandwidth!
                        }
                    }
                    Err(e) => {
                        debug!("Relay error: {}", e);
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                debug!("Relay shutdown signaled");
            }
        }

        // Ensure EOF sent
        ctx.send_end_packet().await;
        debug!("[RELAY] Relay task ended for stream: {}", ctx.stream_id);
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
        // Calculate payload length for bandwidth monitoring
        // This causes double serialization but ensures accuracy for billing/limits
        let payload_len = serde_json::to_vec(&response)
             .map_err(|e| ProxyError::Protocol(protocol::ProtocolError::Serialization(e)))?
             .len();

        // Use codec to encode message with length-delimited framing
        self.send_response_internal(response).await?;

        debug!("[RESPONSE] Message sent successfully");

        // Record bandwidth usage
        if let Some(user_config) = &self.user_config {
            self.bandwidth_monitor
                .record_sent(&user_config.username, payload_len as u64);
        }

        Ok(())
    }
}
