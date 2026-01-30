use crate::config::AgentConfig;
use crate::error::{AgentError, Result};
use protocol::{
    crypto::{AesGcmCipher, RsaKeyPair},
    Address, AuthRequest, ConnectRequest, DataPacket, Message, MessageType,
    ProxyCodec, ProxyRequest, ProxyResponse,
};
use futures::{SinkExt, StreamExt, stream::{SplitSink, SplitStream}};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio_util::codec::Framed;
use tracing::{debug, error, info, warn};

type FramedWriter = SplitSink<Framed<TcpStream, ProxyCodec>, Message>;
type FramedReader = SplitStream<Framed<TcpStream, ProxyCodec>>;

/// A multiplexed connection that can handle multiple concurrent streams over a single TCP connection
pub struct MultiplexedConnection {
    /// Channel to send write requests (avoids blocking on writer lock)
    write_tx: mpsc::Sender<Message>,
    aes_cipher: Arc<AesGcmCipher>,
    /// Channel senders for each active stream, keyed by stream_id
    stream_senders: Arc<RwLock<HashMap<String, mpsc::Sender<DataPacket>>>>,
    /// Pending connect responses, keyed by request_id
    pending_connects: Arc<RwLock<HashMap<String, oneshot::Sender<(bool, String)>>>>,
    /// Current stream count for quick access
    stream_count: Arc<AtomicUsize>,
    /// Flag to indicate if the connection is still healthy
    is_healthy: Arc<std::sync::atomic::AtomicBool>,
}

impl MultiplexedConnection {
    pub async fn connect(config: &AgentConfig) -> Result<Self> {
        info!("Creating multiplexed connection to proxy: {}", config.proxy_addr);
        let stream = TcpStream::connect(&config.proxy_addr)
            .await
            .map_err(|e| AgentError::Connection(e.to_string()))?;

        let framed = Framed::new(stream, ProxyCodec::new());
        let (writer, reader) = framed.split();

        // Generate AES key for the session
        let aes_cipher = AesGcmCipher::new();
        let aes_key = aes_cipher.key().clone();

        // Load user's private key to encrypt the AES key
        let private_key_pem = std::fs::read_to_string(&config.private_key_path)
            .map_err(|e| AgentError::Authentication(format!("Failed to read private key: {}", e)))?;

        let rsa_keypair = RsaKeyPair::from_private_key_pem(&private_key_pem)?;
        let encrypted_aes_key = rsa_keypair.encrypt_with_private_key(&aes_key)?;

        let aes_cipher = Arc::new(aes_cipher);
        let stream_senders: Arc<RwLock<HashMap<String, mpsc::Sender<DataPacket>>>> = 
            Arc::new(RwLock::new(HashMap::new()));
        let pending_connects: Arc<RwLock<HashMap<String, oneshot::Sender<(bool, String)>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let stream_count = Arc::new(AtomicUsize::new(0));
        let is_healthy = Arc::new(std::sync::atomic::AtomicBool::new(true));

        // Create write channel for non-blocking writes
        let (write_tx, write_rx) = mpsc::channel::<Message>(1024);

        // Spawn writer task
        Self::spawn_writer_task(writer, write_rx, is_healthy.clone());

        // Send auth request
        Self::do_authenticate(&write_tx, config.username.clone(), encrypted_aes_key).await?;

        // Spawn reader task
        Self::spawn_reader_task(
            reader,
            aes_cipher.clone(),
            stream_senders.clone(),
            pending_connects.clone(),
            is_healthy.clone(),
        );

        Ok(Self {
            write_tx,
            aes_cipher,
            stream_senders,
            pending_connects,
            stream_count,
            is_healthy,
        })
    }

    fn spawn_writer_task(
        mut writer: FramedWriter,
        mut write_rx: mpsc::Receiver<Message>,
        is_healthy: Arc<std::sync::atomic::AtomicBool>,
    ) {
        tokio::spawn(async move {
            while let Some(msg) = write_rx.recv().await {
                if let Err(e) = writer.send(msg).await {
                    error!("Writer task error: {}", e);
                    is_healthy.store(false, Ordering::SeqCst);
                    break;
                }
            }
            info!("Writer task ended");
            is_healthy.store(false, Ordering::SeqCst);
        });
    }

    async fn do_authenticate(
        write_tx: &mpsc::Sender<Message>,
        username: String,
        encrypted_aes_key: Vec<u8>,
    ) -> Result<()> {
        info!("Authenticating with proxy as user: {}", username);

        let auth_request = AuthRequest {
            username,
            timestamp: common::current_timestamp(),
            encrypted_aes_key,
        };

        let payload = serde_json::to_vec(&ProxyRequest::Auth(auth_request))
            .map_err(|e| AgentError::Protocol(protocol::ProtocolError::Serialization(e)))?;

        let message = Message::new(MessageType::AuthRequest, payload);

        write_tx.send(message).await.map_err(|e| {
            AgentError::Connection(format!("Failed to send auth request: {}", e))
        })?;

        info!("Authentication request sent");
        Ok(())
    }

    fn spawn_reader_task(
        mut reader: FramedReader,
        aes_cipher: Arc<AesGcmCipher>,
        stream_senders: Arc<RwLock<HashMap<String, mpsc::Sender<DataPacket>>>>,
        pending_connects: Arc<RwLock<HashMap<String, oneshot::Sender<(bool, String)>>>>,
        is_healthy: Arc<std::sync::atomic::AtomicBool>,
    ) {
        tokio::spawn(async move {
            while let Some(result) = reader.next().await {
                let msg = match result {
                    Ok(msg) => msg,
                    Err(e) => {
                        error!("Reader task error: {}", e);
                        is_healthy.store(false, Ordering::SeqCst);
                        break;
                    }
                };

                // Check if this is an unencrypted auth response
                if msg.message_type == MessageType::AuthResponse {
                    if let Ok(response) = serde_json::from_slice::<ProxyResponse>(&msg.payload) {
                        match response {
                            ProxyResponse::Auth(auth_response) => {
                                if auth_response.success {
                                    info!("Authentication successful");
                                } else {
                                    error!("Authentication failed: {}", auth_response.message);
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    continue;
                }

                // Decrypt payload for other messages
                let decrypted_payload = match aes_cipher.decrypt(&msg.payload) {
                    Ok(p) => p,
                    Err(e) => {
                        error!("Failed to decrypt message: {}", e);
                        continue;
                    }
                };

                let response: ProxyResponse = match serde_json::from_slice(&decrypted_payload) {
                    Ok(r) => r,
                    Err(e) => {
                        error!("Failed to deserialize response: {}", e);
                        continue;
                    }
                };

                match response {
                    ProxyResponse::Connect(connect_response) => {
                        debug!("Received connect response for request_id: {}", connect_response.request_id);
                        // Use oneshot channel for the specific request
                        let mut pending = pending_connects.write().await;
                        if let Some(tx) = pending.remove(&connect_response.request_id) {
                            let _ = tx.send((connect_response.success, connect_response.message));
                        } else {
                            warn!("No pending connect for request_id: {}", connect_response.request_id);
                        }
                    }
                    ProxyResponse::Data(data_packet) => {
                        debug!("Received data packet for stream_id: {}, size: {}", 
                            data_packet.stream_id, data_packet.data.len());
                        
                        let is_end = data_packet.is_end;
                        let stream_id = data_packet.stream_id.clone();

                        // Get sender without holding lock across send
                        let sender = {
                            let senders = stream_senders.read().await;
                            senders.get(&stream_id).cloned()
                        };

                        if let Some(sender) = sender {
                            if sender.send(data_packet).await.is_err() {
                                warn!("Failed to send data to stream handler, removing stream: {}", stream_id);
                                stream_senders.write().await.remove(&stream_id);
                                // Note: don't decrement stream_count here - StreamReceiver Drop will handle it
                            }
                        } else {
                            warn!("No handler for stream_id: {}", stream_id);
                        }

                        // Note: We don't cleanup here anymore - the StreamReceiver will handle cleanup
                        // when it's dropped or when is_end is received
                        if is_end {
                            debug!("Stream ended signal received: {}", stream_id);
                        }
                    }
                    ProxyResponse::Heartbeat => {
                        debug!("Received heartbeat response");
                    }
                    _ => {
                        warn!("Unexpected response type");
                    }
                }
            }
            
            info!("Reader task ended");
            is_healthy.store(false, Ordering::SeqCst);
        });
    }

    /// Connect to a target and return a Stream handle for sending/receiving data
    pub async fn connect_target(&self, address: Address) -> Result<StreamHandle> {
        // Check if connection is still healthy before trying to use it
        if !self.is_healthy() {
            return Err(AgentError::Connection("Connection is no longer healthy".to_string()));
        }

        let stream_id = common::generate_id();
        
        // Create channel for this stream's data
        let (data_tx, data_rx) = mpsc::channel(1024);

        // Create oneshot channel for connect response
        let (connect_tx, connect_rx) = oneshot::channel();

        // Register pending connect and stream sender
        {
            self.pending_connects.write().await.insert(stream_id.clone(), connect_tx);
            self.stream_senders.write().await.insert(stream_id.clone(), data_tx);
            self.stream_count.fetch_add(1, Ordering::Relaxed);
        }

        // Send connect request
        let connect_request = ConnectRequest {
            request_id: stream_id.clone(),
            address: address.clone(),
        };

        let payload = serde_json::to_vec(&ProxyRequest::Connect(connect_request))
            .map_err(|e| AgentError::Protocol(protocol::ProtocolError::Serialization(e)))?;

        let encrypted_payload = self.aes_cipher.encrypt(&payload)?;
        let message = Message::new(MessageType::ConnectRequest, encrypted_payload);

        self.write_tx.send(message).await.map_err(|e| {
            AgentError::Connection(format!("Failed to send connect request: {}", e))
        })?;

        debug!("Sent connect request for stream_id: {}, address: {:?}", stream_id, address);

        // Wait for connect response with timeout
        let (success, message) = match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            connect_rx,
        ).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(_)) => {
                self.cleanup_stream(&stream_id).await;
                return Err(AgentError::Connection("Connect cancelled".to_string()));
            }
            Err(_) => {
                self.cleanup_stream(&stream_id).await;
                return Err(AgentError::Connection("Connect timeout".to_string()));
            }
        };

        if !success {
            self.cleanup_stream(&stream_id).await;
            return Err(AgentError::Connection(message));
        }

        info!("Stream connected: {}", stream_id);

        Ok(StreamHandle {
            stream_id,
            write_tx: self.write_tx.clone(),
            aes_cipher: self.aes_cipher.clone(),
            receiver: data_rx,
            stream_senders: self.stream_senders.clone(),
            stream_count: self.stream_count.clone(),
        })
    }

    async fn cleanup_stream(&self, stream_id: &str) {
        self.pending_connects.write().await.remove(stream_id);
        self.stream_senders.write().await.remove(stream_id);
        self.stream_count.fetch_sub(1, Ordering::Relaxed);
    }

    /// Get current stream count for this connection
    pub fn stream_count(&self) -> usize {
        self.stream_count.load(Ordering::Relaxed)
    }

    /// Check if the connection is still healthy
    pub fn is_healthy(&self) -> bool {
        self.is_healthy.load(Ordering::SeqCst)
    }
}

/// Handle for a single stream within a multiplexed connection
/// Can be split into sender and receiver for concurrent use
pub struct StreamHandle {
    stream_id: String,
    write_tx: mpsc::Sender<Message>,
    aes_cipher: Arc<AesGcmCipher>,
    receiver: mpsc::Receiver<DataPacket>,
    stream_senders: Arc<RwLock<HashMap<String, mpsc::Sender<DataPacket>>>>,
    stream_count: Arc<AtomicUsize>,
}

impl StreamHandle {
    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }

    /// Split the handle into separate sender and receiver for concurrent use
    pub fn split(self) -> (StreamSender, StreamReceiver) {
        let sender = StreamSender {
            stream_id: self.stream_id.clone(),
            write_tx: self.write_tx,
            aes_cipher: self.aes_cipher,
        };
        let receiver = StreamReceiver {
            stream_id: self.stream_id,
            receiver: self.receiver,
            stream_senders: self.stream_senders,
            stream_count: self.stream_count,
            cleaned_up: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        (sender, receiver)
    }
}

/// Sender half of a stream handle - can send data to proxy
#[derive(Clone)]
pub struct StreamSender {
    stream_id: String,
    write_tx: mpsc::Sender<Message>,
    aes_cipher: Arc<AesGcmCipher>,
}

impl StreamSender {
    pub async fn send_data(&self, data: Vec<u8>, is_end: bool) -> Result<()> {
        let data_packet = DataPacket {
            stream_id: self.stream_id.clone(),
            data,
            is_end,
        };

        let payload = serde_json::to_vec(&ProxyRequest::Data(data_packet))
            .map_err(|e| AgentError::Protocol(protocol::ProtocolError::Serialization(e)))?;

        let encrypted_payload = self.aes_cipher.encrypt(&payload)?;
        let message = Message::new(MessageType::Data, encrypted_payload);

        self.write_tx.send(message).await.map_err(|e| {
            AgentError::Protocol(protocol::ProtocolError::Io(
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.to_string())
            ))
        })?;

        Ok(())
    }
}

/// Receiver half of a stream handle - receives data from proxy
pub struct StreamReceiver {
    stream_id: String,
    receiver: mpsc::Receiver<DataPacket>,
    stream_senders: Arc<RwLock<HashMap<String, mpsc::Sender<DataPacket>>>>,
    stream_count: Arc<AtomicUsize>,
    /// Flag to indicate if we've already decremented the stream count
    cleaned_up: Arc<std::sync::atomic::AtomicBool>,
}

impl StreamReceiver {
    pub async fn receive_data(&mut self) -> Option<DataPacket> {
        self.receiver.recv().await
    }

    /// Clean up this stream - call this when done to ensure proper cleanup
    #[allow(dead_code)]
    pub async fn cleanup(&mut self) {
        // Use compare_exchange to ensure we only cleanup once
        if self.cleaned_up.compare_exchange(
            false,
            true,
            Ordering::SeqCst,
            Ordering::SeqCst
        ).is_ok() {
            self.stream_senders.write().await.remove(&self.stream_id);
            self.stream_count.fetch_sub(1, Ordering::Relaxed);
            debug!("Stream receiver cleaned up: {}", self.stream_id);
        }
    }
}

impl Drop for StreamReceiver {
    fn drop(&mut self) {
        // Only cleanup if not already done
        // Use compare_exchange to ensure we only cleanup once
        if self.cleaned_up.compare_exchange(
            false,
            true,
            Ordering::SeqCst,
            Ordering::SeqCst
        ).is_ok() {
            let stream_id = self.stream_id.clone();
            let stream_senders = self.stream_senders.clone();
            let stream_count = self.stream_count.clone();
            tokio::spawn(async move {
                stream_senders.write().await.remove(&stream_id);
                stream_count.fetch_sub(1, Ordering::Relaxed);
                debug!("Stream receiver dropped: {}", stream_id);
            });
        }
    }
}

/// Connection pool that manages multiplexed connections
pub struct MultiplexedPool {
    connections: RwLock<Vec<Arc<MultiplexedConnection>>>,
    config: Arc<AgentConfig>,
    max_streams_per_conn: usize,
}

impl MultiplexedPool {
    pub fn new(config: Arc<AgentConfig>) -> Self {
        Self {
            connections: RwLock::new(Vec::new()),
            config,
            max_streams_per_conn: 100, // Max streams per connection
        }
    }

    /// Remove dead connections from the pool
    async fn cleanup_dead_connections(&self) {
        let mut connections = self.connections.write().await;
        let before_len = connections.len();
        connections.retain(|conn| conn.is_healthy());
        let after_len = connections.len();
        if before_len != after_len {
            info!("Cleaned up {} dead connections from pool", before_len - after_len);
        }
    }

    pub async fn get_stream(&self, address: Address) -> Result<StreamHandle> {
        // First, cleanup any dead connections
        self.cleanup_dead_connections().await;

        // Try to find an existing healthy connection with capacity
        {
            let connections = self.connections.read().await;
            for conn in connections.iter() {
                // Only use healthy connections
                if conn.is_healthy() && conn.stream_count() < self.max_streams_per_conn {
                    match conn.connect_target(address.clone()).await {
                        Ok(handle) => return Ok(handle),
                        Err(e) => {
                            warn!("Failed to create stream on existing connection: {}", e);
                            continue;
                        }
                    }
                }
            }
        }

        // Need to create a new connection
        info!("Creating new multiplexed connection");
        let new_conn = Arc::new(MultiplexedConnection::connect(&self.config).await?);
        
        // Add small delay for auth response to be processed
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        
        let handle = new_conn.connect_target(address).await?;
        
        {
            let mut connections = self.connections.write().await;
            // Remove dead connections before adding
            connections.retain(|conn| conn.is_healthy());
            if connections.len() < self.config.pool_size {
                connections.push(new_conn);
            }
        }

        Ok(handle)
    }
}
