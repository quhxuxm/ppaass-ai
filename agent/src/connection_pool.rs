use crate::config::AgentConfig;
use crate::error::{AgentError, Result};
use deadpool::unmanaged::Pool;
use protocol::{
    crypto::{AesGcmCipher, RsaKeyPair},
    Address, AuthRequest, ConnectRequest, DataPacket,
    Message, MessageType, ProxyCodec, ProxyRequest, ProxyResponse,
};
use futures::{SinkExt, StreamExt, stream::{SplitSink, SplitStream}};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio_util::codec::Framed;
use tracing::{debug, error, info, warn};

type FramedWriter = SplitSink<Framed<TcpStream, ProxyCodec>, Message>;
type FramedReader = SplitStream<Framed<TcpStream, ProxyCodec>>;

/// A single-use authenticated connection to the proxy
/// This connection is used for one request and then discarded
pub struct ProxyConnection {
    writer: FramedWriter,
    reader: FramedReader,
    aes_cipher: Arc<AesGcmCipher>,
}

impl ProxyConnection {
    /// Create a new authenticated connection to the proxy
    pub async fn new(config: &AgentConfig) -> Result<Self> {
        debug!("Creating new connection to proxy: {}", config.proxy_addr);

        let stream = TcpStream::connect(&config.proxy_addr)
            .await
            .map_err(|e| AgentError::Connection(e.to_string()))?;

        let framed = Framed::new(stream, ProxyCodec::new());
        let (mut writer, mut reader) = framed.split();

        // Generate AES key for the session
        let aes_cipher = AesGcmCipher::new();
        let aes_key = aes_cipher.key().clone();

        // Load user's private key to encrypt the AES key
        let private_key_pem = std::fs::read_to_string(&config.private_key_path)
            .map_err(|e| AgentError::Authentication(format!("Failed to read private key: {}", e)))?;

        let rsa_keypair = RsaKeyPair::from_private_key_pem(&private_key_pem)?;
        let encrypted_aes_key = rsa_keypair.encrypt_with_private_key(&aes_key)?;

        // Send auth request
        let auth_request = AuthRequest {
            username: config.username.clone(),
            timestamp: common::current_timestamp(),
            encrypted_aes_key,
        };

        let payload = serde_json::to_vec(&ProxyRequest::Auth(auth_request))
            .map_err(|e| AgentError::Protocol(protocol::ProtocolError::Serialization(e)))?;

        let message = Message::new(MessageType::AuthRequest, payload);

        debug!("[AUTH] Sending auth request");
        writer.send(message).await.map_err(|e| {
            AgentError::Connection(format!("Failed to send auth request: {}", e))
        })?;

        // Wait for auth response with timeout
        let auth_response = match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            reader.next()
        ).await {
            Ok(Some(Ok(msg))) => msg,
            Ok(Some(Err(e))) => {
                return Err(AgentError::Connection(format!("Failed to read auth response: {}", e)));
            }
            Ok(None) => {
                return Err(AgentError::Connection("Connection closed during auth".to_string()));
            }
            Err(_) => {
                return Err(AgentError::Authentication("Auth timeout".to_string()));
            }
        };

        // Parse auth response
        let response: ProxyResponse = serde_json::from_slice(&auth_response.payload)
            .map_err(|e| AgentError::Protocol(protocol::ProtocolError::Serialization(e)))?;

        match response {
            ProxyResponse::Auth(auth_resp) => {
                if !auth_resp.success {
                    return Err(AgentError::Authentication(auth_resp.message));
                }
                info!("Authentication successful");
            }
            _ => {
                return Err(AgentError::Authentication("Unexpected auth response".to_string()));
            }
        }

        Ok(Self {
            writer,
            reader,
            aes_cipher: Arc::new(aes_cipher),
        })
    }

    /// Connect to a target address and return a bidirectional stream handle
    pub async fn connect_target(mut self, address: Address) -> Result<ConnectedStream> {
        let request_id = common::generate_id();

        let connect_request = ConnectRequest {
            request_id: request_id.clone(),
            address: address.clone(),
        };

        let payload = serde_json::to_vec(&ProxyRequest::Connect(connect_request))
            .map_err(|e| AgentError::Protocol(protocol::ProtocolError::Serialization(e)))?;

        let encrypted_payload = self.aes_cipher.encrypt(&payload)?;
        let message = Message::new(MessageType::ConnectRequest, encrypted_payload);

        debug!("[CONNECT] Sending connect request for {:?}", address);
        self.writer.send(message).await.map_err(|e| {
            AgentError::Connection(format!("Failed to send connect request: {}", e))
        })?;

        // Wait for connect response with timeout
        let connect_response = match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            self.reader.next()
        ).await {
            Ok(Some(Ok(msg))) => msg,
            Ok(Some(Err(e))) => {
                return Err(AgentError::Connection(format!("Failed to read connect response: {}", e)));
            }
            Ok(None) => {
                return Err(AgentError::Connection("Connection closed during connect".to_string()));
            }
            Err(_) => {
                return Err(AgentError::Connection("Connect timeout".to_string()));
            }
        };

        // Decrypt and parse connect response
        let decrypted = self.aes_cipher.decrypt(&connect_response.payload)?;
        let response: ProxyResponse = serde_json::from_slice(&decrypted)
            .map_err(|e| AgentError::Protocol(protocol::ProtocolError::Serialization(e)))?;

        match response {
            ProxyResponse::Connect(connect_resp) => {
                if !connect_resp.success {
                    return Err(AgentError::Connection(connect_resp.message));
                }
                info!("Connected to target: {:?}", address);
            }
            _ => {
                return Err(AgentError::Connection("Unexpected connect response".to_string()));
            }
        }

        Ok(ConnectedStream {
            writer: self.writer,
            reader: self.reader,
            aes_cipher: self.aes_cipher,
            stream_id: request_id,
        })
    }
}

/// A connected stream to a target through the proxy
/// This handles bidirectional data transfer
pub struct ConnectedStream {
    writer: FramedWriter,
    reader: FramedReader,
    aes_cipher: Arc<AesGcmCipher>,
    stream_id: String,
}

impl ConnectedStream {
    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }

    /// Split into sender and receiver for concurrent bidirectional communication
    pub fn split(self) -> (StreamSender, StreamReceiver) {
        (
            StreamSender {
                writer: Arc::new(Mutex::new(self.writer)),
                aes_cipher: self.aes_cipher.clone(),
                stream_id: self.stream_id.clone(),
            },
            StreamReceiver {
                reader: self.reader,
                aes_cipher: self.aes_cipher,
                stream_id: self.stream_id,
            },
        )
    }
}

/// Sender half for sending data to proxy
pub struct StreamSender {
    writer: Arc<Mutex<FramedWriter>>,
    aes_cipher: Arc<AesGcmCipher>,
    stream_id: String,
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

        let mut writer = self.writer.lock().await;

        match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            writer.send(message)
        ).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(AgentError::Protocol(protocol::ProtocolError::Io(e))),
            Err(_) => Err(AgentError::Connection("Send timeout".to_string())),
        }
    }
}

/// Receiver half for receiving data from proxy
pub struct StreamReceiver {
    reader: FramedReader,
    aes_cipher: Arc<AesGcmCipher>,
    stream_id: String,
}

impl StreamReceiver {
    pub async fn receive_data(&mut self) -> Option<DataPacket> {
        loop {
            match self.reader.next().await {
                Some(Ok(msg)) => {
                    // Decrypt payload
                    let decrypted = match self.aes_cipher.decrypt(&msg.payload) {
                        Ok(d) => d,
                        Err(e) => {
                            error!("Failed to decrypt message: {}", e);
                            return None;
                        }
                    };

                    // Parse response
                    let response: ProxyResponse = match serde_json::from_slice(&decrypted) {
                        Ok(r) => r,
                        Err(e) => {
                            error!("Failed to parse response: {}", e);
                            return None;
                        }
                    };

                    match response {
                        ProxyResponse::Data(packet) => {
                            if packet.stream_id == self.stream_id {
                                return Some(packet);
                            } else {
                                warn!("Received data for wrong stream: {} vs {}", packet.stream_id, self.stream_id);
                            }
                        }
                        ProxyResponse::Heartbeat => {
                            debug!("Received heartbeat");
                            continue;
                        }
                        _ => {
                            warn!("Unexpected response type");
                            continue;
                        }
                    }
                }
                Some(Err(e)) => {
                    error!("Failed to read from proxy: {}", e);
                    return None;
                }
                None => {
                    debug!("Proxy connection closed");
                    return None;
                }
            }
        }
    }
}

/// Connection pool using deadpool::unmanaged for prewarming connections
/// Connections are NOT reused - each connection is taken from the pool and consumed
pub struct ConnectionPool {
    /// The unmanaged pool of prewarmed connections
    pool: Pool<ProxyConnection>,
    config: Arc<AgentConfig>,
    /// Channel to request refill
    refill_tx: mpsc::Sender<()>,
    /// Tracks number of available connections in the pool
    available: Arc<AtomicUsize>,
}

impl ConnectionPool {
    pub fn new(config: Arc<AgentConfig>) -> Self {
        let pool_size = config.pool_size;

        // Create unmanaged pool with specified size
        let pool = Pool::new(pool_size * 2);

        // Create refill channel
        let (refill_tx, refill_rx) = mpsc::channel::<()>(pool_size);

        let pool_clone = pool.clone();
        let config_clone = config.clone();
        let available = Arc::new(AtomicUsize::new(0));
        let available_clone = available.clone();

        // Spawn background refill task
        tokio::spawn(async move {
            Self::refill_task(refill_rx, pool_clone, config_clone, available_clone, pool_size).await;
        });

        Self {
            pool,
            config,
            refill_tx,
            available,
        }
    }

    async fn refill_task(
        mut refill_rx: mpsc::Receiver<()>,
        pool: Pool<ProxyConnection>,
        config: Arc<AgentConfig>,
        available: Arc<AtomicUsize>,
        target_size: usize,
    ) {
        loop {
            // Wait for refill request or periodic check
            tokio::select! {
                _ = refill_rx.recv() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
            }

            // Check current pool size
            let current_size = available.load(Ordering::Acquire);

            // Refill if below target
            if current_size < target_size {
                let to_create = target_size - current_size;
                debug!("Refilling pool: creating {} connections (current: {})", to_create, current_size);

                for _ in 0..to_create {
                    match ProxyConnection::new(&config).await {
                        Ok(conn) => {
                            if pool.try_add(conn).is_ok() {
                                available.fetch_add(1, Ordering::Release);
                                debug!("Added prewarmed connection to pool");
                            } else {
                                debug!("Pool is full, stopping refill");
                                break;
                            }
                        }
                        Err(e) => {
                            warn!("Failed to create prewarmed connection: {}", e);
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    }
                }
            }
        }
    }

    /// Prewarm the pool with initial connections
    pub async fn prewarm(&self) {
        info!("Prewarming connection pool with {} connections", self.config.pool_size);

        // Create connections concurrently
        let mut handles = Vec::with_capacity(self.config.pool_size);

        for i in 0..self.config.pool_size {
            let config = self.config.clone();
            let pool = self.pool.clone();
            let available = self.available.clone();
            handles.push(tokio::spawn(async move {
                match ProxyConnection::new(&config).await {
                    Ok(conn) => {
                        if pool.try_add(conn).is_ok() {
                            available.fetch_add(1, Ordering::Release);
                            debug!("Prewarmed connection {}", i + 1);
                            true
                        } else {
                            debug!("Pool full during prewarm");
                            false
                        }
                    }
                    Err(e) => {
                        warn!("Failed to prewarm connection {}: {}", i + 1, e);
                        false
                    }
                }
            }));
        }

        let mut success_count = 0;
        for handle in handles {
            if let Ok(true) = handle.await {
                success_count += 1;
            }
        }

        info!("Pool prewarmed with {} connections", success_count);
    }

    /// Get a connection and connect to target
    /// The connection is consumed (not returned to pool)
    pub async fn get_connected_stream(&self, address: Address) -> Result<ConnectedStream> {
        // Request refill in background
        let _ = self.refill_tx.try_send(());

        // Try to get a prewarmed connection from the pool
        let conn = match self.pool.try_remove() {
            Ok(conn) => {
                self.available.fetch_sub(1, Ordering::AcqRel);
                debug!("Using prewarmed connection from pool");
                conn
            }
            Err(_) => {
                debug!("No prewarmed connection available, creating new one");
                ProxyConnection::new(&self.config).await?
            }
        };

        // Connect to target (consumes the connection)
        conn.connect_target(address).await
    }
}
