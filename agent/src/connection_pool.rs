use crate::config::AgentConfig;
use crate::error::{AgentError, Result};
use bytes::Bytes;
use deadpool::unmanaged::Pool;
use futures::{
    Sink, SinkExt, Stream, StreamExt,
    stream::{SplitSink, SplitStream},
};
use protocol::{
    Address, AuthRequest, ConnectRequest, DataPacket, Message, MessageType, ProxyCodec,
    ProxyRequest, ProxyResponse,
    crypto::{AesGcmCipher, RsaKeyPair},
};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_util::codec::Framed;
use tokio_util::io::{SinkWriter, StreamReader};
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

        let payload = serde_json::to_vec(&ProxyRequest::Auth(auth_request))
            .map_err(|e| AgentError::Protocol(protocol::ProtocolError::Serialization(e)))?;

        let message = Message::new(MessageType::AuthRequest, payload);

        debug!("[AUTH] Sending auth request");
        writer
            .send(message)
            .await
            .map_err(|e| AgentError::Connection(format!("Failed to send auth request: {}", e)))?;

        // Wait for auth response with timeout
        let auth_response =
            match tokio::time::timeout(std::time::Duration::from_secs(10), reader.next()).await {
                Ok(Some(Ok(msg))) => msg,
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
                return Err(AgentError::Authentication(
                    "Unexpected auth response".to_string(),
                ));
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
            self.reader.next(),
        )
        .await
        {
            Ok(Some(Ok(msg))) => msg,
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
                return Err(AgentError::Connection(
                    "Unexpected connect response".to_string(),
                ));
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
                writer: self.writer,
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

    /// Convert to an AsyncRead + AsyncWrite compatible stream for use with copy_bidirectional
    pub fn into_async_io(self) -> ProxyStreamIo {
        ProxyStreamIo::new(self.writer, self.reader, self.aes_cipher, self.stream_id)
    }
}

/// A stream adapter that decrypts and extracts data from proxy protocol messages
/// This implements Stream<Item = Result<Bytes, io::Error>> for use with StreamReader
pub struct DecryptingStream {
    reader: FramedReader,
    aes_cipher: Arc<AesGcmCipher>,
    stream_id: String,
}

impl DecryptingStream {
    pub fn new(reader: FramedReader, aes_cipher: Arc<AesGcmCipher>, stream_id: String) -> Self {
        Self {
            reader,
            aes_cipher,
            stream_id,
        }
    }
}

impl Stream for DecryptingStream {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            let reader = Pin::new(&mut self.reader);
            match reader.poll_next(cx) {
                Poll::Ready(Some(Ok(msg))) => {
                    // Decrypt payload
                    let decrypted = match self.aes_cipher.decrypt(&msg.payload) {
                        Ok(d) => d,
                        Err(e) => {
                            return Poll::Ready(Some(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                e.to_string(),
                            ))));
                        }
                    };

                    // Parse response
                    let response: ProxyResponse = match serde_json::from_slice(&decrypted) {
                        Ok(r) => r,
                        Err(e) => {
                            return Poll::Ready(Some(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                e,
                            ))));
                        }
                    };

                    match response {
                        ProxyResponse::Data(packet) => {
                            if packet.stream_id == self.stream_id {
                                if packet.is_end && packet.data.is_empty() {
                                    return Poll::Ready(None);
                                }
                                return Poll::Ready(Some(Ok(Bytes::from(packet.data))));
                            }
                            // Wrong stream, continue polling
                        }
                        _ => {
                            // Ignore other responses, continue polling
                        }
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Some(Err(io::Error::other(e.to_string()))));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(None);
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }
}

/// A sink adapter that encrypts and wraps data into proxy protocol messages
/// This implements Sink<&[u8], Error = io::Error> for use with SinkWriter
pub struct EncryptingSink {
    writer: FramedWriter,
    aes_cipher: Arc<AesGcmCipher>,
    stream_id: String,
}

impl EncryptingSink {
    pub fn new(writer: FramedWriter, aes_cipher: Arc<AesGcmCipher>, stream_id: String) -> Self {
        Self {
            writer,
            aes_cipher,
            stream_id,
        }
    }

    fn create_data_message(&self, data: &[u8], is_end: bool) -> io::Result<Message> {
        let data_packet = DataPacket {
            stream_id: self.stream_id.clone(),
            data: data.to_vec(),
            is_end,
        };

        let payload = serde_json::to_vec(&ProxyRequest::Data(data_packet))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let encrypted_payload = self
            .aes_cipher
            .encrypt(&payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        Ok(Message::new(MessageType::Data, encrypted_payload))
    }
}

impl<'a> Sink<&'a [u8]> for EncryptingSink {
    type Error = io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        Pin::new(&mut self.writer)
            .poll_ready(cx)
            .map_err(|e| io::Error::other(e.to_string()))
    }

    fn start_send(
        mut self: Pin<&mut Self>,
        item: &'a [u8],
    ) -> std::result::Result<(), Self::Error> {
        let message = self.create_data_message(item, false)?;
        Pin::new(&mut self.writer)
            .start_send(message)
            .map_err(|e| io::Error::other(e.to_string()))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        Pin::new(&mut self.writer)
            .poll_flush(cx)
            .map_err(|e| io::Error::other(e.to_string()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        // First, send end-of-stream message
        let this = self.as_mut().get_mut();
        let message = this.create_data_message(&[], true)?;

        let writer = Pin::new(&mut this.writer);
        match writer.poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                let writer = Pin::new(&mut this.writer);
                writer
                    .start_send(message)
                    .map_err(|e| io::Error::other(e.to_string()))?;
            }
            Poll::Ready(Err(e)) => {
                return Poll::Ready(Err(io::Error::other(e.to_string())));
            }
            Poll::Pending => {
                return Poll::Pending;
            }
        }

        // Then close the underlying writer
        Pin::new(&mut self.writer)
            .poll_close(cx)
            .map_err(|e| io::Error::other(e.to_string()))
    }
}

/// A wrapper that implements AsyncRead + AsyncWrite for use with tokio::io::copy_bidirectional
/// This uses SinkWriter and StreamReader from tokio_util for better performance
pub struct ProxyStreamIo {
    reader: StreamReader<DecryptingStream, Bytes>,
    writer: SinkWriter<EncryptingSink>,
}

impl ProxyStreamIo {
    pub fn new(
        framed_writer: FramedWriter,
        framed_reader: FramedReader,
        aes_cipher: Arc<AesGcmCipher>,
        stream_id: String,
    ) -> Self {
        let decrypting_stream =
            DecryptingStream::new(framed_reader, aes_cipher.clone(), stream_id.clone());
        let encrypting_sink = EncryptingSink::new(framed_writer, aes_cipher, stream_id);

        Self {
            reader: StreamReader::new(decrypting_stream),
            writer: SinkWriter::new(encrypting_sink),
        }
    }
}

impl AsyncRead for ProxyStreamIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for ProxyStreamIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

/// Sender half for sending data to proxy
pub struct StreamSender {
    writer: FramedWriter,
    aes_cipher: Arc<AesGcmCipher>,
    stream_id: String,
}

impl StreamSender {
    pub async fn send_data(&mut self, data: Vec<u8>, is_end: bool) -> Result<()> {
        let data_packet = DataPacket {
            stream_id: self.stream_id.clone(),
            data,
            is_end,
        };

        let payload = serde_json::to_vec(&ProxyRequest::Data(data_packet))
            .map_err(|e| AgentError::Protocol(protocol::ProtocolError::Serialization(e)))?;

        let encrypted_payload = self.aes_cipher.encrypt(&payload)?;
        let message = Message::new(MessageType::Data, encrypted_payload);

        match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            self.writer.send(message),
        )
        .await
        {
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
                                warn!(
                                    "Received data for wrong stream: {} vs {}",
                                    packet.stream_id, self.stream_id
                                );
                            }
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

        // Create unmanaged pool with reasonable capacity (1.5x target size)
        let pool = Pool::new((pool_size as f32 * 1.5) as usize);

        // Create refill channel
        let (refill_tx, refill_rx) = mpsc::channel::<()>(pool_size);

        let pool_clone = pool.clone();
        let config_clone = config.clone();
        let available = Arc::new(AtomicUsize::new(0));
        let available_clone = available.clone();

        // Spawn background refill task
        tokio::spawn(async move {
            Self::refill_task(
                refill_rx,
                pool_clone,
                config_clone,
                available_clone,
                pool_size,
            )
            .await;
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
                debug!(
                    "Refilling pool: creating {} connections (current: {})",
                    to_create, current_size
                );

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
        info!(
            "Prewarming connection pool with {} connections",
            self.config.pool_size
        );

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
