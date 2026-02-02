use crate::config::AgentConfig;
use crate::error::{AgentError, Result};
use bytes::Bytes;
use deadpool::unmanaged::Pool;
use futures::{
    Sink, SinkExt, Stream, StreamExt,
    stream::{SplitSink, SplitStream},
};
use protocol::{
    Address, AgentCodec, AuthRequest, ConnectRequest, DataPacket, ProxyRequest, ProxyResponse,
    crypto::{AesGcmCipher, RsaKeyPair},
    CipherState,
};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio_util::codec::Framed;
use tokio_util::io::{SinkWriter, StreamReader};
use tracing::{debug, info, warn};

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
    pub async fn connect_target(mut self, address: Address) -> Result<ConnectedStream> {
        let request_id = common::generate_id();

        let connect_request = ConnectRequest {
            request_id: request_id.clone(),
            address: address.clone(),
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

        Ok(ConnectedStream {
            writer: self.writer,
            reader: self.reader,
            stream_id: request_id,
        })
    }
}

/// A connected stream to a target through the proxy
/// This handles bidirectional data transfer
pub struct ConnectedStream {
    writer: FramedWriter,
    reader: FramedReader,
    stream_id: String,
}

impl ConnectedStream {
    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }

    /// Convert to an AsyncRead + AsyncWrite compatible stream for use with copy_bidirectional
    pub fn into_async_io(self) -> ProxyStreamIo {
        ProxyStreamIo::new(self.writer, self.reader, self.stream_id)
    }
}

/// A stream adapter that extracts data from proxy protocol messages
/// This implements Stream<Item = Result<Bytes, io::Error>> for use with StreamReader
pub struct ResponseStream {
    reader: FramedReader,
    stream_id: String,
}

impl ResponseStream {
    pub fn new(reader: FramedReader, stream_id: String) -> Self {
        Self {
            reader,
            stream_id,
        }
    }
}

impl Stream for ResponseStream {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            let reader = Pin::new(&mut self.reader);
            match reader.poll_next(cx) {
                Poll::Ready(Some(Ok(response))) => {
                    // Response is already deserialized and decrypted by codec
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

/// A sink adapter that wraps data into proxy protocol messages
/// This implements Sink<&[u8], Error = io::Error> for use with SinkWriter
pub struct DataPacketSink {
    writer: FramedWriter,
    stream_id: String,
}

impl DataPacketSink {
    pub fn new(writer: FramedWriter, stream_id: String) -> Self {
        Self {
            writer,
            stream_id,
        }
    }

    fn create_data_request(&self, data: &[u8], is_end: bool) -> ProxyRequest {
        let data_packet = DataPacket {
            stream_id: self.stream_id.clone(),
            data: data.to_vec(),
            is_end,
        };

        ProxyRequest::Data(data_packet)
    }
}

impl<'a> Sink<&'a [u8]> for DataPacketSink {
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
        let request = self.create_data_request(item, false);
        Pin::new(&mut self.writer)
            .start_send(request)
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
        let request = this.create_data_request(&[], true);

        let writer = Pin::new(&mut this.writer);
        match writer.poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                let writer = Pin::new(&mut this.writer);
                writer
                    .start_send(request)
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
    reader: StreamReader<ResponseStream, Bytes>,
    writer: SinkWriter<DataPacketSink>,
}

impl ProxyStreamIo {
    pub fn new(
        framed_writer: FramedWriter,
        framed_reader: FramedReader,
        stream_id: String,
    ) -> Self {
        let response_stream =
            ResponseStream::new(framed_reader, stream_id.clone());
        let data_sink = DataPacketSink::new(framed_writer, stream_id);

        Self {
            reader: StreamReader::new(response_stream),
            writer: SinkWriter::new(data_sink),
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

/// Connection pool using deadpool::unmanaged for prewarming connections
/// Connections are NOT reused - each connection is taken from the pool and consumed
pub struct ConnectionPool {
    /// The unmanaged pool of prewarmed connections
    pool: Pool<ProxyConnection>,
    config: Arc<AgentConfig>,
    /// Notification to request refill
    refill_notify: Arc<Notify>,
    /// Tracks number of available connections in the pool
    available: Arc<AtomicUsize>,
}

impl ConnectionPool {
    pub fn new(config: Arc<AgentConfig>) -> Self {
        let pool_size = config.pool_size;

        // Create unmanaged pool with reasonable capacity (1.5x target size)
        let pool = Pool::new((pool_size as f32 * 1.5) as usize);

        // Create refill notification mechanism instead of channel
        let refill_notify = Arc::new(Notify::new());

        let pool_clone = pool.clone();
        let config_clone = config.clone();
        let available = Arc::new(AtomicUsize::new(0));
        let available_clone = available.clone();
        let refill_notify_clone = refill_notify.clone();

        // Spawn background refill task
        tokio::spawn(async move {
            Self::refill_task(
                refill_notify_clone,
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
            refill_notify,
            available,
        }
    }

    async fn refill_task(
        refill_notify: Arc<Notify>,
        pool: Pool<ProxyConnection>,
        config: Arc<AgentConfig>,
        available: Arc<AtomicUsize>,
        target_size: usize,
    ) {
        loop {
            // Wait for refill request or periodic check
            tokio::select! {
                _ = refill_notify.notified() => {}
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

                // Limit concurrency to avoid overwhelming the system or proxy
                const MAX_CONCURRENT_REFILL: usize = 10;
                let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_REFILL));
                let mut set = tokio::task::JoinSet::new();

                for _ in 0..to_create {
                    let config = config.clone();
                    let semaphore = semaphore.clone();

                    set.spawn(async move {
                        let _permit = semaphore.acquire().await.ok();
                        ProxyConnection::new(&config).await
                    });
                }

                while let Some(res) = set.join_next().await {
                    match res {
                        Ok(Ok(conn)) => {
                            if pool.try_add(conn).is_ok() {
                                available.fetch_add(1, Ordering::Release);
                                debug!("Added prewarmed connection to pool");
                            } else {
                                debug!("Pool is full, stopping refill");
                                // If pool is full, we can discard the rest of the tasks or let them finish and fail to add
                                // We'll let them finish but stop adding if pool is actually full (try_add fails)
                            }
                        }
                        Ok(Err(e)) => {
                            warn!("Failed to create prewarmed connection: {}", e);
                        }
                        Err(e) => {
                            warn!("Refill task join error: {}", e);
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
        // Request refill in background using notify
        self.refill_notify.notify_one();

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
