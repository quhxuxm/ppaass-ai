use crate::bandwidth::BandwidthMonitor;
use crate::config::UserConfig;
use crate::error::{ProxyError, Result};
use futures::{Sink, SinkExt, StreamExt, stream::{SplitSink, SplitStream}};
use protocol::{
    Address, AuthRequest, AuthResponse, ConnectRequest, ConnectResponse, DataPacket, ProxyRequest,
    ProxyResponse, ServerCodec,
    crypto::{AesGcmCipher, RsaKeyPair},
    CipherState,
};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use tokio_util::io::{SinkWriter, StreamReader};
use tracing::{debug, error, info};
use std::pin::Pin;
use std::task::{Context, Poll};
use bytes::Bytes;
use std::io;

type FramedWriter = SplitSink<Framed<TcpStream, ServerCodec>, ProxyResponse>;
type FramedReader = SplitStream<Framed<TcpStream, ServerCodec>>;

struct BytesToProxyResponseSink<'a> {
    inner: &'a mut FramedWriter,
    stream_id: String,
    username: Option<String>,
    bandwidth_monitor: Arc<BandwidthMonitor>,
}

impl<'a> Sink<&[u8]> for BytesToProxyResponseSink<'a> {
    type Error = std::io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: &[u8]) -> std::result::Result<(), Self::Error> {
        let stream_id = self.stream_id.clone();
        if let Some(user) = &self.username {
            self.bandwidth_monitor.record_sent(user, item.len() as u64);
        }
        let packet = DataPacket {
            stream_id,
            data: item.to_vec(),
            is_end: false,
        };
        Pin::new(&mut self.inner).start_send(ProxyResponse::Data(packet))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

pub struct ProxyConnection {
    writer: FramedWriter,
    reader: FramedReader,
    user_config: Option<UserConfig>,
    bandwidth_monitor: Arc<BandwidthMonitor>,
    cipher_state: Arc<CipherState>,
    pending_auth_request: Option<AuthRequest>,
}

impl ProxyConnection {
    pub fn new(stream: TcpStream, bandwidth_monitor: Arc<BandwidthMonitor>) -> Self {
        let cipher_state = Arc::new(CipherState::new());
        let framed = Framed::new(stream, ServerCodec::new(Some(cipher_state.clone())));
        let (writer, reader) = framed.split();

        Self {
            writer,
            reader,
            user_config: None,
            bandwidth_monitor,
            cipher_state,
            pending_auth_request: None,
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

        self.send_response(ProxyResponse::Auth(auth_response)).await
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

        debug!(
            "[AUTH RESPONSE] Sending: success=true, session_id={:?}",
            auth_response.session_id
        );

        self.send_response(ProxyResponse::Auth(auth_response)).await?;

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

    pub async fn handle_request(&mut self) -> Result<bool> {
        self.process().await
    }

    pub async fn process(&mut self) -> Result<bool> {
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
                            // After relay finishes (connection closed), we return false to close connection
                            return Ok(false);
                        }
                        ProxyRequest::Auth(auth_request) => {
                            debug!("Unexpected Auth request in process loop: {:?}", auth_request.username);
                        }
                        _ => {
                            error!("Unexpected request type before Connect");
                        }
                    }
                }
                Some(Err(e)) => return Err(ProxyError::Protocol(protocol::ProtocolError::Io(e))),
                None => return Ok(false), // Agent connection closed
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
            Ok(mut target_stream) => {
                info!("Connected to target: {}", target_addr);

                let connect_response = ConnectResponse {
                    request_id: connect_request.request_id.clone(),
                    success: true,
                    message: "Connected".to_string(),
                };

                self.send_response(ProxyResponse::Connect(connect_response))
                    .await?;

                // Handover to bidirectional relay
                self.relay(connect_request.request_id, &mut target_stream).await?;
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

    async fn relay(&mut self, stream_id: String, target_stream: &mut TcpStream) -> Result<()> {
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

        // Use StreamExt::filter_map to adapt ProxyRequest -> Bytes
        // Note: We use filter_map without async closure to ensure Unpin
        // Async closures in filter_map return a Future, which might not be Unpin if it captures references.
        // We can use std::future::ready or just strict values if no await is needed.
        let stream = (&mut self.reader).filter_map(move |res| {
            let user = username_stream.as_ref();
            let monitor = &monitor_stream;

            let result = match res {
                Ok(ProxyRequest::Data(packet)) => {
                    if !packet.data.is_empty() {
                        if let Some(u) = user {
                            monitor.record_received(u, packet.data.len() as u64);
                        }
                        Some(io::Result::Ok(Bytes::from(packet.data)))
                    } else {
                        // Empty data or is_end=true: ignore, let TCP FIN handle EOF
                        None
                    }
                },
                Ok(_) => None, // Ignore non-Data packets
                Err(e) => Some(Err(io::Error::other(e))),
            };

            futures::future::ready(result)
        });

        let writer = SinkWriter::new(sink);
        let reader = StreamReader::new(stream);

        // Wrapper to satisfy AsyncRead + AsyncWrite on the generic types
        struct AgentIo<R, W> {
            reader: R,
            writer: W,
        }
        impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncRead for AgentIo<R, W> {
            fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.reader).poll_read(cx, buf)
            }
        }
        impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncWrite for AgentIo<R, W> {
            fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
                // SinkWriter writes bytes. We ideally want to write &[u8] but our Sink adapter expects Vec<u8> now?
                // Wait, if we change the Sink adapter to expect Vec<u8>, SinkWriter needs to feed it Vec<u8>.
                // SinkWriter documentation says it requires Sink<&[u8]>.
                // BUT the error says "implements Sink<&'2 [u8]> for some specific lifetime '2" but needs "for any lifetime '1".
                // This is a Higher-Rank Trait Bound (HRTB) issue.
                // The closure takes `|bytes: &[u8]|`. The compiler infers a specific lifetime.
                // We need it to work for ANY lifetime.

                // Usually this is fixed by hinting the compiler about the argument type.
                // closure argument: `bytes: &[u8]`.
                // The issue might be that `sink.with` creates a type that is bound to the specific lifetime of the closure argument?
                // Or rather, SinkWriter calls start_send with a short-lived reference.

                // Let's try explicitly typing the closure argument as `&[u8]`. I did that.
                // Maybe the problem is `move |bytes: &[u8]|`?

                // Alternative fix: Use `Vec<u8>` in the Sink, but `SinkWriter` writes `&[u8]`.
                // SinkWriter copies data into its internal buffer?
                // SinkWriter implements AsyncWrite. When we write to it, it buffers.
                // When we flush/write, it feeds items to the Sink.
                // SinkWriter feeds `&[u8]` (slice of buffer) to the sink.

                // The error is tricky.
                // "implementation of `futures::Sink` is not general enough"
                // `With<...>` must implement `Sink<&'1 [u8]>` for any lifetime '1.
                // But it implements `Sink<&'2 [u8]>`.

                // This often happens when the closure return type depends on the lifetime of the input.
                // My closure returns `Ready<Result<...>>`. `Ready` owns the result.
                // `Result` contains `ProxyResponse`.
                // `ProxyResponse::Data(packet)`. `Packet` owns `data` (Vec<u8>).
                // `bytes.to_vec()` creates owned data from borrowed input.
                // So the return future does NOT depend on input lifetime.

                // Why does the compiler think it does?
                // `move |bytes: &[u8]|`.

                // Maybe because I am using `&mut self.writer`?
                // No, that's the inner sink.

                // Let's try to remove `move` if possible? No, we capture `stream_id` etc.

                // One workaround for this specific rustc quirk with HRTB and closures in `with` is to force the type inference.
                // Or box the sink? `Box::pin(sink)`?

                // Let's try boxing the sink.
                Pin::new(&mut self.writer).poll_write(cx, buf)
            }
            fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.writer).poll_flush(cx)
            }
            fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.writer).poll_shutdown(cx)
            }
        }

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
