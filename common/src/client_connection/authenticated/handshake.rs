use std::sync::Arc;
use std::time::Duration;

use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use protocol::tcp_transport::{
    TCP_AUTH_CONNECT_RESPONSE_OAEP_LABEL, TCP_AUTH_NONCE_LEN, TCP_HANDSHAKE_VERSION,
    TCP_MASTER_SECRET_LEN, TcpSessionCipher, TcpSessionRole, tcp_auth_connect_request_transcript,
    tcp_auth_connect_transcript_hash,
};
use protocol::{
    Address, AgentCodec, AuthConnectIntent, AuthConnectRequest, CipherState, ConnectRequest,
    ProxyRequest, ProxyResponse, SpeedTestRequest, TransportProtocol,
};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use tracing::{debug, info};

use super::status::{
    AuthenticationFailure, VerifiedAuthAttempt, publish_verified_active_status,
    publish_verified_failure_status,
};
use crate::client_connection::config::ClientConnectionConfig;
use crate::client_connection::stream::ClientStream;
use crate::client_connection::yamux::YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE;

type FramedWriter<S> = SplitSink<Framed<S, AgentCodec>, ProxyRequest>;
type FramedReader<S> = SplitStream<Framed<S, AgentCodec>>;

/// Authenticated PPAASS stream after its initial AuthConnect operation.
pub struct AuthenticatedConnection<S = TcpStream>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    writer: FramedWriter<S>,
    reader: FramedReader<S>,
    timeout: Duration,
}

impl<S> AuthenticatedConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    async fn establish<C>(
        stream: S,
        config: &C,
        intent: AuthConnectIntent,
    ) -> Result<Self, std::io::Error>
    where
        C: ClientConnectionConfig,
    {
        let username = config.username();
        let auth_status_attempt = VerifiedAuthAttempt::begin(username.clone());
        let timeout = config.timeout_duration();
        let cipher_state = Arc::new(CipherState::with_compression(config.compression_mode()));
        let framed = Framed::new(stream, AgentCodec::new(cipher_state.clone()));
        let (mut writer, mut reader) = framed.split();

        let identity = config
            .private_key_pair()
            .map_err(invalid_configuration_error)?;
        let timestamp = crate::current_timestamp();
        let mut client_nonce = [0_u8; TCP_AUTH_NONCE_LEN];
        rand::rng().fill_bytes(&mut client_nonce);
        let transcript = tcp_auth_connect_request_transcript(
            TCP_HANDSHAKE_VERSION,
            &username,
            timestamp,
            &client_nonce,
        )
        .map_err(protocol_input_error)?;
        let transcript_hash = tcp_auth_connect_transcript_hash(&transcript);
        let signature = identity
            .sign_pss_sha256(&transcript)
            .map_err(|_| std::io::Error::other("无法生成 AuthConnect 签名"))?;

        writer
            .send(ProxyRequest::AuthConnect(AuthConnectRequest {
                version: TCP_HANDSHAKE_VERSION,
                username: username.clone(),
                timestamp,
                client_nonce,
                signature,
            }))
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;

        let response = read_response(&mut reader, timeout, "AuthConnect 响应超时").await?;
        let ProxyResponse::AuthConnect(response) = response else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "期望收到 AuthConnectResponse",
            ));
        };
        response.validate_shape().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "AuthConnect 响应无效")
        })?;
        if !response.success {
            let Some(code) = response.failure_code else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "认证失败",
                ));
            };
            let failure = AuthenticationFailure {
                username,
                code,
                message: response.message,
            };
            publish_verified_failure_status(&auth_status_attempt, &failure);
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                failure,
            ));
        }

        let request_secret: [u8; TCP_MASTER_SECRET_LEN] = identity
            .decrypt_oaep_sha256_labelled(
                TCP_AUTH_CONNECT_RESPONSE_OAEP_LABEL,
                &response.encrypted_session_secret,
            )
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "会话密钥无效"))?
            .try_into()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "会话密钥长度无效"))?;
        let session_cipher = TcpSessionCipher::new(
            TcpSessionRole::Agent,
            request_secret,
            transcript_hash,
            client_nonce,
            response.server_nonce,
            response.session_id,
        )
        .map_err(protocol_input_error)?;
        cipher_state
            .set_session_cipher(Arc::new(session_cipher))
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "会话重复初始化"))?;
        writer
            .send(ProxyRequest::AuthConnectIntent(intent))
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        publish_verified_active_status(&auth_status_attempt, &username);
        info!("已通过远端 Proxy AuthConnect 认证");
        Ok(Self {
            writer,
            reader,
            timeout,
        })
    }

    pub async fn establish_target<C>(
        stream: S,
        config: &C,
        address: Address,
        transport: TransportProtocol,
    ) -> Result<(ClientStream<S>, String), std::io::Error>
    where
        C: ClientConnectionConfig,
    {
        let request_id = crate::generate_id();
        let intent = AuthConnectIntent::Connect(ConnectRequest {
            request_id: request_id.clone(),
            address,
            transport,
        });
        let connection = Self::establish(stream, config, intent).await?;
        connection.await_connect_response(request_id).await
    }

    pub async fn establish_speed_test<C>(
        stream: S,
        config: &C,
        download_bytes: u32,
    ) -> Result<Self, std::io::Error>
    where
        C: ClientConnectionConfig,
    {
        Self::establish(
            stream,
            config,
            AuthConnectIntent::SpeedTest(SpeedTestRequest { download_bytes }),
        )
        .await
    }

    async fn await_connect_response(
        mut self,
        request_id: String,
    ) -> Result<(ClientStream<S>, String), std::io::Error> {
        let response = read_response(
            &mut self.reader,
            self.timeout,
            YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE,
        )
        .await?;
        let ProxyResponse::Connect(response) = response else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "期望收到 ConnectResponse",
            ));
        };
        if response.request_id != request_id {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ConnectResponse 请求标识不匹配",
            ));
        }
        if !response.success {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("连接失败: {}", response.message),
            ));
        }
        debug!("已通过远端代理连接目标");
        Ok((
            ClientStream {
                writer: self.writer,
                reader: self.reader,
                end_sent: false,
                stream_id: request_id.clone(),
                read_buf: Vec::new(),
                read_pos: 0,
            },
            request_id,
        ))
    }

    /// Read speed-test bytes from a dedicated AuthConnect stream.
    pub async fn download_speed_test(mut self, bytes: u64) -> Result<u64, std::io::Error> {
        let mut received = 0_u64;
        loop {
            let response = read_response(&mut self.reader, self.timeout, "测速响应超时").await?;
            match response {
                ProxyResponse::Data(packet)
                    if packet.stream_id == protocol::SPEED_TEST_STREAM_ID =>
                {
                    received = received.saturating_add(packet.data.len() as u64);
                    if packet.is_end {
                        return (received == bytes).then_some(received).ok_or_else(|| {
                            std::io::Error::new(std::io::ErrorKind::InvalidData, "测速字节数不匹配")
                        });
                    }
                }
                ProxyResponse::Error { message } => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        message,
                    ));
                }
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "测速响应无效",
                    ));
                }
            }
        }
    }
}

impl AuthenticatedConnection<TcpStream> {
    pub async fn connect_target<C>(
        config: &C,
        address: Address,
        transport: TransportProtocol,
    ) -> Result<(ClientStream<TcpStream>, String), std::io::Error>
    where
        C: ClientConnectionConfig,
    {
        let stream = super::tcp::connect_tcp_stream(config).await?;
        Self::establish_target(stream, config, address, transport).await
    }

    pub async fn connect_for_speed_test<C>(
        config: &C,
        download_bytes: u32,
    ) -> Result<Self, std::io::Error>
    where
        C: ClientConnectionConfig,
    {
        let stream = super::tcp::connect_tcp_stream(config).await?;
        Self::establish_speed_test(stream, config, download_bytes).await
    }
}

async fn read_response<S>(
    reader: &mut FramedReader<S>,
    timeout: Duration,
    timeout_message: &str,
) -> Result<ProxyResponse, std::io::Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match tokio::time::timeout(timeout, reader.next()).await {
        Ok(Some(Ok(response))) => Ok(response),
        Ok(Some(Err(error))) => Err(error),
        Ok(None) => Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "远端在响应前关闭了连接",
        )),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            timeout_message,
        )),
    }
}

fn invalid_configuration_error(message: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

fn protocol_input_error(error: protocol::ProtocolError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
}
