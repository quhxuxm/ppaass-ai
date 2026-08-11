use std::sync::Arc;
use std::time::Duration;

use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use protocol::{
    Address, AgentCodec, AuthRequest, CipherState, ConnectRequest, ProxyRequest, ProxyResponse,
    SPEED_TEST_STREAM_ID, SpeedTestRequest, TransportProtocol,
    tcp_transport::{
        TCP_AUTH_NONCE_LEN, TCP_HANDSHAKE_VERSION, TCP_OAEP_LABEL, TcpSessionCipher,
        TcpSessionRole, decode_tcp_session_secret, tcp_auth_request_transcript,
        tcp_auth_transcript_hash,
    },
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

/// 已认证的客户端连接，用于连接远端代理
/// 可用于发送连接请求到远端代理，或转换为流
pub struct AuthenticatedConnection<S = TcpStream>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 认证成功后保留下来的 framed writer/reader；后续 Connect 和 Data 继续复用同一 TCP 连接。
    writer: FramedWriter<S>,
    reader: FramedReader<S>,
    timeout: Duration,
}

impl<S> AuthenticatedConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// 在一条已经建立的双向流上执行 PPAASS 认证。
    ///
    /// 这套逻辑运行在 Yamux 子 stream 内，AuthResponse 成功并完成上下文
    /// 校验后才启用 v4 方向独立的记录层密钥。
    pub async fn authenticate_stream<C>(stream: S, config: &C) -> Result<Self, std::io::Error>
    where
        C: ClientConnectionConfig,
    {
        let username = config.username();
        let auth_status_attempt = VerifiedAuthAttempt::begin(username.clone());
        let timeout = config.timeout_duration();

        // 2. 设置编解码器。认证成功前 cipher_state 尚未安装 v4 记录层。
        let cipher_state = Arc::new(CipherState::with_compression(config.compression_mode()));
        let framed = Framed::new(stream, AgentCodec::new(cipher_state.clone()));
        let (mut writer, mut reader) = framed.split();

        // 3. 准备认证。
        let rsa_keypair = config
            .private_key_pair()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let timestamp = crate::current_timestamp();
        let mut client_nonce = [0_u8; TCP_AUTH_NONCE_LEN];
        rand::rng().fill_bytes(&mut client_nonce);
        let transcript =
            tcp_auth_request_transcript(TCP_HANDSHAKE_VERSION, &username, timestamp, &client_nonce)
                .map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
                })?;
        let transcript_hash = tcp_auth_transcript_hash(&transcript);
        let signature = rsa_keypair
            .sign_pss_sha256(&transcript)
            .map_err(|_| std::io::Error::other("无法生成认证签名"))?;

        let auth_request = AuthRequest {
            version: TCP_HANDSHAKE_VERSION,
            username: username.clone(),
            timestamp,
            client_nonce,
            signature,
        };

        // 4. 发送认证请求
        writer
            .send(ProxyRequest::Auth(auth_request))
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        // 5. 读取认证响应
        let response = match tokio::time::timeout(timeout, reader.next()).await {
            Ok(Some(Ok(resp))) => resp,
            Ok(Some(Err(e))) => return Err(e),
            Ok(None) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "认证期间远端关闭了连接",
                ));
            }
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "认证响应超时",
                ));
            }
        };

        if let ProxyResponse::Auth(auth_resp) = response {
            auth_resp.validate_shape().map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "认证服务返回了无效响应")
            })?;
            if !auth_resp.success {
                let Some(failure_code) = auth_resp.failure_code else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "认证失败",
                    ));
                };
                let failure = AuthenticationFailure {
                    username,
                    code: failure_code,
                    message: auth_resp.message,
                };
                publish_verified_failure_status(&auth_status_attempt, &failure);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    failure,
                ));
            }
            let encoded_secret = rsa_keypair
                .decrypt_oaep_sha256_labelled(TCP_OAEP_LABEL, &auth_resp.encrypted_session)
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "无法解密认证服务返回的会话响应",
                    )
                })?;
            let secret = decode_tcp_session_secret(&encoded_secret).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "认证服务返回的会话响应格式无效",
                )
            })?;
            secret
                .validate_handshake_context(&transcript_hash, &client_nonce)
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "认证服务返回的会话响应与本次登录不匹配",
                    )
                })?;
            let session_cipher = TcpSessionCipher::new(
                TcpSessionRole::Agent,
                secret.master_secret,
                transcript_hash,
                client_nonce,
                secret.server_nonce,
                secret.session_id,
            )
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "无法初始化认证会话记录层")
            })?;
            info!("已通过远端代理认证");
            // 必须在解密并核对成功 AuthResponse 后再启用记录层，否则会把
            // 认证响应本身当成受保护帧读取。
            cipher_state
                .set_session_cipher(Arc::new(session_cipher))
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "认证会话记录层重复初始化")
                })?;
            publish_verified_active_status(&auth_status_attempt, &username);
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "期望收到 AuthResponse",
            ));
        }

        Ok(Self {
            writer,
            reader,
            timeout,
        })
    }

    /// 通过已认证的连接连接到目标
    pub async fn connect_to_target(
        mut self,
        address: Address,
        transport: TransportProtocol,
    ) -> Result<(ClientStream<S>, String), std::io::Error> {
        // 6. 发送连接请求。request_id 后续就是 DataPacket 的 stream_id。
        let request_id = crate::generate_id();
        let connect_request = ConnectRequest {
            request_id: request_id.clone(),
            address: address.clone(),
            transport,
        };

        debug!("向远端代理发送连接请求：{connect_request:?}");
        let response = match tokio::time::timeout(self.timeout, async {
            self.writer
                .send(ProxyRequest::Connect(connect_request))
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))?;

            self.reader.next().await.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "连接期间远端关闭了连接",
                )
            })?
        })
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE,
                ));
            }
        };
        debug!("已通过远端代理连接到目标: {response:?}");
        if let ProxyResponse::Connect(connect_resp) = response {
            if !connect_resp.success {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    format!("连接失败: {}", connect_resp.message),
                ));
            }
            info!("已通过远端代理连接到目标");
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "期望收到 ConnectResponse",
            ));
        }

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

    /// 在认证连接上请求 Proxy Entry 直接下发一段不可压缩测试数据。
    ///
    /// 该路径不连接第三方目标，测量的是 Agent 与当前 Entry 之间的真实加密 TCP 吞吐。
    pub async fn download_speed_test(mut self, download_bytes: u32) -> Result<u64, std::io::Error> {
        let request = SpeedTestRequest { download_bytes };
        request
            .validate_shape()
            .map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidInput, message))?;
        self.writer
            .send(ProxyRequest::SpeedTest(request))
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;

        let receive = async {
            let mut received = 0_u64;
            loop {
                let response = self.reader.next().await.ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "Proxy Entry 在测速完成前关闭了连接",
                    )
                })??;
                match response {
                    ProxyResponse::Data(packet) if packet.stream_id == SPEED_TEST_STREAM_ID => {
                        received = received
                            .checked_add(packet.data.len() as u64)
                            .ok_or_else(|| std::io::Error::other("测速字节数溢出"))?;
                        if received > u64::from(download_bytes) {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "Proxy Entry 返回了过量测速数据",
                            ));
                        }
                        if packet.is_end {
                            if received != u64::from(download_bytes) {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::UnexpectedEof,
                                    "Proxy Entry 返回的测速数据不完整",
                                ));
                            }
                            return Ok(received);
                        }
                    }
                    ProxyResponse::Error { message } => {
                        return Err(std::io::Error::other(message));
                    }
                    _ => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Proxy Entry 返回了无效测速响应",
                        ));
                    }
                }
            }
        };
        tokio::time::timeout(self.timeout.max(Duration::from_secs(20)), receive)
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "测速超时"))?
    }
}
