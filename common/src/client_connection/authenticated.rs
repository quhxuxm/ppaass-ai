//! agent/proxy 级联场景共用的 PPAASS 子流握手逻辑。
//!
//! 外层 raw TCP 只承载 Yamux session；每个 Yamux 子 stream 内执行：
//! 发送 Auth -> 收到 AuthResponse 后启用 AES -> 发送 ConnectRequest ->
//! 返回 `ClientStream` 做数据中继。

use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use protocol::{
    Address, AgentCodec, AuthRequest, CipherState, ConnectRequest, ProxyRequest, ProxyResponse,
    TransportProtocol,
    crypto::{RsaKeyPair, verify_pss_sha256},
    tcp_transport::{
        TCP_AUTH_NONCE_LEN, TCP_HANDSHAKE_VERSION, TCP_OAEP_LABEL, TcpSessionCipher,
        TcpSessionRole, decode_tcp_session_secret, tcp_auth_request_transcript,
        tcp_auth_response_signature_transcript, tcp_auth_transcript_hash,
    },
};
use rand::Rng;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpSocket, TcpStream};
use tokio_util::codec::Framed;
use tracing::{debug, info, warn};

use crate::configure_proxy_tcp_socket;

use super::config::{BindInterface, ClientConnectionConfig};
use super::socket_bind::bind_socket_to_interface;
use super::stream::ClientStream;
use super::yamux::YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE;

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
    /// 校验后才启用 v2 方向独立的记录层密钥。
    pub async fn authenticate_stream<C>(stream: S, config: &C) -> Result<Self, std::io::Error>
    where
        C: ClientConnectionConfig,
    {
        let username = config.username();
        let timeout = config.timeout_duration();

        // 2. 设置编解码器。认证成功前 cipher_state 尚未安装 v2 记录层。
        let cipher_state = Arc::new(CipherState::with_compression(config.compression_mode()));
        let framed = Framed::new(stream, AgentCodec::new(cipher_state.clone()));
        let (mut writer, mut reader) = framed.split();

        // 3. 准备认证。
        let private_key_pem = config
            .private_key_pem()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let rsa_keypair = RsaKeyPair::from_private_key_pem(&private_key_pem)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        let proxy_identity_public_key_pem =
            config.proxy_identity_public_key_pem().map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "未配置可信的 Proxy 传输身份公钥",
                )
            })?;
        let proxy_identity_public_key =
            RsaKeyPair::from_public_key_pem(&proxy_identity_public_key_pem).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Proxy 传输身份公钥格式无效",
                )
            })?;
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
            username,
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
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "认证失败",
                ));
            }
            let proxy_signature_transcript = tcp_auth_response_signature_transcript(
                auth_resp.version,
                &transcript_hash,
                &auth_resp.encrypted_session,
            )
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "认证服务返回了无效的身份签名上下文",
                )
            })?;
            // Verify the pinned Proxy identity before attempting private-key
            // OAEP decryption or installing any attacker-selected session key.
            verify_pss_sha256(
                &proxy_identity_public_key,
                &proxy_signature_transcript,
                &auth_resp.proxy_signature,
            )
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Proxy 传输身份验证失败",
                )
            })?;
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
}

impl AuthenticatedConnection<TcpStream> {
    pub async fn connect<C>(config: &C) -> Result<Self, std::io::Error>
    where
        C: ClientConnectionConfig,
    {
        let stream = connect_tcp_stream(config).await?;
        Self::authenticate_stream(stream, config).await
    }
}

// ---------------------------------------------------------------------------
// 辅助函数
// ---------------------------------------------------------------------------

pub(super) async fn connect_tcp_stream<C>(config: &C) -> std::io::Result<TcpStream>
where
    C: ClientConnectionConfig,
{
    let remote_addr = config.remote_addr();
    let timeout = config.timeout_duration();

    debug!("正在连接远端代理: {}", remote_addr);

    // TCP 连接 — 可选绑定到指定本地地址，以绕过可能存在的 TUN 默认路由。
    let stream = if let Some(bind) = config.bind_addr() {
        connect_bound(config, &remote_addr, bind, config.bind_interface(), timeout).await?
    } else {
        connect_unbound(config, &remote_addr, timeout).await?
    };
    if let Err(err) = stream.set_nodelay(true) {
        warn!("设置代理连接 TCP_NODELAY 失败，将继续使用默认 TCP 行为: {err}");
    }

    Ok(stream)
}

/// 连接到 `remote_addr`，同时将套接字绑定到 `bind`。
///
/// 确保连接使用拥有 `bind.ip()` 的网络接口，而非操作系统根据当前路由表
/// 自动选择的接口——这在 TUN 模式下至关重要，可防止代理连接回环到 TUN 设备。
///
/// 如果所有绑定连接尝试都失败，则直接返回错误。
/// TUN 模式依赖这个绑定来防止代理连接回环进入 TUN，不能静默回退到普通连接。
async fn connect_bound<C>(
    config: &C,
    remote_addr: &str,
    bind: SocketAddr,
    bind_interface: Option<BindInterface>,
    timeout: std::time::Duration,
) -> std::io::Result<TcpStream>
where
    C: ClientConnectionConfig,
{
    // 异步解析远端主机名
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(remote_addr)
        .await
        .map(|it| it.collect())
        .unwrap_or_default();

    let mut last_error = None;
    let mut has_matching_addr = false;

    for dst in &addrs {
        // 跳过 IP 版本与绑定地址不匹配的地址
        let version_match = (bind.is_ipv4() && dst.is_ipv4()) || (bind.is_ipv6() && dst.is_ipv6());
        if !version_match {
            continue;
        }
        has_matching_addr = true;

        let socket = match Socket::new(Domain::for_address(*dst), Type::STREAM, Some(Protocol::TCP))
        {
            Ok(s) => s,
            Err(e) => {
                warn!("创建 TcpSocket 失败 (dst={}): {e}", dst);
                last_error = Some(e);
                continue;
            }
        };
        if let Err(e) = config.protect_socket(&socket, *dst) {
            warn!("保护代理连接 socket 失败 (dst={}): {e}", dst);
            last_error = Some(e);
            continue;
        }
        tune_proxy_socket(config, &socket, *dst);
        tune_proxy_keepalive(&socket, *dst);
        if let Err(e) = bind_socket_to_interface(&socket, bind_interface.as_ref(), *dst) {
            warn!("绑定代理连接到物理接口失败 (dst={}): {e}", dst);
            last_error = Some(e);
            continue;
        }
        if let Err(e) = socket.bind(&SockAddr::from(bind)) {
            warn!("TcpSocket::bind({bind}) 失败: {e}");
            last_error = Some(e);
            continue;
        }
        if let Err(e) = socket.set_nonblocking(true) {
            warn!("设置代理连接 socket 非阻塞失败 (dst={}): {e}", dst);
            last_error = Some(e);
            continue;
        }

        let socket = TcpSocket::from_std_stream(socket.into());
        match tokio::time::timeout(timeout, socket.connect(*dst)).await {
            Ok(Ok(stream)) => {
                debug!("已通过绑定套接字连接到 {dst} (本地={bind})");
                return Ok(stream);
            }
            Ok(Err(e)) => {
                warn!("绑定连接到 {dst} 失败: {e}");
                last_error = Some(e);
            }
            Err(_) => {
                warn!("绑定连接到 {dst} 超时");
                last_error = Some(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("绑定连接到 {dst} 超时"),
                ));
            }
        }
    }

    if !has_matching_addr {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            format!("代理地址 {remote_addr} 没有与绑定地址 {bind} 匹配的 IP 版本"),
        ));
    }

    Err(last_error.unwrap_or_else(|| {
        std::io::Error::other(format!("所有到 {remote_addr} 的绑定连接尝试均失败"))
    }))
}

async fn connect_unbound<C>(
    config: &C,
    remote_addr: &str,
    timeout: std::time::Duration,
) -> std::io::Result<TcpStream>
where
    C: ClientConnectionConfig,
{
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(remote_addr).await?.collect();
    let mut last_error = None;

    for dst in addrs {
        let socket = match Socket::new(Domain::for_address(dst), Type::STREAM, Some(Protocol::TCP))
        {
            Ok(socket) => socket,
            Err(e) => {
                warn!("创建 TcpSocket 失败 (dst={}): {e}", dst);
                last_error = Some(e);
                continue;
            }
        };
        if let Err(e) = config.protect_socket(&socket, dst) {
            warn!("保护代理连接 socket 失败 (dst={}): {e}", dst);
            last_error = Some(e);
            continue;
        }
        tune_proxy_socket(config, &socket, dst);
        tune_proxy_keepalive(&socket, dst);
        if let Err(e) = socket.set_nonblocking(true) {
            warn!("设置代理连接 socket 非阻塞失败 (dst={}): {e}", dst);
            last_error = Some(e);
            continue;
        }

        let socket = TcpSocket::from_std_stream(socket.into());
        match tokio::time::timeout(timeout, socket.connect(dst)).await {
            Ok(Ok(stream)) => {
                debug!("已连接到远端代理 {dst}");
                return Ok(stream);
            }
            Ok(Err(e)) => {
                warn!("连接到远端代理 {dst} 失败: {e}");
                last_error = Some(e);
            }
            Err(_) => {
                warn!("连接到远端代理 {dst} 超时");
                last_error = Some(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("连接到远端代理 {dst} 超时"),
                ));
            }
        }
    }

    Err(last_error
        .unwrap_or_else(|| std::io::Error::other(format!("所有到 {remote_addr} 的连接尝试均失败"))))
}

fn tune_proxy_socket<C>(config: &C, socket: &Socket, dst: SocketAddr)
where
    C: ClientConnectionConfig,
{
    let Some(buffer_size) = config.tcp_socket_buffer_size() else {
        return;
    };
    if let Err(err) = socket.set_recv_buffer_size(buffer_size) {
        warn!("设置代理连接 socket 接收缓冲失败 (dst={}): {err}", dst);
    }
    if let Err(err) = socket.set_send_buffer_size(buffer_size) {
        warn!("设置代理连接 socket 发送缓冲失败 (dst={}): {err}", dst);
    }
}

fn tune_proxy_keepalive(socket: &Socket, dst: SocketAddr) {
    if let Err(err) = configure_proxy_tcp_socket(socket) {
        debug!("设置代理 TCP keepalive 失败 (dst={}): {err}", dst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::crypto::encrypt_oaep_sha256_labelled;
    use protocol::tcp_transport::{
        TCP_MASTER_SECRET_LEN, TCP_SERVER_NONCE_LEN, TCP_SESSION_ID_LEN, TcpSessionSecret,
        encode_tcp_session_secret,
    };
    use protocol::{AuthResponse, ConnectResponse, ProxyCodec};
    use std::fmt;

    struct TestClientConfig {
        username: String,
        private_key_pem: String,
        proxy_identity_public_key_pem: String,
    }

    impl fmt::Debug for TestClientConfig {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("TestClientConfig")
                .field("username", &self.username)
                .field("private_key_pem", &"[REDACTED]")
                .field("proxy_identity_public_key_pem", &"[CONFIGURED]")
                .finish()
        }
    }

    impl ClientConnectionConfig for TestClientConfig {
        fn remote_addr(&self) -> String {
            "unused.invalid:1".to_string()
        }

        fn username(&self) -> String {
            self.username.clone()
        }

        fn private_key_pem(&self) -> Result<String, String> {
            Ok(self.private_key_pem.clone())
        }

        fn proxy_identity_public_key_pem(&self) -> Result<String, String> {
            Ok(self.proxy_identity_public_key_pem.clone())
        }

        fn timeout_duration(&self) -> Duration {
            Duration::from_secs(5)
        }
    }

    #[tokio::test]
    async fn framed_stream_switches_from_clear_auth_to_encrypted_connect() {
        let user_identity = RsaKeyPair::generate(2048).unwrap();
        let user_public_key =
            RsaKeyPair::from_public_key_pem(&user_identity.public_key_to_pem().unwrap()).unwrap();
        let proxy_identity = RsaKeyPair::generate(2048).unwrap();
        let config = TestClientConfig {
            username: "alice".to_string(),
            private_key_pem: user_identity.private_key_to_pem().unwrap(),
            proxy_identity_public_key_pem: proxy_identity.public_key_to_pem().unwrap(),
        };
        let expected_address = Address::Domain {
            host: "example.com".to_string(),
            port: 443,
        };
        let server_expected_address = expected_address.clone();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let server_flow = async move {
            let cipher_state = Arc::new(CipherState::new());
            let framed = Framed::new(server_io, ProxyCodec::new(cipher_state.clone()));
            let (mut writer, mut reader) = framed.split();

            let auth = match reader.next().await.unwrap().unwrap() {
                ProxyRequest::Auth(auth) => auth,
                other => panic!("expected Auth request, got {other:?}"),
            };
            auth.validate_shape().unwrap();
            let transcript = tcp_auth_request_transcript(
                auth.version,
                &auth.username,
                auth.timestamp,
                &auth.client_nonce,
            )
            .unwrap();
            verify_pss_sha256(&user_public_key, &transcript, &auth.signature).unwrap();
            let transcript_hash = tcp_auth_transcript_hash(&transcript);
            let master_secret = [11_u8; TCP_MASTER_SECRET_LEN];
            let server_nonce = [22_u8; TCP_SERVER_NONCE_LEN];
            let session_id = [33_u8; TCP_SESSION_ID_LEN];
            let secret = TcpSessionSecret {
                version: TCP_HANDSHAKE_VERSION,
                auth_transcript_hash: transcript_hash,
                client_nonce: auth.client_nonce,
                server_nonce,
                session_id,
                master_secret,
            };
            let encrypted_session = encrypt_oaep_sha256_labelled(
                &user_public_key,
                TCP_OAEP_LABEL,
                &encode_tcp_session_secret(&secret).unwrap(),
            )
            .unwrap();
            let response_transcript = tcp_auth_response_signature_transcript(
                TCP_HANDSHAKE_VERSION,
                &transcript_hash,
                &encrypted_session,
            )
            .unwrap();
            let response_signature = proxy_identity
                .sign_pss_sha256(&response_transcript)
                .unwrap();
            let server_cipher = TcpSessionCipher::new(
                TcpSessionRole::Proxy,
                master_secret,
                transcript_hash,
                auth.client_nonce,
                server_nonce,
                session_id,
            )
            .unwrap();

            // The successful AuthResponse is the final clear envelope. Only
            // after it has been written may either codec accept business data.
            writer
                .send(ProxyResponse::Auth(AuthResponse::success(
                    encrypted_session,
                    response_signature,
                )))
                .await
                .unwrap();
            cipher_state
                .set_session_cipher(Arc::new(server_cipher))
                .unwrap();

            let connect = match reader.next().await.unwrap().unwrap() {
                ProxyRequest::Connect(connect) => connect,
                other => panic!("expected encrypted Connect request, got {other:?}"),
            };
            assert_eq!(connect.address, server_expected_address);
            assert_eq!(connect.transport, TransportProtocol::Tcp);
            let request_id = connect.request_id.clone();
            writer
                .send(ProxyResponse::Connect(ConnectResponse {
                    request_id: connect.request_id,
                    success: true,
                    message: "connected".to_string(),
                }))
                .await
                .unwrap();
            request_id
        };

        let client_flow = async {
            let connection = AuthenticatedConnection::authenticate_stream(client_io, &config)
                .await
                .unwrap();
            let (_stream, request_id) = connection
                .connect_to_target(expected_address, TransportProtocol::Tcp)
                .await
                .unwrap();
            request_id
        };

        let (server_request_id, client_request_id) =
            tokio::time::timeout(Duration::from_secs(10), async {
                tokio::join!(server_flow, client_flow)
            })
            .await
            .unwrap();
        assert_eq!(server_request_id, client_request_id);
    }
}
