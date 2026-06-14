//! agent/proxy 级联场景共用的客户端握手逻辑。
//!
//! Desktop agent 用它连接远端 proxy；proxy 的 forward 模式也复用它连接下一跳 proxy。
//! 生命周期是：TCP connect -> 发送 Auth -> 收到 AuthResponse 后启用 AES ->
//! 发送 ConnectRequest -> 返回 `ClientStream` 做数据中继。

use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use protocol::{
    Address, AgentCodec, AuthRequest, CipherState, ConnectRequest, ProxyRequest, ProxyResponse,
    TransportProtocol,
    crypto::{AesGcmCipher, RsaKeyPair},
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpSocket, TcpStream};
use tokio_util::codec::Framed;
use tracing::{debug, info, warn};

use super::config::{BindInterface, ClientConnectionConfig};
use super::socket_bind::bind_socket_to_interface;
use super::stream::ClientStream;

type FramedWriter = SplitSink<Framed<TcpStream, AgentCodec>, ProxyRequest>;
type FramedReader = SplitStream<Framed<TcpStream, AgentCodec>>;

/// 已认证的客户端连接，用于连接远端代理
/// 可用于发送连接请求到远端代理，或转换为流
pub struct AuthenticatedConnection {
    // 认证成功后保留下来的 framed writer/reader；后续 Connect 和 Data 继续复用同一 TCP 连接。
    writer: FramedWriter,
    reader: FramedReader,
    timeout: Duration,
}

impl AuthenticatedConnection {
    /// 建立到远端代理的已认证连接，但不立即连接目标
    /// 适用于连接池场景，仅预热认证
    pub async fn authenticate_only<C>(config: &C) -> Result<Self, std::io::Error>
    where
        C: ClientConnectionConfig,
    {
        let remote_addr = config.remote_addr();
        let username = config.username();
        let timeout = config.timeout_duration();

        debug!("正在连接远端代理: {}", remote_addr);

        // 1. TCP 连接 — 可选绑定到指定本地地址，
        //    以绕过可能存在的 TUN 默认路由。
        let stream = if let Some(bind) = config.bind_addr() {
            connect_bound(config, &remote_addr, bind, config.bind_interface(), timeout).await?
        } else {
            connect_unbound(config, &remote_addr, timeout).await?
        };
        if let Err(err) = stream.set_nodelay(true) {
            warn!("设置代理连接 TCP_NODELAY 失败，将继续使用默认 TCP 行为: {err}");
        }

        // 2. 设置编解码器。认证成功前 cipher_state 只有压缩配置，没有 AES cipher。
        let cipher_state = Arc::new(CipherState::with_compression(config.compression_mode()));
        let framed = Framed::new(stream, AgentCodec::new(Some(cipher_state.clone())));
        let (mut writer, mut reader) = framed.split();

        // 3. 准备认证。
        // agent 生成一次性 AES 会话密钥，再用用户私钥处理后发给 proxy；
        // proxy 用用户公钥还原/校验，成功后双方切换到同一 AES cipher。
        let aes_cipher = AesGcmCipher::new();
        let aes_key = *aes_cipher.key();

        let private_key_pem = config
            .private_key_pem()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let rsa_keypair = RsaKeyPair::from_private_key_pem(&private_key_pem)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        let encrypted_aes_key = rsa_keypair
            .encrypt_with_private_key(&aes_key)
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        let auth_request = AuthRequest {
            username,
            timestamp: crate::current_timestamp(),
            encrypted_aes_key,
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
            if !auth_resp.success {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("认证失败: {}", auth_resp.message),
                ));
            }
            info!("已通过远端代理认证");
            // 必须在收到成功 AuthResponse 后再启用 AES；
            // 否则会把认证响应本身当成加密帧读取，双方状态就错位。
            cipher_state.set_cipher(Arc::new(aes_cipher));
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
    ) -> Result<(ClientStream, String), std::io::Error> {
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

            self.reader
                .next()
                .await
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "连接期间远端关闭了连接",
                    )
                })
                .and_then(|r| r)
        })
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "连接目标响应超时",
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

// ---------------------------------------------------------------------------
// 辅助函数
// ---------------------------------------------------------------------------

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
