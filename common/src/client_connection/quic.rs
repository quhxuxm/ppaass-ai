//! QUIC 客户端连接以及双向流适配器。
//!
//! TLS 在这里用于满足 QUIC 握手要求；PPAASS 原有 RSA/AES 认证和加密仍在每条
//! QUIC 双向流内执行，因此切换传输模式不会改变应用协议帧。

use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, TransportConfig, VarInt};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, info, warn};

use super::authenticated::AuthenticatedConnection;
use super::config::ClientConnectionConfig;
use super::socket_bind::bind_socket_to_interface;
use super::stream::ClientStream;
use protocol::{Address, TransportProtocol};

pub const PPAASS_QUIC_ALPN: &[u8] = b"ppaass/1";

/// QUIC endpoint 的 UDP socket 缓冲区。
///
/// Quinn 的一个 endpoint 会把所有连接的 UDP 包集中到同一个 socket；系统默认
/// 缓冲在多并发流量下容易溢出，溢出后会被 QUIC 视为网络丢包并收缩拥塞窗口。
pub const QUIC_UDP_SOCKET_BUFFER_SIZE: usize = 4 * 1024 * 1024;

const QUIC_STREAM_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;
const QUIC_CONNECTION_RECEIVE_WINDOW: u32 = 64 * 1024 * 1024;
const QUIC_SEND_WINDOW: u64 = 64 * 1024 * 1024;

/// 创建适合高 RTT、多并发代理流量的 QUIC transport 参数。
///
/// `max_incoming_bidi_streams` 是对端允许主动打开的流数：agent 端传 0，proxy 端
/// 传入它允许的 agent 业务流数。
pub fn quic_transport_config(max_incoming_bidi_streams: u32) -> Arc<TransportConfig> {
    let mut transport = TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(VarInt::from_u32(max_incoming_bidi_streams))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .stream_receive_window(VarInt::from_u32(QUIC_STREAM_RECEIVE_WINDOW))
        .receive_window(VarInt::from_u32(QUIC_CONNECTION_RECEIVE_WINDOW))
        .send_window(QUIC_SEND_WINDOW)
        .send_fairness(true);
    Arc::new(transport)
}

/// 在把 UDP socket 交给 Quinn 前扩大内核收发队列。
///
/// 某些平台会按系统上限截断请求值，因此这里采用 best-effort：设置失败不阻止连接，
/// 但记录实际缓冲大小便于诊断。
pub fn configure_quic_udp_socket(socket: &Socket) {
    if let Err(err) = socket.set_recv_buffer_size(QUIC_UDP_SOCKET_BUFFER_SIZE) {
        warn!("设置 QUIC UDP SO_RCVBUF 失败，继续使用系统值：{err}");
    }
    if let Err(err) = socket.set_send_buffer_size(QUIC_UDP_SOCKET_BUFFER_SIZE) {
        warn!("设置 QUIC UDP SO_SNDBUF 失败，继续使用系统值：{err}");
    }
    debug!(
        requested = QUIC_UDP_SOCKET_BUFFER_SIZE,
        recv = ?socket.recv_buffer_size().ok(),
        send = ?socket.send_buffer_size().ok(),
        "QUIC UDP socket 缓冲区已配置"
    );
}

/// 把 quinn 的收、发半流组合成通用 AsyncRead + AsyncWrite。
pub struct QuicBiStream {
    send: SendStream,
    recv: RecvStream,
}

impl QuicBiStream {
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for QuicBiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicBiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

impl Unpin for QuicBiStream {}

/// 一条可复用的 agent -> proxy QUIC 连接。
#[derive(Clone)]
pub struct QuicClientConnection {
    // Endpoint 必须与 Connection 同寿命，否则底层 UDP driver 会停止。
    _endpoint: Endpoint,
    connection: Connection,
}

impl QuicClientConnection {
    pub async fn connect<C>(config: &C) -> io::Result<Self>
    where
        C: ClientConnectionConfig,
    {
        let remote_addr = config.remote_addr();
        let timeout = config.timeout_duration();
        let resolved: Vec<SocketAddr> = tokio::net::lookup_host(&remote_addr).await?.collect();
        let bind_ip = config.bind_addr().map(|addr| addr.ip());
        let mut last_error = None;

        for remote in resolved {
            if bind_ip.is_some_and(|ip| ip.is_ipv4() != remote.is_ipv4()) {
                continue;
            }
            match connect_one(config, remote, bind_ip, timeout).await {
                Ok(connection) => {
                    info!("已建立 QUIC proxy 连接 remote={remote}");
                    return Ok(connection);
                }
                Err(err) => {
                    warn!("建立 QUIC proxy 连接失败 remote={remote}: {err}");
                    last_error = Some(err);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("proxy 地址 {remote_addr} 没有可用的 QUIC 端点"),
            )
        }))
    }

    pub fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }

    /// 返回当前连接的 RTT、拥塞窗口和丢包等运行指标。
    pub fn stats(&self) -> quinn::ConnectionStats {
        self.connection.stats()
    }

    pub async fn connect_to_target<C>(
        &self,
        config: &C,
        address: Address,
        transport: TransportProtocol,
    ) -> io::Result<(ClientStream<QuicBiStream>, String)>
    where
        C: ClientConnectionConfig,
    {
        let timeout = config.timeout_duration();
        let (send, recv) = tokio::time::timeout(timeout, self.connection.open_bi())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "打开 QUIC 双向流超时"))?
            .map_err(|err| io::Error::other(err.to_string()))?;
        let authenticated =
            AuthenticatedConnection::authenticate_stream(QuicBiStream::new(send, recv), config)
                .await?;
        authenticated.connect_to_target(address, transport).await
    }
}

async fn connect_one<C>(
    config: &C,
    remote: SocketAddr,
    bind_ip: Option<IpAddr>,
    timeout: std::time::Duration,
) -> io::Result<QuicClientConnection>
where
    C: ClientConnectionConfig,
{
    let socket = Socket::new(
        Domain::for_address(remote),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    configure_quic_udp_socket(&socket);
    config.protect_socket(&socket, remote)?;
    bind_socket_to_interface(&socket, config.bind_interface().as_ref(), remote)?;
    let local = SocketAddr::new(
        bind_ip.unwrap_or_else(|| {
            if remote.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            }
        }),
        0,
    );
    socket.bind(&SockAddr::from(local))?;
    socket.set_nonblocking(true)?;

    let mut endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket.into(),
        Arc::new(quinn::TokioRuntime),
    )?;
    endpoint.set_default_client_config(insecure_client_config()?);
    let connecting = endpoint
        .connect(remote, "ppaass.local")
        .map_err(|err| io::Error::other(err.to_string()))?;
    let connection = tokio::time::timeout(timeout, connecting)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "QUIC 握手超时"))?
        .map_err(|err| io::Error::other(err.to_string()))?;
    debug!(
        "QUIC 握手完成 local={} remote={remote}",
        endpoint.local_addr()?
    );
    Ok(QuicClientConnection {
        _endpoint: endpoint,
        connection,
    })
}

fn insecure_client_config() -> io::Result<ClientConfig> {
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    crypto.alpn_protocols = vec![PPAASS_QUIC_ALPN.to_vec()];
    let crypto =
        QuicClientConfig::try_from(crypto).map_err(|err| io::Error::other(err.to_string()))?;
    let mut config = ClientConfig::new(Arc::new(crypto));
    // proxy 不会反向主动打开业务流，因此客户端 incoming bidi 设为 0。
    config.transport_config(quic_transport_config(0));
    Ok(config)
}

/// PPAASS 在 QUIC 流内完成原有的用户认证与应用层加密；这里接受 proxy 启动时
/// 自动生成的自签名证书，避免部署额外证书文件。
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
