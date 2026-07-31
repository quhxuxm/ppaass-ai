use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use common::{
    AuthenticatedConnection, ClientStream, TransportMode, UdpClientConnection, UdpClientStream,
    YAMUX_SESSION_STREAM_CAPACITY_EXHAUSTED_MESSAGE, YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE,
    YamuxClientConnection, YamuxClientStream,
};
use protocol::{Address, TransportProtocol};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::config::AndroidAgentConfig;
use crate::error::{AndroidAgentError, Result};

const MAX_CONCURRENT_SESSION_CONNECTS: usize = 10;
const MAX_CONFIGURED_DIRECT_TCP_CONNECTS: usize = 256;
const MIN_DIRECT_TCP_STREAM_TIMEOUT_SECS: u64 = 5;
const MAX_DIRECT_TCP_STREAM_TIMEOUT_SECS: u64 = 20;

#[derive(Clone)]
struct AndroidYamuxSession {
    id: usize,
    connection: YamuxClientConnection,
}

#[derive(Clone)]
struct AndroidUdpSession {
    id: usize,
    connection: UdpClientConnection,
}

pub struct AndroidYamuxSessionManager {
    config: Arc<AndroidAgentConfig>,
    shutdown: CancellationToken,
    manager_name: &'static str,
    yamux_transport: TransportProtocol,
    yamux_sessions: Mutex<Vec<AndroidYamuxSession>>,
    // 每个 slot 拥有独立原生 UDP socket、会话密钥与序号空间。slot 级锁使首次
    // 并发建连可以平行进行，不会被一把全局锁串行化。
    udp_sessions: Vec<Mutex<Option<AndroidUdpSession>>>,
    yamux_refill_lock: Mutex<()>,
    direct_tcp_connects: Semaphore,
    udp_next_index: AtomicUsize,
    udp_next_session_id: AtomicUsize,
    yamux_next_index: AtomicUsize,
    yamux_next_session_id: AtomicUsize,
    // 自动模式按原生 UDP pool slot 独立回退，避免一个坏 session 影响其他
    // 仍然可用的加密 UDP session。
    auto_udp_fallback_to_yamux: Vec<AtomicBool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyStreamRoute {
    Auto,
    DirectTcp,
    NativeUdp,
    Yamux,
}

impl AndroidYamuxSessionManager {
    pub fn new_tcp_direct(
        config: Arc<AndroidAgentConfig>,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        Self::new_for_transport(
            config,
            shutdown,
            "tcp_direct_connections",
            TransportProtocol::Tcp,
        )
    }

    pub fn new_udp(config: Arc<AndroidAgentConfig>, shutdown: CancellationToken) -> Arc<Self> {
        Self::new_for_transport(
            config,
            shutdown,
            "udp_proxy_connections",
            TransportProtocol::Udp,
        )
    }

    #[doc(hidden)]
    pub fn udp_session_pool_size(&self) -> usize {
        self.udp_sessions.len()
    }

    #[doc(hidden)]
    pub fn udp_fallback_slot_count(&self) -> usize {
        self.auto_udp_fallback_to_yamux.len()
    }

    #[doc(hidden)]
    pub fn udp_fallback_to_yamux(&self, slot: usize) -> bool {
        self.auto_udp_fallback_to_yamux
            .get(slot)
            .is_some_and(|fallback| fallback.load(Ordering::Acquire))
    }

    #[doc(hidden)]
    pub fn set_udp_fallback_to_yamux(&self, slot: usize, enabled: bool) {
        if let Some(fallback) = self.auto_udp_fallback_to_yamux.get(slot) {
            fallback.store(enabled, Ordering::Release);
        }
    }

    fn new_for_transport(
        config: Arc<AndroidAgentConfig>,
        shutdown: CancellationToken,
        manager_name: &'static str,
        yamux_transport: TransportProtocol,
    ) -> Arc<Self> {
        let direct_tcp_connect_limit = config
            .http_proxy_max_concurrent_connects
            .clamp(1, MAX_CONFIGURED_DIRECT_TCP_CONNECTS);
        // transport_mode=udp 只控制 UDP 的外层传输。TCP manager 始终使用
        // direct framed TCP，因此不应分配也不可能误用原生 UDP 会话池。
        let udp_pool_size = if config.transport_mode.uses_native_udp_for(yamux_transport) {
            config.effective_udp_session_pool_size()
        } else {
            0
        };
        Arc::new(Self {
            config,
            shutdown,
            manager_name,
            yamux_transport,
            yamux_sessions: Mutex::new(Vec::new()),
            udp_sessions: (0..udp_pool_size).map(|_| Mutex::new(None)).collect(),
            yamux_refill_lock: Mutex::new(()),
            direct_tcp_connects: Semaphore::new(direct_tcp_connect_limit),
            udp_next_index: AtomicUsize::new(0),
            udp_next_session_id: AtomicUsize::new(0),
            yamux_next_index: AtomicUsize::new(0),
            yamux_next_session_id: AtomicUsize::new(0),
            auto_udp_fallback_to_yamux: (0..udp_pool_size)
                .map(|_| AtomicBool::new(false))
                .collect(),
        })
    }
}

mod connection;
mod pool;

#[doc(hidden)]
pub fn proxy_stream_route(
    transport_mode: TransportMode,
    manager_transport: TransportProtocol,
    target_transport: TransportProtocol,
) -> Option<ProxyStreamRoute> {
    if manager_transport != target_transport {
        return None;
    }

    if target_transport == TransportProtocol::Tcp {
        // TCP 不受 transport_mode 影响，一律沿用原来的独立 framed TCP 连接。
        Some(ProxyStreamRoute::DirectTcp)
    } else if transport_mode.automatically_falls_back_to_tcp() {
        Some(ProxyStreamRoute::Auto)
    } else if transport_mode.uses_native_udp_for(target_transport) {
        Some(ProxyStreamRoute::NativeUdp)
    } else {
        Some(ProxyStreamRoute::Yamux)
    }
}

#[doc(hidden)]
pub fn is_native_udp_timeout(error: &AndroidAgentError) -> bool {
    match error {
        AndroidAgentError::Io(error) => error.kind() == io::ErrorKind::TimedOut,
        AndroidAgentError::Connection(message) => {
            message.contains("原生 UDP 认证响应超时") || message.contains("连接原生 UDP proxy 超时")
        }
        _ => false,
    }
}

pub enum AndroidYamuxTargetStream {
    Direct(ClientStream<TcpStream>),
    Yamux(YamuxClientStream),
    Udp(UdpClientStream),
}

impl AsyncRead for AndroidYamuxTargetStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Direct(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Yamux(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Udp(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for AndroidYamuxTargetStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Direct(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Yamux(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Udp(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Direct(stream) => Pin::new(stream).poll_flush(cx),
            Self::Yamux(stream) => Pin::new(stream).poll_flush(cx),
            Self::Udp(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Direct(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Yamux(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Udp(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

impl Unpin for AndroidYamuxTargetStream {}

#[doc(hidden)]
pub fn is_yamux_actual_target_connect_error(message: &str) -> bool {
    message.starts_with("连接失败:")
        || message == YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE
        || message == "连接目标响应超时"
}

fn is_yamux_session_capacity_error(message: &str) -> bool {
    message == YAMUX_SESSION_STREAM_CAPACITY_EXHAUSTED_MESSAGE
}

fn target_label(address: &Address) -> String {
    match address {
        Address::Domain { host, port } => format!("{host}:{port}"),
        Address::Ipv4 { addr, port } => {
            format!("{}.{}.{}.{}:{port}", addr[0], addr[1], addr[2], addr[3])
        }
        Address::Ipv6 { addr, port } => format!(
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
        ),
        Address::ProxyDns { port } => format!("proxy-dns:{port}"),
        Address::UdpRelay => "udp-relay".to_string(),
    }
}
