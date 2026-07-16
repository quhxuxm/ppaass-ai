use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

#[cfg(test)]
use common::YAMUX_OPEN_STREAM_TIMEOUT_MESSAGE;
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

use crate::android_log;
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
enum ProxyStreamRoute {
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

    pub async fn connect_to_target(
        &self,
        address: Address,
        transport: TransportProtocol,
    ) -> Result<AndroidYamuxTargetStream> {
        let route = proxy_stream_route(self.config.transport_mode, self.yamux_transport, transport)
            .ok_or_else(|| {
                AndroidAgentError::Connection(format!(
                    "Android {} only supports {:?} proxy streams",
                    self.manager_name, self.yamux_transport
                ))
            })?;

        match route {
            ProxyStreamRoute::DirectTcp => self.open_direct_tcp_stream(address).await,
            ProxyStreamRoute::NativeUdp => self.open_udp_stream(address, transport).await,
            ProxyStreamRoute::Auto => {
                let slot_index = self.next_udp_session_slot();
                if self.auto_udp_fallback_to_yamux[slot_index].load(Ordering::Acquire) {
                    return self.open_target_stream(address, transport).await;
                }
                match self
                    .open_udp_stream_in_slot(address.clone(), transport, slot_index)
                    .await
                {
                    Ok(stream) => Ok(stream),
                    Err(err) if is_native_udp_timeout(&err) => {
                        self.auto_udp_fallback_to_yamux[slot_index].store(true, Ordering::Release);
                        warn!(
                            slot = slot_index,
                            "Android automatic UDP session timed out; switching only this session slot to TCP/Yamux: {err}"
                        );
                        android_log::warn(format!(
                            "Automatic UDP session slot {slot_index} switched to TCP/Yamux after timeout: {err}"
                        ));
                        self.open_target_stream(address, transport).await
                    }
                    Err(err) => Err(err),
                }
            }
            ProxyStreamRoute::Yamux => self.open_target_stream(address, transport).await,
        }
    }

    async fn open_udp_stream(
        &self,
        address: Address,
        transport: TransportProtocol,
    ) -> Result<AndroidYamuxTargetStream> {
        if self.shutdown.is_cancelled() {
            return Err(AndroidAgentError::Connection(
                "Android agent is stopping".into(),
            ));
        }
        if self.udp_sessions.is_empty() {
            return Err(AndroidAgentError::Connection(format!(
                "Android {} native UDP transport is disabled",
                self.manager_name
            )));
        }
        let slot_index = self.next_udp_session_slot();
        self.open_udp_stream_in_slot(address, transport, slot_index)
            .await
    }

    async fn open_udp_stream_in_slot(
        &self,
        address: Address,
        transport: TransportProtocol,
        slot_index: usize,
    ) -> Result<AndroidYamuxTargetStream> {
        for attempt in 0..2 {
            let handle = {
                let mut current = self.udp_sessions[slot_index].lock().await;
                if self.config.transport_mode.automatically_falls_back_to_tcp()
                    && current
                        .as_ref()
                        .is_some_and(|handle| handle.connection.timed_out())
                {
                    return Err(AndroidAgentError::Io(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "原生 UDP 会话保活响应超时",
                    )));
                }
                if current
                    .as_ref()
                    .is_none_or(|handle| handle.connection.is_closed())
                {
                    let connection = UdpClientConnection::connect(self.config.as_ref())
                        .await
                        .map_err(AndroidAgentError::Io)?;
                    let connection_id = self.udp_next_session_id.fetch_add(1, Ordering::AcqRel);
                    debug!(
                        manager = self.manager_name,
                        slot = slot_index,
                        connection_id,
                        "Android native encrypted UDP session pool slot established"
                    );
                    *current = Some(AndroidUdpSession {
                        id: connection_id,
                        connection,
                    });
                }
                current
                    .as_ref()
                    .expect("Android UDP session initialized")
                    .clone()
            };
            match handle
                .connection
                .connect_to_target(address.clone(), transport)
                .await
            {
                Ok((stream, _)) => return Ok(AndroidYamuxTargetStream::Udp(stream)),
                Err(err) if attempt == 0 && handle.connection.is_closed() => {
                    let mut current = self.udp_sessions[slot_index].lock().await;
                    // 只移除本次失败的旧连接。并发任务可能已在该 slot 建立了
                    // 新连接，不能无条件清空它。
                    if current
                        .as_ref()
                        .is_some_and(|current| current.id == handle.id)
                    {
                        *current = None;
                    }
                    warn!(
                        manager = self.manager_name,
                        slot = slot_index,
                        connection_id = handle.id,
                        "Android native UDP proxy session closed; rebuilding only this pool slot: {err}"
                    );
                }
                Err(err) => return Err(AndroidAgentError::Io(err)),
            }
        }
        Err(AndroidAgentError::Connection(
            "Android native UDP proxy session failed".into(),
        ))
    }

    fn next_udp_session_slot(&self) -> usize {
        // AndroidAgentConfig 已把 pool size 夹到至少 1，因此这里不会除以 0。
        self.udp_next_index.fetch_add(1, Ordering::AcqRel) % self.udp_sessions.len()
    }

    async fn open_direct_tcp_stream(&self, address: Address) -> Result<AndroidYamuxTargetStream> {
        let target = target_label(&address);
        let timeout_duration = self.direct_tcp_stream_timeout();
        let connect = async {
            let _permit = self.direct_tcp_connects.acquire().await.map_err(|_| {
                AndroidAgentError::Connection("Android TCP connect limiter closed".into())
            })?;
            let connection = AuthenticatedConnection::connect(self.config.as_ref())
                .await
                .map_err(|err| AndroidAgentError::Connection(err.to_string()))?;
            let (stream, _stream_id) = connection
                .connect_to_target(address, TransportProtocol::Tcp)
                .await
                .map_err(|err| AndroidAgentError::Connection(err.to_string()))?;
            Ok(AndroidYamuxTargetStream::Direct(stream))
        };

        match tokio::time::timeout(timeout_duration, connect).await {
            Ok(result) => result,
            Err(_) => {
                warn!(
                    "Android TCP proxy stream timed out target={} after {:?}",
                    target, timeout_duration
                );
                android_log::warn(format!(
                    "Android TCP proxy stream timed out {target} after {}s",
                    timeout_duration.as_secs()
                ));
                Err(AndroidAgentError::Connection(format!(
                    "Android TCP proxy stream timed out after {} seconds",
                    timeout_duration.as_secs()
                )))
            }
        }
    }

    fn direct_tcp_stream_timeout(&self) -> Duration {
        Duration::from_secs(self.config.connect_timeout_secs.clamp(
            MIN_DIRECT_TCP_STREAM_TIMEOUT_SECS,
            MAX_DIRECT_TCP_STREAM_TIMEOUT_SECS,
        ))
    }

    async fn open_target_stream(
        &self,
        address: Address,
        transport: TransportProtocol,
    ) -> Result<AndroidYamuxTargetStream> {
        let max_sessions = self.yamux_target_size();
        let mut attempts = 0usize;

        loop {
            self.prune_closed_yamux_sessions().await;
            self.ensure_yamux_sessions(1.min(max_sessions)).await?;
            let session = match self.next_yamux_session_with_capacity().await {
                Some(session) => session,
                None => {
                    if self.ensure_additional_yamux_session(max_sessions).await? > 0 {
                        continue;
                    }
                    self.next_yamux_session().await.ok_or_else(|| {
                        AndroidAgentError::Connection(
                            "no available Android Yamux proxy session".into(),
                        )
                    })?
                }
            };

            let connect = if session.connection.has_immediate_stream_capacity() {
                session
                    .connection
                    .try_connect_to_target(address.clone(), transport)
                    .await
            } else {
                session
                    .connection
                    .connect_to_target(address.clone(), transport)
                    .await
            };

            match connect {
                Ok((stream, _stream_id)) => return Ok(AndroidYamuxTargetStream::Yamux(stream)),
                Err(err) => {
                    let message = err.to_string();
                    if is_yamux_session_capacity_error(&message) {
                        if self.ensure_additional_yamux_session(max_sessions).await? > 0 {
                            continue;
                        }
                        attempts += 1;
                        if attempts >= max_sessions.max(3) {
                            return Err(AndroidAgentError::Connection(message));
                        }
                        tokio::task::yield_now().await;
                        continue;
                    }

                    if is_yamux_actual_target_connect_error(&message) {
                        return Err(AndroidAgentError::Connection(message));
                    }
                    warn!(
                        "Android {} Yamux session {} unusable; retrying: {message}",
                        self.manager_name, session.id
                    );
                    android_log::warn(format!(
                        "Android {} Yamux session unusable: {message}",
                        self.manager_name
                    ));
                    self.remove_yamux_session(session.id).await;
                    attempts += 1;
                    if attempts >= max_sessions.max(3) {
                        return Err(AndroidAgentError::Connection(message));
                    }
                }
            }
        }
    }

    async fn ensure_yamux_sessions(&self, target_size: usize) -> Result<usize> {
        if self.shutdown.is_cancelled() || target_size == 0 {
            return Ok(0);
        }

        self.prune_closed_yamux_sessions().await;

        if self.yamux_sessions.lock().await.len() >= target_size {
            return Ok(0);
        }

        let _guard = self.yamux_refill_lock.lock().await;
        let current_size = self.yamux_sessions.lock().await.len();
        if current_size >= target_size {
            return Ok(0);
        }

        let to_create = target_size - current_size;
        debug!(
            "refilling Android {}: creating {} Yamux sessions (current={})",
            self.manager_name, to_create, current_size
        );

        let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SESSION_CONNECTS));
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..to_create {
            let config = self.config.clone();
            let semaphore = semaphore.clone();
            let transport = self.yamux_transport;
            let yamux_settings = config.yamux.udp_settings();
            let session_id = self.yamux_next_session_id.fetch_add(1, Ordering::AcqRel);
            set.spawn(async move {
                let _permit = semaphore.acquire().await.ok();
                YamuxClientConnection::connect_for(config.as_ref(), transport, yamux_settings)
                    .await
                    .map(|connection| AndroidYamuxSession {
                        id: session_id,
                        connection,
                    })
                    .map_err(|err| AndroidAgentError::Connection(err.to_string()))
            });
        }

        let mut success_count = 0usize;
        let mut failure_count = 0usize;
        let mut last_error = None;
        while let Some(result) = set.join_next().await {
            match result {
                Ok(Ok(session)) => {
                    let mut sessions = self.yamux_sessions.lock().await;
                    if sessions.len() >= target_size {
                        set.abort_all();
                        break;
                    }
                    sessions.push(session);
                    success_count += 1;
                }
                Ok(Err(err)) => {
                    debug!(
                        "failed to create Android {} Yamux session: {err}",
                        self.manager_name
                    );
                    failure_count += 1;
                    last_error = Some(err);
                }
                Err(err) if err.is_cancelled() => {}
                Err(err) => warn!(
                    "Android {} Yamux refill join error: {err}",
                    self.manager_name
                ),
            }
        }

        if success_count == 0 && self.yamux_sessions.lock().await.is_empty() {
            let err = last_error.unwrap_or_else(|| {
                AndroidAgentError::Connection("failed to create Android Yamux session".into())
            });
            warn!(
                "failed to refill Android {} Yamux: {err}",
                self.manager_name
            );
            android_log::warn(format!(
                "Android {} Yamux refill failed: {err}",
                self.manager_name
            ));
            return Err(err);
        }

        if failure_count > 0 {
            debug!(
                "partially refilled Android {} Yamux: {} succeeded, {} failed",
                self.manager_name, success_count, failure_count
            );
        }

        Ok(success_count)
    }

    async fn ensure_additional_yamux_session(&self, max_sessions: usize) -> Result<usize> {
        if self.shutdown.is_cancelled() || max_sessions == 0 {
            return Ok(0);
        }

        self.prune_closed_yamux_sessions().await;

        let current_size = self.yamux_sessions.lock().await.len();
        if current_size >= max_sessions {
            return Ok(0);
        }

        self.ensure_yamux_sessions((current_size + 1).min(max_sessions))
            .await
    }

    async fn next_yamux_session_with_capacity(&self) -> Option<AndroidYamuxSession> {
        let sessions = self.yamux_sessions.lock().await;
        if sessions.is_empty() {
            return None;
        }

        let start = self.yamux_next_index.fetch_add(1, Ordering::AcqRel) % sessions.len();
        for offset in 0..sessions.len() {
            let index = (start + offset) % sessions.len();
            if sessions[index].connection.has_immediate_stream_capacity() {
                return Some(sessions[index].clone());
            }
        }

        None
    }

    async fn next_yamux_session(&self) -> Option<AndroidYamuxSession> {
        let sessions = self.yamux_sessions.lock().await;
        if sessions.is_empty() {
            return None;
        }
        let index = self.yamux_next_index.fetch_add(1, Ordering::AcqRel) % sessions.len();
        for offset in 0..sessions.len() {
            let index = (index + offset) % sessions.len();
            if !sessions[index].connection.is_closed() {
                return Some(sessions[index].clone());
            }
        }

        None
    }

    async fn remove_yamux_session(&self, session_id: usize) {
        let removed = {
            let mut sessions = self.yamux_sessions.lock().await;
            sessions
                .iter()
                .position(|session| session.id == session_id)
                .map(|index| sessions.remove(index))
        };

        if let Some(session) = removed {
            session.connection.close().await;
        }
    }

    async fn prune_closed_yamux_sessions(&self) -> usize {
        let removed = {
            let mut sessions = self.yamux_sessions.lock().await;
            let mut removed = Vec::new();
            let mut index = 0usize;
            while index < sessions.len() {
                if sessions[index].connection.is_closed() {
                    removed.push(sessions.remove(index));
                } else {
                    index += 1;
                }
            }
            removed
        };

        for session in &removed {
            debug!(
                "pruning closed Android {} Yamux session {}",
                self.manager_name, session.id
            );
            session.connection.close().await;
        }

        removed.len()
    }

    fn yamux_target_size(&self) -> usize {
        match self.yamux_transport {
            TransportProtocol::Udp => self.config.yamux.udp_session_count(),
            TransportProtocol::Tcp => 0,
        }
    }
}

fn proxy_stream_route(
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

fn is_native_udp_timeout(error: &AndroidAgentError) -> bool {
    match error {
        AndroidAgentError::Io(error) => error.kind() == io::ErrorKind::TimedOut,
        AndroidAgentError::Connection(message) => {
            message.contains("UDP CONNECT 响应超时")
                || message.contains("原生 UDP 认证响应超时")
                || message.contains("连接原生 UDP proxy 超时")
        }
        _ => false,
    }
}

pub enum AndroidYamuxTargetStream {
    Direct(ClientStream<TcpStream>),
    Yamux(YamuxClientStream),
    Udp(UdpClientStream),
}

impl AndroidYamuxTargetStream {
    pub fn is_native_udp(&self) -> bool {
        matches!(self, Self::Udp(_))
    }
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

fn is_yamux_actual_target_connect_error(message: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_AGENT_CONFIG: &str = r#"{
        "proxy_addrs": ["127.0.0.1:8080"],
        "username": "user1",
        "private_key_pem": "key"
    }"#;

    #[test]
    fn yamux_session_errors_do_not_close_session_for_target_timeouts() {
        assert!(is_yamux_actual_target_connect_error(
            YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE
        ));
        assert!(is_yamux_actual_target_connect_error("连接目标响应超时"));
        assert!(!is_yamux_actual_target_connect_error(
            YAMUX_OPEN_STREAM_TIMEOUT_MESSAGE
        ));
        assert!(!is_yamux_actual_target_connect_error(
            YAMUX_SESSION_STREAM_CAPACITY_EXHAUSTED_MESSAGE
        ));
    }

    #[test]
    fn actual_target_connect_error_is_reported_directly() {
        assert!(is_yamux_actual_target_connect_error(
            "连接失败: Connection refused"
        ));
    }

    #[test]
    fn udp_session_pool_round_robins_across_independent_sockets() {
        let config: AndroidAgentConfig = serde_json::from_str(MINIMAL_AGENT_CONFIG).unwrap();
        let manager =
            AndroidYamuxSessionManager::new_udp(Arc::new(config), CancellationToken::new());

        assert_eq!(manager.udp_sessions.len(), 4);
        let slots: Vec<_> = (0..10).map(|_| manager.next_udp_session_slot()).collect();
        assert_eq!(slots, vec![0, 1, 2, 3, 0, 1, 2, 3, 0, 1]);
    }

    #[test]
    fn udp_mode_routes_only_udp_over_native_udp() {
        assert_eq!(
            proxy_stream_route(
                TransportMode::Udp,
                TransportProtocol::Tcp,
                TransportProtocol::Tcp,
            ),
            Some(ProxyStreamRoute::DirectTcp)
        );
        assert_eq!(
            proxy_stream_route(
                TransportMode::Udp,
                TransportProtocol::Udp,
                TransportProtocol::Udp,
            ),
            Some(ProxyStreamRoute::NativeUdp)
        );
    }

    #[test]
    fn tcp_mode_keeps_udp_on_yamux_and_tcp_on_direct_framed_tcp() {
        assert_eq!(
            proxy_stream_route(
                TransportMode::Tcp,
                TransportProtocol::Tcp,
                TransportProtocol::Tcp,
            ),
            Some(ProxyStreamRoute::DirectTcp)
        );
        assert_eq!(
            proxy_stream_route(
                TransportMode::Tcp,
                TransportProtocol::Udp,
                TransportProtocol::Udp,
            ),
            Some(ProxyStreamRoute::Yamux)
        );
    }

    #[test]
    fn auto_mode_routes_udp_through_runtime_fallback_path() {
        assert_eq!(
            proxy_stream_route(
                TransportMode::Auto,
                TransportProtocol::Udp,
                TransportProtocol::Udp,
            ),
            Some(ProxyStreamRoute::Auto)
        );
        assert!(is_native_udp_timeout(&AndroidAgentError::Connection(
            "UDP CONNECT 响应超时".into()
        )));
        assert!(!is_native_udp_timeout(&AndroidAgentError::Connection(
            "authentication failed".into()
        )));
    }

    #[test]
    fn tcp_manager_never_allocates_a_native_udp_pool() {
        let config: AndroidAgentConfig = serde_json::from_str(MINIMAL_AGENT_CONFIG).unwrap();
        let manager =
            AndroidYamuxSessionManager::new_tcp_direct(Arc::new(config), CancellationToken::new());

        assert!(manager.udp_sessions.is_empty());
    }

    #[test]
    fn manager_rejects_cross_protocol_routes() {
        assert_eq!(
            proxy_stream_route(
                TransportMode::Udp,
                TransportProtocol::Tcp,
                TransportProtocol::Udp,
            ),
            None
        );
        assert_eq!(
            proxy_stream_route(
                TransportMode::Udp,
                TransportProtocol::Udp,
                TransportProtocol::Tcp,
            ),
            None
        );
    }

    #[test]
    fn auto_fallback_state_is_isolated_per_udp_session_slot() {
        let config: AndroidAgentConfig = serde_json::from_str(
            r#"{
                "proxy_addrs": ["127.0.0.1:8080"],
                "username": "user1",
                "private_key_pem": "key",
                "transport_mode": "auto"
            }"#,
        )
        .unwrap();
        let manager =
            AndroidYamuxSessionManager::new_udp(Arc::new(config), CancellationToken::new());

        assert_eq!(manager.auto_udp_fallback_to_yamux.len(), 4);
        manager.auto_udp_fallback_to_yamux[2].store(true, Ordering::Release);
        assert!(!manager.auto_udp_fallback_to_yamux[1].load(Ordering::Acquire));
        assert!(manager.auto_udp_fallback_to_yamux[2].load(Ordering::Acquire));
        assert!(!manager.auto_udp_fallback_to_yamux[3].load(Ordering::Acquire));
    }
}
