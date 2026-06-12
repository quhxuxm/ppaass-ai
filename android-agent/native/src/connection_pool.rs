use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use common::{
    AuthenticatedConnection, ClientStream, DatagramStreamIo, TcpTransportMode,
    YAMUX_OPEN_STREAM_TIMEOUT_MESSAGE, YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE,
    YamuxClientConnection, YamuxClientStream, spawn_guarded,
};
use protocol::{Address, TransportProtocol};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Mutex, Notify};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::android_log;
use crate::config::AndroidAgentConfig;
use crate::error::{AndroidAgentError, Result};

const MAX_CONCURRENT_POOL_CONNECTS: usize = 5;
const POOL_MAX_CONNECTION_AGE: Duration = Duration::from_secs(90);

struct PooledConnection {
    connection: AuthenticatedConnection,
    created_at: Instant,
}

#[derive(Clone)]
struct AndroidYamuxSession {
    id: usize,
    connection: YamuxClientConnection,
}

pub struct AndroidConnectionPool {
    config: Arc<AndroidAgentConfig>,
    shutdown: CancellationToken,
    pool_size: usize,
    pool_name: &'static str,
    connections: Mutex<VecDeque<PooledConnection>>,
    refill_notify: Notify,
    use_yamux: bool,
    yamux_mode: Option<TcpTransportMode>,
    yamux_transport: Option<TransportProtocol>,
    yamux_outer_address: Option<Address>,
    yamux_sessions: Mutex<Vec<AndroidYamuxSession>>,
    yamux_refill_lock: Mutex<()>,
    yamux_next_index: AtomicUsize,
    yamux_next_session_id: AtomicUsize,
}

impl AndroidConnectionPool {
    pub fn new(
        config: Arc<AndroidAgentConfig>,
        shutdown: CancellationToken,
        pool_size: usize,
        pool_name: &'static str,
    ) -> Arc<Self> {
        let (yamux_mode, yamux_transport, yamux_outer_address) = match pool_name {
            "tcp_pool" => (
                Some(config.transport.tcp_mode),
                Some(TransportProtocol::Tcp),
                Some(Address::TcpYamux),
            ),
            "udp_pool" => (
                Some(config.transport.udp_mode),
                Some(TransportProtocol::Udp),
                Some(Address::UdpYamux),
            ),
            _ => (None, None, None),
        };
        let use_yamux = yamux_mode
            .map(|mode| mode != TcpTransportMode::Legacy)
            .unwrap_or(false);
        Arc::new(Self {
            config,
            shutdown,
            pool_size,
            pool_name,
            connections: Mutex::new(VecDeque::new()),
            refill_notify: Notify::new(),
            use_yamux,
            yamux_mode,
            yamux_transport,
            yamux_outer_address,
            yamux_sessions: Mutex::new(Vec::new()),
            yamux_refill_lock: Mutex::new(()),
            yamux_next_index: AtomicUsize::new(0),
            yamux_next_session_id: AtomicUsize::new(0),
        })
    }

    pub async fn prewarm(self: &Arc<Self>) {
        if self.shutdown.is_cancelled() {
            return;
        }
        info!(
            "prewarming Android {} with {} connections",
            self.pool_name, self.pool_size
        );
        if self.use_yamux {
            match self.ensure_yamux_sessions(self.yamux_target_size()).await {
                Ok(success_count) => {
                    info!(
                        "Android {} Yamux prewarmed {} connections",
                        self.pool_name, success_count
                    );
                    return;
                }
                Err(err) if self.yamux_mode == Some(TcpTransportMode::Auto) => warn!(
                    "failed to prewarm Android {} Yamux, falling back to legacy: {err}",
                    self.pool_name
                ),
                Err(err) => {
                    warn!("failed to prewarm Android {} Yamux: {err}", self.pool_name);
                    android_log::warn(format!(
                        "Android {} Yamux prewarm failed: {err}",
                        self.pool_name
                    ));
                    return;
                }
            }
        }

        let success_count = self.fill_to_target().await;
        info!(
            "Android {} prewarmed {} connections",
            self.pool_name, success_count
        );

        let pool = self.clone();
        spawn_guarded("android connection pool refill", async move {
            pool.refill_task().await;
        });
    }

    pub async fn get_connected_stream(
        &self,
        address: Address,
        transport: TransportProtocol,
    ) -> Result<AndroidProxyStream> {
        if self.use_yamux && self.yamux_transport == Some(transport) {
            match self
                .get_yamux_connected_stream(address.clone(), transport)
                .await
            {
                Ok(stream) => return Ok(stream),
                Err(err)
                    if self.yamux_mode == Some(TcpTransportMode::Auto)
                        && should_fallback_yamux_error(&err) =>
                {
                    warn!(
                        "Android {} Yamux unavailable, falling back to legacy: {err}",
                        self.pool_name
                    );
                }
                Err(err) => return Err(err),
            }
        }

        loop {
            let pooled = {
                let mut connections = self.connections.lock().await;
                connections.pop_front()
            };
            self.refill_notify.notify_one();

            match pooled {
                Some(pooled) if !pooled.is_expired() => {
                    debug!("using prewarmed Android {} connection", self.pool_name);
                    match pooled
                        .connection
                        .connect_to_target(address.clone(), transport)
                        .await
                    {
                        Ok((stream, _stream_id)) => return Ok(AndroidProxyStream::Framed(stream)),
                        Err(err) => {
                            let message = err.to_string();
                            if message.starts_with("连接失败:") {
                                return Err(AndroidAgentError::Connection(message));
                            }
                            warn!(
                                "Android {} connection was unusable; retrying: {message}",
                                self.pool_name
                            );
                        }
                    }
                }
                Some(_) => {
                    debug!("discarding expired Android {} connection", self.pool_name);
                    continue;
                }
                None => {
                    debug!(
                        "Android {} empty; creating connection on demand",
                        self.pool_name
                    );
                    let connection = self.create_connection().await?;
                    let (stream, _stream_id) = connection
                        .connect_to_target(address, transport)
                        .await
                        .map_err(|err| AndroidAgentError::Connection(err.to_string()))?;
                    return Ok(AndroidProxyStream::Framed(stream));
                }
            }
        }
    }

    async fn refill_task(self: Arc<Self>) {
        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => break,
                _ = self.refill_notify.notified() => {}
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
            }
            if self.shutdown.is_cancelled() {
                break;
            }
            self.fill_to_target().await;
        }
    }

    async fn fill_to_target(&self) -> usize {
        if self.shutdown.is_cancelled() {
            return 0;
        }
        if self.pool_size == 0 {
            return 0;
        }

        let current_size = self.connection_count().await;
        if current_size >= self.pool_size {
            return 0;
        }

        let to_create = self.pool_size - current_size;
        debug!(
            "refilling Android {}: creating {} connections (current={})",
            self.pool_name, to_create, current_size
        );

        let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_POOL_CONNECTS));
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..to_create {
            let config = self.config.clone();
            let semaphore = semaphore.clone();
            set.spawn(async move {
                let _permit = semaphore.acquire().await.ok();
                create_pooled_connection(config).await
            });
        }

        let mut success_count = 0;
        while let Some(result) = set.join_next().await {
            match result {
                Ok(Ok(connection)) => {
                    if self.try_add_connection(connection).await {
                        success_count += 1;
                    } else {
                        set.abort_all();
                        break;
                    }
                }
                Ok(Err(err)) => {
                    warn!(
                        "failed to create Android {} connection: {err}",
                        self.pool_name
                    );
                    android_log::warn(format!(
                        "Android {} connection create failed: {err}",
                        self.pool_name
                    ));
                }
                Err(err) if err.is_cancelled() => {}
                Err(err) => warn!("Android {} refill task join error: {err}", self.pool_name),
            }
        }
        success_count
    }

    async fn connection_count(&self) -> usize {
        self.connections.lock().await.len()
    }

    async fn try_add_connection(&self, connection: PooledConnection) -> bool {
        let mut connections = self.connections.lock().await;
        if connections.len() >= self.pool_size {
            return false;
        }
        connections.push_back(connection);
        true
    }

    async fn create_connection(&self) -> Result<AuthenticatedConnection> {
        AuthenticatedConnection::authenticate_only(self.config.as_ref())
            .await
            .map_err(|err| AndroidAgentError::Connection(err.to_string()))
    }

    async fn get_yamux_connected_stream(
        &self,
        address: Address,
        transport: TransportProtocol,
    ) -> Result<AndroidProxyStream> {
        let target_size = self.yamux_target_size();
        let mut attempts = 0usize;

        loop {
            self.ensure_yamux_sessions(target_size).await?;
            let session = self.next_yamux_session().await.ok_or_else(|| {
                AndroidAgentError::Connection("no available Android Yamux proxy session".into())
            })?;

            match session
                .connection
                .connect_to_target(address.clone(), transport)
                .await
            {
                Ok((stream, _stream_id)) => {
                    return if transport == TransportProtocol::Udp {
                        Ok(AndroidProxyStream::YamuxDatagram(DatagramStreamIo::new(
                            stream,
                        )))
                    } else {
                        Ok(AndroidProxyStream::Yamux(stream))
                    };
                }
                Err(err) => {
                    let message = err.to_string();
                    if is_yamux_actual_target_connect_error(&message) {
                        return Err(AndroidAgentError::Connection(message));
                    }
                    warn!(
                        "Android {} Yamux session {} unusable; retrying: {message}",
                        self.pool_name, session.id
                    );
                    android_log::warn(format!(
                        "Android {} Yamux session unusable: {message}",
                        self.pool_name
                    ));
                    session.connection.close().await;
                    self.remove_yamux_session(session.id).await;
                    attempts += 1;
                    if attempts >= target_size.max(3) {
                        return Err(AndroidAgentError::Connection(message));
                    }
                }
            }
        }
    }

    async fn ensure_yamux_sessions(&self, target_size: usize) -> Result<usize> {
        if target_size == 0 {
            return Ok(0);
        }

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
            "refilling Android {} Yamux: creating {} sessions (current={})",
            self.pool_name, to_create, current_size
        );

        let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_POOL_CONNECTS));
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..to_create {
            let config = self.config.clone();
            let semaphore = semaphore.clone();
            let outer_address = self.yamux_outer_address.clone().ok_or_else(|| {
                AndroidAgentError::Connection("Android Yamux outer address missing".to_string())
            })?;
            let transport = self.yamux_transport.ok_or_else(|| {
                AndroidAgentError::Connection("Android Yamux transport missing".to_string())
            })?;
            let yamux_settings = match transport {
                TransportProtocol::Udp => config.yamux.udp_settings(),
                TransportProtocol::Tcp => config.yamux.tcp_settings(),
            };
            let session_id = self.yamux_next_session_id.fetch_add(1, Ordering::AcqRel);
            set.spawn(async move {
                let _permit = semaphore.acquire().await.ok();
                YamuxClientConnection::connect_for(
                    config.as_ref(),
                    outer_address,
                    transport,
                    yamux_settings,
                )
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
                        self.pool_name
                    );
                    failure_count += 1;
                    last_error = Some(err);
                }
                Err(err) if err.is_cancelled() => {}
                Err(err) => warn!("Android {} Yamux refill join error: {err}", self.pool_name),
            }
        }

        if success_count == 0 && self.yamux_sessions.lock().await.is_empty() {
            let err = last_error.unwrap_or_else(|| {
                AndroidAgentError::Connection("failed to create Android Yamux session".into())
            });
            warn!("failed to refill Android {} Yamux: {err}", self.pool_name);
            android_log::warn(format!(
                "Android {} Yamux refill failed: {err}",
                self.pool_name
            ));
            return Err(err);
        }

        if failure_count > 0 {
            debug!(
                "partially refilled Android {} Yamux: {} succeeded, {} failed",
                self.pool_name, success_count, failure_count
            );
        }

        Ok(success_count)
    }

    async fn next_yamux_session(&self) -> Option<AndroidYamuxSession> {
        let sessions = self.yamux_sessions.lock().await;
        if sessions.is_empty() {
            return None;
        }
        let index = self.yamux_next_index.fetch_add(1, Ordering::AcqRel) % sessions.len();
        Some(sessions[index].clone())
    }

    async fn remove_yamux_session(&self, session_id: usize) {
        let mut sessions = self.yamux_sessions.lock().await;
        sessions.retain(|session| session.id != session_id);
    }

    fn yamux_target_size(&self) -> usize {
        match self.yamux_transport {
            Some(TransportProtocol::Udp) => self.config.yamux.udp_session_count(),
            _ => self.config.yamux.tcp_session_count(),
        }
    }
}

impl PooledConnection {
    fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= POOL_MAX_CONNECTION_AGE
    }
}

async fn create_pooled_connection(
    config: Arc<AndroidAgentConfig>,
) -> std::io::Result<PooledConnection> {
    let connection = AuthenticatedConnection::authenticate_only(config.as_ref()).await?;
    Ok(PooledConnection {
        connection,
        created_at: Instant::now(),
    })
}

pub enum AndroidProxyStream {
    Framed(ClientStream),
    Yamux(YamuxClientStream),
    YamuxDatagram(DatagramStreamIo<YamuxClientStream>),
}

impl AsyncRead for AndroidProxyStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Framed(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Yamux(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::YamuxDatagram(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for AndroidProxyStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Framed(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Yamux(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::YamuxDatagram(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Framed(stream) => Pin::new(stream).poll_flush(cx),
            Self::Yamux(stream) => Pin::new(stream).poll_flush(cx),
            Self::YamuxDatagram(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Framed(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Yamux(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::YamuxDatagram(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

impl Unpin for AndroidProxyStream {}

fn should_fallback_yamux_error(err: &AndroidAgentError) -> bool {
    match err {
        AndroidAgentError::Connection(message) => {
            is_yamux_session_error(message) || !is_yamux_actual_target_connect_error(message)
        }
        AndroidAgentError::Io(_) => true,
        _ => false,
    }
}

fn is_yamux_actual_target_connect_error(message: &str) -> bool {
    message.starts_with("连接失败:")
}

fn is_yamux_session_error(message: &str) -> bool {
    message == YAMUX_OPEN_STREAM_TIMEOUT_MESSAGE
        || message == YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE
        || message.contains("Yamux session")
        || message.contains("connection closed")
        || message.contains("broken pipe")
        || message.contains("reset")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yamux_timeouts_can_fallback_or_retry() {
        let err = AndroidAgentError::Connection(
            YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE.to_string(),
        );
        assert!(should_fallback_yamux_error(&err));
        assert!(is_yamux_session_error(
            YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE
        ));
        assert!(is_yamux_session_error(YAMUX_OPEN_STREAM_TIMEOUT_MESSAGE));
    }

    #[test]
    fn actual_target_connect_error_does_not_fallback() {
        let err = AndroidAgentError::Connection("连接失败: Connection refused".to_string());
        assert!(!should_fallback_yamux_error(&err));
        assert!(is_yamux_actual_target_connect_error(
            "连接失败: Connection refused"
        ));
    }
}
