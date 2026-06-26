use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

#[cfg(test)]
use common::YAMUX_OPEN_STREAM_TIMEOUT_MESSAGE;
use common::{
    AuthenticatedConnection, ClientStream, YAMUX_SESSION_STREAM_CAPACITY_EXHAUSTED_MESSAGE,
    YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE, YamuxClientConnection, YamuxClientStream,
};
use protocol::{Address, TransportProtocol};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::android_log;
use crate::config::AndroidAgentConfig;
use crate::error::{AndroidAgentError, Result};

const MAX_CONCURRENT_SESSION_CONNECTS: usize = 10;

#[derive(Clone)]
struct AndroidYamuxSession {
    id: usize,
    connection: YamuxClientConnection,
}

pub struct AndroidYamuxSessionManager {
    config: Arc<AndroidAgentConfig>,
    shutdown: CancellationToken,
    manager_name: &'static str,
    yamux_transport: TransportProtocol,
    yamux_sessions: Mutex<Vec<AndroidYamuxSession>>,
    yamux_refill_lock: Mutex<()>,
    yamux_next_index: AtomicUsize,
    yamux_next_session_id: AtomicUsize,
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
            "udp_yamux_sessions",
            TransportProtocol::Udp,
        )
    }

    fn new_for_transport(
        config: Arc<AndroidAgentConfig>,
        shutdown: CancellationToken,
        manager_name: &'static str,
        yamux_transport: TransportProtocol,
    ) -> Arc<Self> {
        Arc::new(Self {
            config,
            shutdown,
            manager_name,
            yamux_transport,
            yamux_sessions: Mutex::new(Vec::new()),
            yamux_refill_lock: Mutex::new(()),
            yamux_next_index: AtomicUsize::new(0),
            yamux_next_session_id: AtomicUsize::new(0),
        })
    }

    pub async fn connect_to_target(
        &self,
        address: Address,
        transport: TransportProtocol,
    ) -> Result<AndroidYamuxTargetStream> {
        if transport == TransportProtocol::Tcp && self.yamux_transport == TransportProtocol::Tcp {
            return self.open_direct_tcp_stream(address).await;
        }

        if transport != self.yamux_transport {
            return Err(AndroidAgentError::Connection(format!(
                "Android {} only supports {:?} proxy streams",
                self.manager_name, self.yamux_transport
            )));
        }
        self.open_target_stream(address, transport).await
    }

    async fn open_direct_tcp_stream(&self, address: Address) -> Result<AndroidYamuxTargetStream> {
        let connection = AuthenticatedConnection::connect(self.config.as_ref())
            .await
            .map_err(|err| AndroidAgentError::Connection(err.to_string()))?;
        let (stream, _stream_id) = connection
            .connect_to_target(address, TransportProtocol::Tcp)
            .await
            .map_err(|err| AndroidAgentError::Connection(err.to_string()))?;
        Ok(AndroidYamuxTargetStream::Direct(stream))
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

pub enum AndroidYamuxTargetStream {
    Direct(ClientStream<TcpStream>),
    Yamux(YamuxClientStream),
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
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Direct(stream) => Pin::new(stream).poll_flush(cx),
            Self::Yamux(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Direct(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Yamux(stream) => Pin::new(stream).poll_shutdown(cx),
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
