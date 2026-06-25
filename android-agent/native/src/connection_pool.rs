use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

#[cfg(test)]
use common::{YAMUX_OPEN_STREAM_TIMEOUT_MESSAGE, YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE};
use common::{YamuxClientConnection, YamuxClientStream};
use protocol::{Address, TransportProtocol};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::android_log;
use crate::config::AndroidAgentConfig;
use crate::error::{AndroidAgentError, Result};

const MAX_CONCURRENT_POOL_CONNECTS: usize = 10;

#[derive(Clone)]
struct AndroidYamuxSession {
    id: usize,
    connection: YamuxClientConnection,
}

pub struct AndroidConnectionPool {
    config: Arc<AndroidAgentConfig>,
    shutdown: CancellationToken,
    pool_name: &'static str,
    yamux_transport: TransportProtocol,
    yamux_sessions: Mutex<Vec<AndroidYamuxSession>>,
    yamux_refill_lock: Mutex<()>,
    yamux_next_index: AtomicUsize,
    yamux_next_session_id: AtomicUsize,
}

impl AndroidConnectionPool {
    pub fn new(
        config: Arc<AndroidAgentConfig>,
        shutdown: CancellationToken,
        pool_name: &'static str,
    ) -> Arc<Self> {
        let yamux_transport = match pool_name {
            "udp_pool" => TransportProtocol::Udp,
            _ => TransportProtocol::Tcp,
        };
        Arc::new(Self {
            config,
            shutdown,
            pool_name,
            yamux_transport,
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
        let target_size = self.yamux_target_size();
        info!(
            "prewarming Android {} with {} Yamux sessions",
            self.pool_name, target_size
        );
        match self.ensure_yamux_sessions(target_size).await {
            Ok(success_count) => {
                info!(
                    "Android {} Yamux prewarmed {} sessions",
                    self.pool_name, success_count
                );
            }
            Err(err) => {
                warn!("failed to prewarm Android {} Yamux: {err}", self.pool_name);
                android_log::warn(format!(
                    "Android {} Yamux prewarm failed: {err}",
                    self.pool_name
                ));
            }
        }
    }

    pub async fn get_connected_stream(
        &self,
        address: Address,
        transport: TransportProtocol,
    ) -> Result<AndroidProxyStream> {
        if transport != self.yamux_transport {
            return Err(AndroidAgentError::Connection(format!(
                "Android {} only supports {:?} Yamux streams",
                self.pool_name, self.yamux_transport
            )));
        }
        self.get_yamux_connected_stream(address, transport).await
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
                Ok((stream, _stream_id)) => return Ok(AndroidProxyStream::Yamux(stream)),
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
        if self.shutdown.is_cancelled() || target_size == 0 {
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
            let transport = self.yamux_transport;
            let yamux_settings = match transport {
                TransportProtocol::Udp => config.yamux.udp_settings(),
                TransportProtocol::Tcp => config.yamux.tcp_settings(),
            };
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
            TransportProtocol::Udp => self.config.yamux.udp_session_count(),
            TransportProtocol::Tcp => self.config.yamux.tcp_session_count(),
        }
    }
}

pub enum AndroidProxyStream {
    Yamux(YamuxClientStream),
}

impl AsyncRead for AndroidProxyStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Yamux(stream) => Pin::new(stream).poll_read(cx, buf),
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
            Self::Yamux(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Yamux(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Yamux(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

impl Unpin for AndroidProxyStream {}

fn is_yamux_actual_target_connect_error(message: &str) -> bool {
    message.starts_with("连接失败:")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yamux_session_errors_are_not_target_connect_errors() {
        assert!(!is_yamux_actual_target_connect_error(
            YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE
        ));
        assert!(!is_yamux_actual_target_connect_error(
            YAMUX_OPEN_STREAM_TIMEOUT_MESSAGE
        ));
    }

    #[test]
    fn actual_target_connect_error_is_reported_directly() {
        assert!(is_yamux_actual_target_connect_error(
            "连接失败: Connection refused"
        ));
    }
}
