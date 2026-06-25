//! Yamux 客户端外层连接。
//!
//! 外层 raw TCP 只承载 tokio-yamux session。每个真实目标连接通过打开子流，
//! 然后在子流内执行完整的 PPAASS Auth/Connect/Data 协议完成。

use futures::StreamExt;
use protocol::{Address, CompressionMode, TransportProtocol};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_yamux::{session::Session, stream::StreamHandle};
use tracing::{debug, info};

use crate::YamuxSettings;
use crate::spawn_guarded;

use super::authenticated::{AuthenticatedConnection, connect_tcp_stream};
use super::config::ClientConnectionConfig;
use super::stream::ClientStream;

pub const YAMUX_OPEN_STREAM_TIMEOUT_MESSAGE: &str = "Yamux open stream timeout";
pub const YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE: &str =
    "Yamux target connect response timeout";
const MAX_CONCURRENT_OPEN_STREAMS_PER_SESSION: usize = 16;

#[derive(Clone)]
pub struct YamuxClientConnection {
    // tokio-yamux 控制句柄，用于打开新的出站子流。
    control: tokio_yamux::Control,
    settings: YamuxSettings,
    connect_response_timeout: Duration,
    open_stream_permits: Arc<Semaphore>,
    // 控制同一外层 session 中存活的业务子流数量。
    stream_permits: Arc<Semaphore>,
    transport: TransportProtocol,
    auth_config: Arc<YamuxSubstreamAuthConfig>,
}

#[derive(Debug)]
struct YamuxSubstreamAuthConfig {
    username: String,
    private_key_pem: String,
    timeout: Duration,
    compression_mode: CompressionMode,
}

impl ClientConnectionConfig for YamuxSubstreamAuthConfig {
    fn remote_addr(&self) -> String {
        String::new()
    }

    fn username(&self) -> String {
        self.username.clone()
    }

    fn private_key_pem(&self) -> Result<String, String> {
        Ok(self.private_key_pem.clone())
    }

    fn timeout_duration(&self) -> Duration {
        self.timeout
    }

    fn compression_mode(&self) -> CompressionMode {
        self.compression_mode
    }
}

impl YamuxClientConnection {
    pub async fn connect<C>(config: &C) -> std::io::Result<Self>
    where
        C: ClientConnectionConfig,
    {
        Self::connect_with_settings(config, YamuxSettings::default()).await
    }

    pub async fn connect_with_settings<C>(
        config: &C,
        settings: YamuxSettings,
    ) -> std::io::Result<Self>
    where
        C: ClientConnectionConfig,
    {
        Self::connect_for(config, TransportProtocol::Tcp, settings).await
    }

    pub async fn connect_for<C>(
        config: &C,
        transport: TransportProtocol,
        settings: YamuxSettings,
    ) -> std::io::Result<Self>
    where
        C: ClientConnectionConfig,
    {
        let connect_response_timeout = config
            .timeout_duration()
            .max(settings.open_stream_timeout)
            .saturating_add(Duration::from_secs(5));
        let auth_config = Arc::new(YamuxSubstreamAuthConfig {
            username: config.username(),
            private_key_pem: config
                .private_key_pem()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
            timeout: config.timeout_duration(),
            compression_mode: config.compression_mode(),
        });
        // 外层 session 是 raw TCP + Yamux；PPAASS 加密协议只在每个子 stream 内执行。
        let outer_stream = connect_tcp_stream(config).await?;
        let mut session = Session::new_client(outer_stream, settings.to_tokio_config());
        let control = session.control();
        let open_stream_permits = Arc::new(Semaphore::new(
            settings
                .max_streams_per_session
                .clamp(1, MAX_CONCURRENT_OPEN_STREAMS_PER_SESSION),
        ));
        let stream_permits = Arc::new(Semaphore::new(settings.max_streams_per_session));

        spawn_guarded("yamux client session", async move {
            // agent 侧只主动打开子流；如果收到入站子流，说明对端行为不符合当前协议约定。
            while let Some(result) = session.next().await {
                match result {
                    Ok(mut inbound_stream) => {
                        debug!("收到意外的客户端入站 Yamux 子流 id={}", inbound_stream.id());
                        let _ = inbound_stream.shutdown().await;
                    }
                    Err(err) => {
                        debug!("Yamux 客户端会话已结束 transport={transport:?}: {err}");
                        break;
                    }
                }
            }
        });

        info!("已建立 {:?} raw Yamux 外层连接", transport);
        Ok(Self {
            control,
            settings,
            connect_response_timeout,
            open_stream_permits,
            stream_permits,
            transport,
            auth_config,
        })
    }

    pub async fn connect_to_target(
        &self,
        address: Address,
        transport: TransportProtocol,
    ) -> std::io::Result<(YamuxClientStream, String)> {
        if transport != self.transport {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Yamux client connection transport mismatch",
            ));
        }
        if self.transport == TransportProtocol::Tcp && matches!(address, Address::UdpRelay) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Yamux substream target is not valid for this session",
            ));
        }

        // stream_permit 覆盖业务子流整个生命周期；YamuxClientStream Drop 后释放。
        let permit = self
            .stream_permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| std::io::Error::other("Yamux session has been closed"))?;
        // open_stream 本身也限流，避免短时间大量并发 open 卡住 session control。
        let open_permit = self
            .open_stream_permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| std::io::Error::other("Yamux session has been closed"))?;
        let mut control = self.control.clone();
        let stream = tokio::time::timeout(self.settings.open_stream_timeout, control.open_stream())
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    YAMUX_OPEN_STREAM_TIMEOUT_MESSAGE,
                )
            })?
            .map_err(|err| std::io::Error::other(err.to_string()))?;
        drop(open_permit);

        let (client_stream, request_id) = tokio::time::timeout(self.connect_response_timeout, async {
            debug!("通过 Yamux 子流执行 PPAASS 认证并连接目标：address={address:?}, transport={transport:?}");
            let auth_conn =
                AuthenticatedConnection::authenticate_stream(stream, self.auth_config.as_ref())
                    .await?;
            auth_conn.connect_to_target(address, transport).await
        })
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE,
            )
        })??;

        Ok((YamuxClientStream::new(client_stream, permit), request_id))
    }

    pub async fn close(&self) {
        let mut control = self.control.clone();
        control.close().await;
    }
}

pub struct YamuxClientStream {
    inner: ClientStream<StreamHandle>,
    _permit: OwnedSemaphorePermit,
}

impl YamuxClientStream {
    fn new(inner: ClientStream<StreamHandle>, permit: OwnedSemaphorePermit) -> Self {
        Self {
            inner,
            _permit: permit,
        }
    }
}

impl AsyncRead for YamuxClientStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for YamuxClientStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Unpin for YamuxClientStream {}
