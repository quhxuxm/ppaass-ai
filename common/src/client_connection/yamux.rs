use futures::StreamExt;
use protocol::{
    Address, ConnectRequest, TransportProtocol, read_yamux_connect_response,
    write_yamux_connect_request,
};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_yamux::{session::Session, stream::StreamHandle};
use tracing::{debug, info};

use crate::YamuxSettings;

use super::authenticated::AuthenticatedConnection;
use super::config::ClientConnectionConfig;

#[derive(Clone)]
pub struct YamuxClientConnection {
    control: tokio_yamux::Control,
    settings: YamuxSettings,
    stream_permits: Arc<Semaphore>,
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
        let auth_conn = AuthenticatedConnection::authenticate_only(config).await?;
        let (outer_stream, outer_stream_id) = auth_conn
            .connect_to_target(Address::TcpYamux, TransportProtocol::Tcp)
            .await?;
        let mut session = Session::new_client(outer_stream, settings.to_tokio_config());
        let control = session.control();
        let stream_permits = Arc::new(Semaphore::new(settings.max_streams_per_session));

        tokio::spawn(async move {
            while let Some(result) = session.next().await {
                match result {
                    Ok(mut inbound_stream) => {
                        debug!("收到意外的客户端入站 Yamux 子流 id={}", inbound_stream.id());
                        let _ = inbound_stream.shutdown().await;
                    }
                    Err(err) => {
                        debug!("Yamux 客户端会话已结束 outer_stream_id={outer_stream_id}: {err}");
                        break;
                    }
                }
            }
        });

        info!("已建立 TCP Yamux 外层连接");
        Ok(Self {
            control,
            settings,
            stream_permits,
        })
    }

    pub async fn connect_to_target(
        &self,
        address: Address,
        transport: TransportProtocol,
    ) -> std::io::Result<(YamuxClientStream, String)> {
        if transport != TransportProtocol::Tcp {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Yamux client connection only supports TCP transport",
            ));
        }
        if matches!(address, Address::TcpYamux | Address::UdpRelay) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Yamux substream target must be a real TCP target",
            ));
        }

        let request_id = crate::generate_id();
        let request = ConnectRequest {
            request_id: request_id.clone(),
            address: address.clone(),
            transport,
        };

        let permit = self
            .stream_permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| std::io::Error::other("Yamux session has been closed"))?;
        let mut control = self.control.clone();
        let stream = tokio::time::timeout(self.settings.open_stream_timeout, async {
            let mut stream = control
                .open_stream()
                .await
                .map_err(|err| std::io::Error::other(err.to_string()))?;

            debug!("通过 Yamux 子流发送连接请求：{request:?}");
            write_yamux_connect_request(&mut stream, &request).await?;
            let response = read_yamux_connect_response(&mut stream).await?;
            debug!("Yamux 子流收到连接响应：{response:?}");

            if !response.success {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    format!("连接失败: {}", response.message),
                ));
            }

            Ok(stream)
        })
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "Yamux open stream timeout")
        })??;

        Ok((YamuxClientStream::new(stream, permit), request_id))
    }

    pub async fn close(&self) {
        let mut control = self.control.clone();
        control.close().await;
    }
}

pub struct YamuxClientStream {
    inner: StreamHandle,
    _permit: OwnedSemaphorePermit,
}

impl YamuxClientStream {
    fn new(inner: StreamHandle, permit: OwnedSemaphorePermit) -> Self {
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
