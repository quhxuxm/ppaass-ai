//! Android native TCP relay helper.
//!
//! Android TUN TCP and the optional Android HTTP proxy CONNECT path both end up
//! as "local client stream <-> remote/proxy stream". Keep them on the same
//! Tokio copy_bidirectional implementation so half-close behavior does not drift
//! between entry points.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use common::TCP_RELAY_COPY_BUFFER_SIZE;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TcpRelayStats {
    pub(crate) client_to_remote: u64,
    pub(crate) remote_to_client: u64,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TcpRelayOptions<'a> {
    pub(crate) label: &'a str,
}

impl<'a> TcpRelayOptions<'a> {
    pub(crate) fn tun(label: &'a str) -> Self {
        Self { label }
    }

    pub(crate) fn http_proxy(label: &'a str) -> Self {
        Self { label }
    }
}

struct AndroidTcpRelayIo<'a, S> {
    inner: &'a mut S,
    label: &'a str,
}

impl<'a, S> AndroidTcpRelayIo<'a, S> {
    fn new(inner: &'a mut S, label: &'a str) -> Self {
        Self { inner, label }
    }
}

impl<S> AsyncRead for AndroidTcpRelayIo<'_, S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut *this.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for AndroidTcpRelayIo<'_, S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut *this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut *this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut *this.inner).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) if can_ignore_tcp_shutdown_error(&error) => {
                debug!(
                    "Android TCP relay ignored {} shutdown error: {}",
                    this.label, error
                );
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub(crate) async fn relay_tcp_bidirectional<C, R>(
    client: &mut C,
    remote: &mut R,
    options: TcpRelayOptions<'_>,
) -> io::Result<TcpRelayStats>
where
    C: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    let mut client_io = AndroidTcpRelayIo::new(client, options.label);
    let mut remote_io = AndroidTcpRelayIo::new(remote, options.label);
    let (client_to_remote, remote_to_client) = tokio::io::copy_bidirectional_with_sizes(
        &mut client_io,
        &mut remote_io,
        TCP_RELAY_COPY_BUFFER_SIZE,
        TCP_RELAY_COPY_BUFFER_SIZE,
    )
    .await?;

    Ok(TcpRelayStats {
        client_to_remote,
        remote_to_client,
    })
}

fn can_ignore_tcp_shutdown_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset | io::ErrorKind::NotConnected
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::task::Waker;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn tun_relay_keeps_response_after_client_half_close() {
        assert_half_close_keeps_response(TcpRelayOptions::tun("test")).await;
    }

    #[tokio::test]
    async fn http_proxy_relay_keeps_response_after_client_half_close() {
        assert_half_close_keeps_response(TcpRelayOptions::http_proxy("test")).await;
    }

    async fn assert_half_close_keeps_response(options: TcpRelayOptions<'static>) {
        let (mut client_relay, mut client_peer) = tokio::io::duplex(1024);
        let (mut remote_relay, mut remote_peer) = tokio::io::duplex(1024);

        let relay = tokio::spawn(async move {
            relay_tcp_bidirectional(&mut client_relay, &mut remote_relay, options).await
        });

        client_peer.write_all(b"GET").await.unwrap();
        client_peer.shutdown().await.unwrap();

        let mut request = [0u8; 3];
        remote_peer.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"GET");

        let mut eof_probe = [0u8; 1];
        assert_eq!(remote_peer.read(&mut eof_probe).await.unwrap(), 0);

        remote_peer.write_all(b"complete-body").await.unwrap();
        remote_peer.shutdown().await.unwrap();

        let mut response = Vec::new();
        client_peer.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"complete-body");

        let stats = tokio::time::timeout(Duration::from_secs(5), relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(stats.client_to_remote, 3);
        assert_eq!(stats.remote_to_client, b"complete-body".len() as u64);
    }

    #[tokio::test]
    async fn relay_keeps_response_when_request_shutdown_errors() {
        let (mut client_relay, mut client_peer) = tokio::io::duplex(1024);
        let mut remote = ShutdownErrorRemote::new(b"complete-body");

        let relay = tokio::spawn(async move {
            relay_tcp_bidirectional(
                &mut client_relay,
                &mut remote,
                TcpRelayOptions::http_proxy("test"),
            )
            .await
        });

        client_peer.write_all(b"GET").await.unwrap();
        client_peer.shutdown().await.unwrap();

        let mut response = Vec::new();
        client_peer.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"complete-body");

        let stats = tokio::time::timeout(Duration::from_secs(5), relay)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(stats.client_to_remote, 3);
        assert_eq!(stats.remote_to_client, b"complete-body".len() as u64);
    }

    struct ShutdownErrorRemote {
        state: Arc<Mutex<ShutdownErrorRemoteState>>,
    }

    struct ShutdownErrorRemoteState {
        body: VecDeque<u8>,
        body_released: bool,
        read_waker: Option<Waker>,
    }

    impl ShutdownErrorRemote {
        fn new(body: &[u8]) -> Self {
            Self {
                state: Arc::new(Mutex::new(ShutdownErrorRemoteState {
                    body: body.iter().copied().collect(),
                    body_released: false,
                    read_waker: None,
                })),
            }
        }
    }

    impl AsyncRead for ShutdownErrorRemote {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let mut state = self.state.lock().unwrap();
            if !state.body_released {
                state.read_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }

            while buf.remaining() > 0 {
                let Some(byte) = state.body.pop_front() else {
                    break;
                };
                buf.put_slice(&[byte]);
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ShutdownErrorRemote {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let mut state = self.state.lock().unwrap();
            state.body_released = true;
            if let Some(waker) = state.read_waker.take() {
                waker.wake();
            }
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "synthetic shutdown error",
            )))
        }
    }
}
