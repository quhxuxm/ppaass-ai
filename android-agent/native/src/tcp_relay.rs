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
pub struct TcpRelayStats {
    pub client_to_remote: u64,
    pub remote_to_client: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct TcpRelayOptions<'a> {
    label: &'a str,
}

impl<'a> TcpRelayOptions<'a> {
    pub fn tun(label: &'a str) -> Self {
        Self { label }
    }

    pub fn http_proxy(label: &'a str) -> Self {
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

pub async fn relay_tcp_bidirectional<C, R>(
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
