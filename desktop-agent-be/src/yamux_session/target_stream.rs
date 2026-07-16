//! 已连接目标的统一流类型。

use common::{ClientStream, UdpClientStream, YamuxClientStream};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

pub enum YamuxTargetStream {
    Direct {
        stream: ClientStream<TcpStream>,
        stream_id: String,
    },
    Yamux {
        stream: YamuxClientStream,
        stream_id: String,
    },
    Udp {
        stream: UdpClientStream,
        stream_id: String,
    },
}

impl YamuxTargetStream {
    pub fn new_direct(stream: ClientStream<TcpStream>, stream_id: String) -> Self {
        Self::Direct { stream, stream_id }
    }

    pub fn new_yamux(stream: YamuxClientStream, stream_id: String) -> Self {
        Self::Yamux { stream, stream_id }
    }

    pub fn new_udp(stream: UdpClientStream, stream_id: String) -> Self {
        Self::Udp { stream, stream_id }
    }

    pub fn stream_id(&self) -> &str {
        match self {
            Self::Direct { stream_id, .. } => stream_id,
            Self::Yamux { stream_id, .. } => stream_id,
            Self::Udp { stream_id, .. } => stream_id,
        }
    }

    pub fn into_async_io(self) -> YamuxTargetIo {
        match self {
            Self::Direct { stream, .. } => YamuxTargetIo::Direct(stream),
            Self::Yamux { stream, .. } => YamuxTargetIo::Yamux(stream),
            Self::Udp { stream, .. } => YamuxTargetIo::Udp(stream),
        }
    }
}

pub enum YamuxTargetIo {
    Direct(ClientStream<TcpStream>),
    Yamux(YamuxClientStream),
    Udp(UdpClientStream),
}

impl YamuxTargetIo {
    pub fn is_native_udp(&self) -> bool {
        matches!(self, Self::Udp(_))
    }
}

impl AsyncRead for YamuxTargetIo {
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

impl AsyncWrite for YamuxTargetIo {
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

impl Unpin for YamuxTargetIo {}
