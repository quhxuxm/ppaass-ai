//! 已连接目标的统一流类型。

use common::YamuxClientStream;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub enum ConnectedStream {
    Yamux {
        stream: YamuxClientStream,
        stream_id: String,
    },
}

impl ConnectedStream {
    pub fn new_yamux(stream: YamuxClientStream, stream_id: String) -> Self {
        Self::Yamux { stream, stream_id }
    }

    pub fn stream_id(&self) -> &str {
        match self {
            Self::Yamux { stream_id, .. } => stream_id,
        }
    }

    pub fn into_async_io(self) -> ConnectedStreamIo {
        match self {
            Self::Yamux { stream, .. } => ConnectedStreamIo::Yamux(stream),
        }
    }
}

pub enum ConnectedStreamIo {
    Yamux(YamuxClientStream),
}

impl AsyncRead for ConnectedStreamIo {
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

impl AsyncWrite for ConnectedStreamIo {
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

impl Unpin for ConnectedStreamIo {}
