//! 已连接目标的统一流类型。

use common::YamuxClientStream;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub enum YamuxTargetStream {
    Yamux {
        stream: YamuxClientStream,
        stream_id: String,
    },
}

impl YamuxTargetStream {
    pub fn new_yamux(stream: YamuxClientStream, stream_id: String) -> Self {
        Self::Yamux { stream, stream_id }
    }

    pub fn stream_id(&self) -> &str {
        match self {
            Self::Yamux { stream_id, .. } => stream_id,
        }
    }

    pub fn into_async_io(self) -> YamuxTargetIo {
        match self {
            Self::Yamux { stream, .. } => YamuxTargetIo::Yamux(stream),
        }
    }
}

pub enum YamuxTargetIo {
    Yamux(YamuxClientStream),
}

impl AsyncRead for YamuxTargetIo {
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

impl AsyncWrite for YamuxTargetIo {
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

impl Unpin for YamuxTargetIo {}
