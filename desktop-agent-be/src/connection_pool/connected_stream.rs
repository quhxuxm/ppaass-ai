//! 已连接目标的统一流类型。
//!
//! 上层不需要知道目标流来自 legacy DataPacket、TCP Yamux 子流还是 UDP Yamux 子流；
//! 调用 `into_async_io` 后统一得到 `AsyncRead + AsyncWrite`，可直接用于双向中继。

use super::proxy_stream_io::ProxyStreamIo;
use common::{DatagramStreamIo, YamuxClientStream};
use futures::stream::{SplitSink, SplitStream};
use protocol::{AgentCodec, ProxyRequest};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

type FramedWriter = SplitSink<Framed<TcpStream, AgentCodec>, ProxyRequest>;
type FramedReader = SplitStream<Framed<TcpStream, AgentCodec>>;

/// 通过代理连接到目标的已连接流
/// 处理双向数据传输
pub enum ConnectedStream {
    // legacy 模式：同一条 agent->proxy TCP 连接通过 stream_id 承载目标数据。
    Framed {
        writer: FramedWriter,
        reader: FramedReader,
        stream_id: String,
    },
    // TCP Yamux 子流：子流本身已经是裸字节通道。
    Yamux {
        stream: YamuxClientStream,
        stream_id: String,
    },
    // UDP Yamux 子流：用 DatagramStreamIo 保留 UDP 数据报边界。
    YamuxDatagram {
        stream: DatagramStreamIo<YamuxClientStream>,
        stream_id: String,
    },
}

impl ConnectedStream {
    pub fn new(writer: FramedWriter, reader: FramedReader, stream_id: String) -> Self {
        // writer/reader 仍共享同一条 proxy TCP 连接，由 stream_id 区分目标流。
        Self::Framed {
            writer,
            reader,
            stream_id,
        }
    }

    pub fn new_yamux(stream: YamuxClientStream, stream_id: String) -> Self {
        Self::Yamux { stream, stream_id }
    }

    pub fn new_yamux_datagram(stream: YamuxClientStream, stream_id: String) -> Self {
        Self::YamuxDatagram {
            stream: DatagramStreamIo::new(stream),
            stream_id,
        }
    }

    pub fn stream_id(&self) -> &str {
        match self {
            Self::Framed { stream_id, .. }
            | Self::Yamux { stream_id, .. }
            | Self::YamuxDatagram { stream_id, .. } => stream_id,
        }
    }

    /// 转换为兼容 AsyncRead + AsyncWrite 的流，用于 copy_bidirectional
    pub fn into_async_io(self) -> ConnectedStreamIo {
        // 后续 HTTP/SOCKS/TUN 中继都使用统一的 AsyncRead/AsyncWrite 视图。
        match self {
            Self::Framed {
                writer,
                reader,
                stream_id,
            } => ConnectedStreamIo::Framed(ProxyStreamIo::new(writer, reader, stream_id)),
            Self::Yamux { stream, .. } => ConnectedStreamIo::Yamux(stream),
            Self::YamuxDatagram { stream, .. } => ConnectedStreamIo::YamuxDatagram(stream),
        }
    }
}

pub enum ConnectedStreamIo {
    Framed(ProxyStreamIo),
    Yamux(YamuxClientStream),
    YamuxDatagram(DatagramStreamIo<YamuxClientStream>),
}

impl AsyncRead for ConnectedStreamIo {
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

impl AsyncWrite for ConnectedStreamIo {
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

impl Unpin for ConnectedStreamIo {}
