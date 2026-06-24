//! legacy proxy stream 的字节流适配器。
//!
//! proxy 协议层读写的是 `ProxyRequest::Data` / `ProxyResponse::Data`；
//! HTTP/SOCKS/TUN 中继层想要的是裸 `AsyncRead + AsyncWrite`。
//! `ProxyStreamIo` 把两者拼起来，隐藏 DataPacket 的封包/拆包细节。

use super::data_packet_sink::DataPacketSink;
use super::response_stream::ResponseStream;
use bytes::Bytes;
use futures::stream::{SplitSink, SplitStream};
use protocol::{AgentCodec, ProxyRequest};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use tokio_util::io::{SinkWriter, StreamReader};

type FramedWriter = SplitSink<Framed<TcpStream, AgentCodec>, ProxyRequest>;
type FramedReader = SplitStream<Framed<TcpStream, AgentCodec>>;

/// 实现 AsyncRead + AsyncWrite 的包装器，用于 tokio::io::copy_bidirectional
/// 使用 tokio_util 的 SinkWriter 与 StreamReader 以获得更好性能
pub struct ProxyStreamIo {
    reader: StreamReader<ResponseStream, Bytes>,
    writer: FlushAfterWrite<SinkWriter<DataPacketSink>>,
}

struct FlushAfterWrite<W> {
    inner: W,
    pending_write_len: Option<usize>,
}

impl<W> FlushAfterWrite<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            pending_write_len: None,
        }
    }
}

impl ProxyStreamIo {
    pub fn new(
        framed_writer: FramedWriter,
        framed_reader: FramedReader,
        stream_id: String,
    ) -> Self {
        // 将协议层 reader/writer 适配成字节流，供 copy_bidirectional 直接使用。
        let response_stream = ResponseStream::new(framed_reader, stream_id.clone());
        let data_sink = DataPacketSink::new(framed_writer, stream_id);

        Self {
            reader: StreamReader::new(response_stream),
            writer: FlushAfterWrite::new(SinkWriter::new(data_sink)),
        }
    }
}

impl AsyncRead for ProxyStreamIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 从 proxy DataPacket 流中读出目标返回的裸字节。
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for ProxyStreamIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // 写入的裸字节会由 DataPacketSink 包装成代理协议消息。
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // 透传 flush，确保中继路径不会额外滞留数据。
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // shutdown 会触发 DataPacketSink 发送 end 包。
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

impl<W> AsyncWrite for FlushAfterWrite<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(len) = self.pending_write_len {
            match Pin::new(&mut self.inner).poll_flush(cx) {
                Poll::Ready(Ok(())) => {
                    self.pending_write_len = None;
                    return Poll::Ready(Ok(len));
                }
                Poll::Ready(Err(err)) => {
                    self.pending_write_len = None;
                    return Poll::Ready(Err(err));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        let written = match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => written,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        };
        if written == 0 {
            return Poll::Ready(Ok(0));
        }

        // SinkWriter::poll_write 只完成 start_send；对 framed proxy 协议而言，
        // 小 DataPacket 必须尽快 flush 到 agent->proxy TCP 上，否则 HLS 小分片
        // 请求/响应会等到 copy 缓冲填满或 EOF 才真正下发。
        self.pending_write_len = Some(written);
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                self.pending_write_len = None;
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(err)) => {
                self.pending_write_len = None;
                Poll::Ready(Err(err))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending_write_len.is_some() {
            match Pin::new(&mut self.inner).poll_flush(cx) {
                Poll::Ready(Ok(())) => self.pending_write_len = None,
                Poll::Ready(Err(err)) => {
                    self.pending_write_len = None;
                    return Poll::Ready(Err(err));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending_write_len.is_some() {
            match Pin::new(&mut self.inner).poll_flush(cx) {
                Poll::Ready(Ok(())) => self.pending_write_len = None,
                Poll::Ready(Err(err)) => {
                    self.pending_write_len = None;
                    return Poll::Ready(Err(err));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
