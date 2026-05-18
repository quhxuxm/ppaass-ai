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
    writer: SinkWriter<DataPacketSink>,
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
            writer: SinkWriter::new(data_sink),
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
