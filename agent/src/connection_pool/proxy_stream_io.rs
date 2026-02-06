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

/// A wrapper that implements AsyncRead + AsyncWrite for use with tokio::io::copy_bidirectional
/// This uses SinkWriter and StreamReader from tokio_util for better performance
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
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for ProxyStreamIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}
