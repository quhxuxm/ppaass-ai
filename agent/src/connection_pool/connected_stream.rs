use super::proxy_stream_io::ProxyStreamIo;
use protocol::{AgentCodec, ProxyRequest};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use futures::stream::{SplitSink, SplitStream};

type FramedWriter = SplitSink<Framed<TcpStream, AgentCodec>, ProxyRequest>;
type FramedReader = SplitStream<Framed<TcpStream, AgentCodec>>;

/// A connected stream to a target through the proxy
/// This handles bidirectional data transfer
pub struct ConnectedStream {
    writer: FramedWriter,
    reader: FramedReader,
    stream_id: String,
}

impl ConnectedStream {
    pub fn new(writer: FramedWriter, reader: FramedReader, stream_id: String) -> Self {
        Self {
            writer,
            reader,
            stream_id,
        }
    }

    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }

    /// Convert to an AsyncRead + AsyncWrite compatible stream for use with copy_bidirectional
    pub fn into_async_io(self) -> ProxyStreamIo {
        ProxyStreamIo::new(self.writer, self.reader, self.stream_id)
    }
}
