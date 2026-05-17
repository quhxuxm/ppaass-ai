use super::proxy_stream_io::ProxyStreamIo;
use futures::stream::{SplitSink, SplitStream};
use protocol::{AgentCodec, ProxyRequest};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

type FramedWriter = SplitSink<Framed<TcpStream, AgentCodec>, ProxyRequest>;
type FramedReader = SplitStream<Framed<TcpStream, AgentCodec>>;

/// 通过代理连接到目标的已连接流
/// 处理双向数据传输
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

    /// 转换为兼容 AsyncRead + AsyncWrite 的流，用于 copy_bidirectional
    pub fn into_async_io(self) -> ProxyStreamIo {
        ProxyStreamIo::new(self.writer, self.reader, self.stream_id)
    }
}
