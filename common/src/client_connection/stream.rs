use futures::stream::{SplitSink, SplitStream};
use futures::{Sink, Stream};
use protocol::{AgentCodec, ProxyRequest, ProxyResponse};
use std::pin::Pin;
use std::task::Poll;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

type FramedWriter = SplitSink<Framed<TcpStream, AgentCodec>, ProxyRequest>;
type FramedReader = SplitStream<Framed<TcpStream, AgentCodec>>;

/// A stream wrapper that converts between ProxyRequest/Response and AsyncRead/AsyncWrite
pub struct ClientStream {
    pub writer: FramedWriter,
    pub reader: FramedReader,
    pub stream_id: String,
    pub read_buf: Vec<u8>,
    pub read_pos: usize,
}

impl ClientStream {
    /// Get the stream ID
    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }
}

impl tokio::io::AsyncRead for ClientStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // If we have buffered data, return it first
        if self.read_pos < self.read_buf.len() {
            let remaining = &self.read_buf[self.read_pos..];
            let to_read = std::cmp::min(remaining.len(), buf.remaining());
            buf.put_slice(&remaining[..to_read]);
            self.read_pos += to_read;
            return Poll::Ready(Ok(()));
        }

        // Clear buffer and try to read next response
        self.read_buf.clear();
        self.read_pos = 0;

        // Poll the reader for the next response
        match Pin::new(&mut self.reader).poll_next(cx) {
            Poll::Ready(Some(Ok(ProxyResponse::Data(packet)))) => {
                if !packet.data.is_empty() {
                    self.read_buf = packet.data;
                    let to_read = std::cmp::min(self.read_buf.len(), buf.remaining());
                    buf.put_slice(&self.read_buf[..to_read]);
                    self.read_pos = to_read;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Ok(_))) => {
                // Ignore non-data responses and try to read the next one
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl tokio::io::AsyncWrite for ClientStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let packet = protocol::DataPacket {
            stream_id: self.stream_id.clone(),
            data: buf.to_vec(),
            is_end: false,
        };

        match Pin::new(&mut self.writer).poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                match Pin::new(&mut self.writer).start_send(ProxyRequest::Data(packet)) {
                    Ok(()) => Poll::Ready(Ok(buf.len())),
                    Err(e) => Poll::Ready(Err(std::io::Error::other(e))),
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match Pin::new(&mut self.writer).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Send end-of-stream packet
        let end_packet = protocol::DataPacket {
            stream_id: self.stream_id.clone(),
            data: vec![],
            is_end: true,
        };

        match Pin::new(&mut self.writer).poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                match Pin::new(&mut self.writer).start_send(ProxyRequest::Data(end_packet)) {
                    Ok(()) => Pin::new(&mut self.writer).poll_flush(cx),
                    Err(e) => Poll::Ready(Err(std::io::Error::other(e))),
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

// Implement Unpin to allow used in contexts that require Unpin
impl Unpin for ClientStream {}
