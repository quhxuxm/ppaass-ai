use futures::Sink;
use futures::stream::SplitSink;
use protocol::{AgentCodec, DataPacket, ProxyRequest};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{io, result::Result};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

type FramedWriter = SplitSink<Framed<TcpStream, AgentCodec>, ProxyRequest>;

/// A sink adapter that wraps data into proxy protocol messages
/// This implements Sink<&[u8], Error = io::Error> for use with SinkWriter
pub struct DataPacketSink {
    writer: FramedWriter,
    stream_id: String,
}

impl DataPacketSink {
    pub fn new(writer: FramedWriter, stream_id: String) -> Self {
        Self { writer, stream_id }
    }

    fn create_data_request(&self, data: &[u8], is_end: bool) -> ProxyRequest {
        let data_packet = DataPacket {
            stream_id: self.stream_id.clone(),
            data: data.to_vec(),
            is_end,
        };

        ProxyRequest::Data(data_packet)
    }
}

impl<'a> Sink<&'a [u8]> for DataPacketSink {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.writer)
            .poll_ready(cx)
            .map_err(|e| io::Error::other(e.to_string()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: &'a [u8]) -> Result<(), Self::Error> {
        let request = self.create_data_request(item, false);
        Pin::new(&mut self.writer)
            .start_send(request)
            .map_err(|e| io::Error::other(e.to_string()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.writer)
            .poll_flush(cx)
            .map_err(|e| io::Error::other(e.to_string()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // First, send end-of-stream message
        let this = self.as_mut().get_mut();
        let request = this.create_data_request(&[], true);

        let writer = Pin::new(&mut this.writer);
        match writer.poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                let writer = Pin::new(&mut this.writer);
                writer
                    .start_send(request)
                    .map_err(|e| io::Error::other(e.to_string()))?;
            }
            Poll::Ready(Err(e)) => {
                return Poll::Ready(Err(io::Error::other(e.to_string())));
            }
            Poll::Pending => {
                return Poll::Pending;
            }
        }

        // Then close the underlying writer
        Pin::new(&mut self.writer)
            .poll_close(cx)
            .map_err(|e| io::Error::other(e.to_string()))
    }
}
