use bytes::Bytes;
use futures::Stream;
use protocol::{AgentCodec, ProxyResponse};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use futures::stream::SplitStream;

type FramedReader = SplitStream<Framed<TcpStream, AgentCodec>>;

/// A stream adapter that extracts data from proxy protocol messages
/// This implements Stream<Item = Result<Bytes, io::Error>> for use with StreamReader
pub struct ResponseStream {
    reader: FramedReader,
    stream_id: String,
}

impl ResponseStream {
    pub fn new(reader: FramedReader, stream_id: String) -> Self {
        Self {
            reader,
            stream_id,
        }
    }
}

impl Stream for ResponseStream {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            let reader = Pin::new(&mut self.reader);
            match reader.poll_next(cx) {
                Poll::Ready(Some(Ok(response))) => {
                    // Response is already deserialized, decrypted, and decompressed by codec
                    match response {
                        ProxyResponse::Data(packet) => {
                            if packet.stream_id == self.stream_id {
                                if packet.is_end && packet.data.is_empty() {
                                    return Poll::Ready(None);
                                }
                                return Poll::Ready(Some(Ok(Bytes::from(packet.data))));
                            }
                            // Wrong stream, continue polling
                        }
                        _ => {
                            // Ignore other responses, continue polling
                        }
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Some(Err(io::Error::other(e.to_string()))));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(None);
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }
}
