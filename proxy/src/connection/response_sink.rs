use crate::bandwidth::BandwidthMonitor;
use futures::{Sink, stream::SplitSink};
use protocol::{DataPacket, ProxyResponse, ServerCodec};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

type FramedWriter = SplitSink<Framed<TcpStream, ServerCodec>, ProxyResponse>;

pub struct BytesToProxyResponseSink<'a> {
    pub inner: &'a mut FramedWriter,
    pub stream_id: String,
    pub username: Option<String>,
    pub bandwidth_monitor: Arc<BandwidthMonitor>,
}

impl<'a> Sink<&[u8]> for BytesToProxyResponseSink<'a> {
    type Error = std::io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: &[u8]) -> std::result::Result<(), Self::Error> {
        let stream_id = self.stream_id.clone();
        
        if let Some(user) = &self.username {
            self.bandwidth_monitor.record_sent(user, item.len() as u64);
        }
        
        // Compression is handled at the codec level
        let packet = DataPacket {
            stream_id,
            data: item.to_vec(),
            is_end: false,
        };
        Pin::new(&mut self.inner).start_send(ProxyResponse::Data(packet))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}
