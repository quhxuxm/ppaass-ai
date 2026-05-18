use futures::Sink;
use futures::stream::SplitSink;
use protocol::{AgentCodec, DataPacket, ProxyRequest};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{io, result::Result};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

type FramedWriter = SplitSink<Framed<TcpStream, AgentCodec>, ProxyRequest>;

/// 将数据包装为代理协议消息的 sink 适配器
/// 实现 Sink<&[u8], Error = io::Error> 以供 SinkWriter 使用
pub struct DataPacketSink {
    writer: FramedWriter,
    stream_id: String,
}

impl DataPacketSink {
    pub fn new(writer: FramedWriter, stream_id: String) -> Self {
        // Sink 绑定单个 stream_id，写入的字节都会发到同一个代理目标流。
        Self { writer, stream_id }
    }

    fn create_data_request(&self, data: &[u8], is_end: bool) -> ProxyRequest {
        // 将裸字节转换成代理协议 DataPacket，编码/加密由 AgentCodec 处理。
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
        // 背压直接透传到底层 framed writer。
        Pin::new(&mut self.writer)
            .poll_ready(cx)
            .map_err(|e| io::Error::other(e.to_string()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: &'a [u8]) -> Result<(), Self::Error> {
        // 普通写入不带结束标记。
        let request = self.create_data_request(item, false);
        Pin::new(&mut self.writer)
            .start_send(request)
            .map_err(|e| io::Error::other(e.to_string()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // flush 保证 DataPacket 及时下发到 proxy。
        Pin::new(&mut self.writer)
            .poll_flush(cx)
            .map_err(|e| io::Error::other(e.to_string()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // 首先发送流结束消息，让 proxy 关闭对应目标流。
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

        // 然后关闭底层 writer，完成 SinkWriter 的关闭语义。
        Pin::new(&mut self.writer)
            .poll_close(cx)
            .map_err(|e| io::Error::other(e.to_string()))
    }
}
