//! 写方向适配器：裸字节 -> `ProxyRequest::Data`。
//!
//! 每个 sink 固定绑定一个 stream_id，确保写入的数据都发给 proxy 端对应的目标流。

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
    end_sent: bool,
}

impl DataPacketSink {
    pub fn new(writer: FramedWriter, stream_id: String) -> Self {
        // Sink 绑定单个 stream_id，写入的字节都会发到同一个代理目标流。
        Self {
            writer,
            stream_id,
            end_sent: false,
        }
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
        // 这里只表达“当前代理 stream 的请求方向结束”，不能顺手关闭底层
        // framed writer。底层 TCP 连接还承担从 proxy 读回响应的另一半；
        // 如果这里过早 poll_close，某些 HLS/HTTP2 分片在响应尚未排空时会看到
        // 承载连接半关闭，表现成分片偶发下载不完整。
        if !self.end_sent {
            let this = self.as_mut().get_mut();
            let request = this.create_data_request(&[], true);

            let writer = Pin::new(&mut this.writer);
            match writer.poll_ready(cx) {
                Poll::Ready(Ok(())) => {
                    let writer = Pin::new(&mut this.writer);
                    writer
                        .start_send(request)
                        .map_err(|e| io::Error::other(e.to_string()))?;
                    this.end_sent = true;
                }
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(io::Error::other(e.to_string())));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }

        // 与 common::ClientStream::poll_shutdown 保持一致：发送 end 包后只 flush。
        // 真正的底层连接关闭由 relay 两个方向都结束后的 drop/外层生命周期处理。
        Pin::new(&mut self.writer)
            .poll_flush(cx)
            .map_err(|e| io::Error::other(e.to_string()))
    }
}
