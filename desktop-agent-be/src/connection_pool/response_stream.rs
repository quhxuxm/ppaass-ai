//! 读方向适配器：`ProxyResponse::Data` -> 裸字节。
//!
//! legacy 连接中所有响应都来自同一个 framed reader，这里只产出当前 stream_id 的 payload，
//! 让上层看到像普通 TCP 流一样的读取接口。

use bytes::Bytes;
use futures::Stream;
use futures::stream::SplitStream;
use protocol::{AgentCodec, ProxyResponse};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

type FramedReader = SplitStream<Framed<TcpStream, AgentCodec>>;

/// 从代理协议消息中提取数据的 stream 适配器
/// 实现 Stream<Item = Result<Bytes, io::Error>> 以供 StreamReader 使用
pub struct ResponseStream {
    reader: FramedReader,
    stream_id: String,
}

impl ResponseStream {
    pub fn new(reader: FramedReader, stream_id: String) -> Self {
        // Stream 只产出目标 stream_id 的数据，其他响应会被跳过。
        Self { reader, stream_id }
    }
}

impl Stream for ResponseStream {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            // 持续轮询直到拿到目标流数据、结束包、错误或 Pending。
            let reader = Pin::new(&mut self.reader);
            match reader.poll_next(cx) {
                Poll::Ready(Some(Ok(response))) => {
                    // 响应已由编解码器完成反序列化、解密和解压
                    match response {
                        ProxyResponse::Data(packet) if packet.stream_id == self.stream_id => {
                            // 空 end 包表示目标流结束，映射成 Stream 结束。
                            if packet.is_end && packet.data.is_empty() {
                                return Poll::Ready(None);
                            }
                            return Poll::Ready(Some(Ok(Bytes::from(packet.data))));
                        }
                        ProxyResponse::Data(_) => {
                            // 不是目标流，继续轮询
                        }
                        _ => {
                            // 忽略其他响应，继续轮询
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
