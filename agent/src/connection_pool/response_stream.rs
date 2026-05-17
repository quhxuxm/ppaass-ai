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
        Self { reader, stream_id }
    }
}

impl Stream for ResponseStream {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            let reader = Pin::new(&mut self.reader);
            match reader.poll_next(cx) {
                Poll::Ready(Some(Ok(response))) => {
                    // 响应已由编解码器完成反序列化、解密和解压
                    match response {
                        ProxyResponse::Data(packet) if packet.stream_id == self.stream_id => {
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
