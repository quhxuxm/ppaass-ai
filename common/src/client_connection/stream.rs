//! legacy `ClientStream` 适配器。
//!
//! `AuthenticatedConnection::connect_to_target` 成功后返回它。上层写入裸字节时，
//! 它会封装成 `ProxyRequest::Data`；读取时，它从 `ProxyResponse::Data` 中拆出 payload。

use futures::stream::{SplitSink, SplitStream};
use futures::{Sink, Stream};
use protocol::{AgentCodec, ProxyRequest, ProxyResponse};
use std::task::Poll;
use std::{pin::Pin, task::Context};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

type FramedWriter<S> = SplitSink<Framed<S, AgentCodec>, ProxyRequest>;
type FramedReader<S> = SplitStream<Framed<S, AgentCodec>>;

/// 流包装器，在 ProxyRequest/Response 与 AsyncRead/AsyncWrite 之间转换
pub struct ClientStream<S = TcpStream>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 写给 proxy 的请求半边。
    pub writer: FramedWriter<S>,
    // 从 proxy 读取响应的半边。
    pub reader: FramedReader<S>,
    // shutdown 只能发送一次空 end 包。
    pub end_sent: bool,
    // 与 ConnectRequest.request_id 相同，用于区分目标流。
    pub stream_id: String,
    pub read_buf: Vec<u8>,
    pub read_pos: usize,
}

impl<S> ClientStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// 获取流 ID
    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }
}

impl<S> tokio::io::AsyncRead for ClientStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        // 如果有缓冲数据，优先返回
        if self.read_pos < self.read_buf.len() {
            let remaining = &self.read_buf[self.read_pos..];
            let to_read = std::cmp::min(remaining.len(), buf.remaining());
            buf.put_slice(&remaining[..to_read]);
            self.read_pos += to_read;
            return Poll::Ready(Ok(()));
        }

        // 清空缓冲区并尝试读取下一个响应
        self.read_buf.clear();
        self.read_pos = 0;

        loop {
            // 轮询读取器获取下一个响应
            match Pin::new(&mut self.reader).poll_next(cx) {
                Poll::Ready(Some(Ok(ProxyResponse::Data(packet)))) => {
                    if packet.is_end && packet.data.is_empty() {
                        return Poll::Ready(Ok(()));
                    }

                    if packet.data.is_empty() {
                        continue;
                    }

                    self.read_buf = packet.data;
                    let to_read = std::cmp::min(self.read_buf.len(), buf.remaining());
                    buf.put_slice(&self.read_buf[..to_read]);
                    self.read_pos = to_read;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Ok(_))) => {
                    // 忽略非数据响应，继续读取下一个，避免被上层误判为 EOF。
                    continue;
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(std::io::Error::other(e))),
                Poll::Ready(None) => return Poll::Ready(Ok(())), // 到达流末尾
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> tokio::io::AsyncWrite for ClientStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        match Pin::new(&mut self.writer).poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                let packet = protocol::DataPacket {
                    stream_id: self.stream_id.clone(),
                    data: buf.to_vec(),
                    is_end: false,
                };
                match Pin::new(&mut self.writer).start_send(ProxyRequest::Data(packet)) {
                    // 让连续 DataPacket 留在 Framed 写缓冲区中一起发送。调用者
                    // 在读取 Pending、EOF 或关闭时会通过 poll_flush 提交它们。
                    Ok(()) => Poll::Ready(Ok(buf.len())),
                    Err(e) => Poll::Ready(Err(std::io::Error::other(e))),
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match Pin::new(&mut self.writer).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if !self.end_sent {
            // 发送流结束数据包
            let end_packet = protocol::DataPacket {
                stream_id: self.stream_id.clone(),
                data: vec![],
                is_end: true,
            };

            match Pin::new(&mut self.writer).poll_ready(cx) {
                Poll::Ready(Ok(())) => {
                    match Pin::new(&mut self.writer).start_send(ProxyRequest::Data(end_packet)) {
                        Ok(()) => {
                            self.end_sent = true;
                        }
                        Err(e) => return Poll::Ready(Err(std::io::Error::other(e))),
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(std::io::Error::other(e))),
                Poll::Pending => return Poll::Pending,
            }
        }

        match Pin::new(&mut self.writer).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

// 实现 Unpin 以允许在需要 Unpin 的上下文中使用
impl<S> Unpin for ClientStream<S> where S: AsyncRead + AsyncWrite + Unpin {}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{FutureExt, StreamExt};
    use protocol::{DataPacket, ProxyCodec};
    use tokio::io::{AsyncWriteExt, DuplexStream};

    fn stream_pair() -> (ClientStream<DuplexStream>, Framed<DuplexStream, ProxyCodec>) {
        let (client_io, proxy_io) = tokio::io::duplex(4096);
        let (writer, reader) = Framed::new(client_io, AgentCodec::new(None)).split();
        let client = ClientStream {
            writer,
            reader,
            end_sent: false,
            stream_id: "test-stream".to_string(),
            read_buf: Vec::new(),
            read_pos: 0,
        };
        let proxy = Framed::new(proxy_io, ProxyCodec::new(None));
        (client, proxy)
    }

    async fn next_data(proxy: &mut Framed<DuplexStream, ProxyCodec>) -> DataPacket {
        match proxy.next().await.unwrap().unwrap() {
            ProxyRequest::Data(packet) => packet,
            _ => panic!("expected data packet"),
        }
    }

    #[tokio::test]
    async fn writes_are_buffered_until_explicit_flush() {
        let (mut client, mut proxy) = stream_pair();

        client.write_all(b"first").await.unwrap();
        client.write_all(b"second").await.unwrap();

        assert!(proxy.next().now_or_never().is_none());

        client.flush().await.unwrap();
        let first = next_data(&mut proxy).await;
        let second = next_data(&mut proxy).await;
        assert_eq!(first.stream_id, "test-stream");
        assert_eq!(first.data, b"first");
        assert!(!first.is_end);
        assert_eq!(second.stream_id, "test-stream");
        assert_eq!(second.data, b"second");
        assert!(!second.is_end);
    }

    #[tokio::test]
    async fn shutdown_flushes_buffered_data_and_sends_one_end_packet() {
        let (mut client, mut proxy) = stream_pair();

        client.write_all(b"payload").await.unwrap();
        assert!(proxy.next().now_or_never().is_none());

        client.shutdown().await.unwrap();
        let data = next_data(&mut proxy).await;
        let end = next_data(&mut proxy).await;
        assert_eq!(data.data, b"payload");
        assert!(!data.is_end);
        assert_eq!(end.stream_id, "test-stream");
        assert!(end.data.is_empty());
        assert!(end.is_end);

        client.shutdown().await.unwrap();
        assert!(proxy.next().now_or_never().is_none());
    }
}
