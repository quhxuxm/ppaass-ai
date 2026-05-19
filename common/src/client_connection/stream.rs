use futures::stream::{SplitSink, SplitStream};
use futures::{Sink, Stream};
use protocol::{AgentCodec, ProxyRequest, ProxyResponse};
use std::task::Poll;
use std::{pin::Pin, task::Context};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

type FramedWriter = SplitSink<Framed<TcpStream, AgentCodec>, ProxyRequest>;
type FramedReader = SplitStream<Framed<TcpStream, AgentCodec>>;

/// 流包装器，在 ProxyRequest/Response 与 AsyncRead/AsyncWrite 之间转换
pub struct ClientStream {
    pub writer: FramedWriter,
    pub reader: FramedReader,
    pub end_sent: bool,
    pub stream_id: String,
    pub read_buf: Vec<u8>,
    pub read_pos: usize,
}

impl ClientStream {
    /// 获取流 ID
    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }
}

impl tokio::io::AsyncRead for ClientStream {
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

impl tokio::io::AsyncWrite for ClientStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
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
impl Unpin for ClientStream {}
