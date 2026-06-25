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
    // framed sink 的 start_send 只把 DataPacket 放进编码缓冲；这里记录一次尚未
    // flush 完成的写入，避免 copy_bidirectional 认为小包已经真正发到 proxy。
    pub pending_write_len: Option<usize>,
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
        if let Some(len) = self.pending_write_len {
            match Pin::new(&mut self.writer).poll_flush(cx) {
                Poll::Ready(Ok(())) => {
                    self.pending_write_len = None;
                    return Poll::Ready(Ok(len));
                }
                Poll::Ready(Err(e)) => {
                    self.pending_write_len = None;
                    return Poll::Ready(Err(std::io::Error::other(e)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

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
                    Ok(()) => {
                        // DataPacket 代表隧道里的一个裸字节块。对真实 TcpStream 来说
                        // flush 基本是 no-op；但这里底层是 framed sink，不 flush 会让
                        // 小请求/小响应滞留到 copy 缓冲填满或 EOF，浏览器就可能重试小分片。
                        self.pending_write_len = Some(buf.len());
                        match Pin::new(&mut self.writer).poll_flush(cx) {
                            Poll::Ready(Ok(())) => {
                                self.pending_write_len = None;
                                Poll::Ready(Ok(buf.len()))
                            }
                            Poll::Ready(Err(e)) => {
                                self.pending_write_len = None;
                                Poll::Ready(Err(std::io::Error::other(e)))
                            }
                            Poll::Pending => Poll::Pending,
                        }
                    }
                    Err(e) => Poll::Ready(Err(std::io::Error::other(e))),
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.pending_write_len.is_some() {
            match Pin::new(&mut self.writer).poll_flush(cx) {
                Poll::Ready(Ok(())) => self.pending_write_len = None,
                Poll::Ready(Err(e)) => {
                    self.pending_write_len = None;
                    return Poll::Ready(Err(std::io::Error::other(e)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        match Pin::new(&mut self.writer).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.pending_write_len.is_some() {
            match Pin::new(&mut self.writer).poll_flush(cx) {
                Poll::Ready(Ok(())) => self.pending_write_len = None,
                Poll::Ready(Err(e)) => {
                    self.pending_write_len = None;
                    return Poll::Ready(Err(std::io::Error::other(e)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

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
