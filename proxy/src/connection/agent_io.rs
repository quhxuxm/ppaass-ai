use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct AgentIo<R, W> {
    /// 从 agent 方向读入的数据流。
    pub reader: R,
    /// 写回 agent 方向的数据流。
    pub writer: W,
    /// writer 是 framed sink 时，poll_write 只 start_send；这里记录待 flush 的写入。
    pub pending_write_len: Option<usize>,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncRead for AgentIo<R, W> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 组合 reader/writer 后仍表现为一个双向 IO，便于 copy_bidirectional 使用。
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncWrite for AgentIo<R, W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(len) = self.pending_write_len {
            match Pin::new(&mut self.writer).poll_flush(cx) {
                Poll::Ready(Ok(())) => {
                    self.pending_write_len = None;
                    return Poll::Ready(Ok(len));
                }
                Poll::Ready(Err(err)) => {
                    self.pending_write_len = None;
                    return Poll::Ready(Err(err));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        // 写操作全部委托给包装的 writer。
        let written = match Pin::new(&mut self.writer).poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => written,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        };
        if written == 0 {
            return Poll::Ready(Ok(0));
        }

        // 对 proxy 协议层来说，写入目标响应后必须尽快 flush。
        // 否则小 HLS 分片响应可能停在 Framed/SinkWriter 内部，浏览器端看起来像分片停住。
        self.pending_write_len = Some(written);
        match Pin::new(&mut self.writer).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                self.pending_write_len = None;
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(err)) => {
                self.pending_write_len = None;
                Poll::Ready(Err(err))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending_write_len.is_some() {
            match Pin::new(&mut self.writer).poll_flush(cx) {
                Poll::Ready(Ok(())) => self.pending_write_len = None,
                Poll::Ready(Err(err)) => {
                    self.pending_write_len = None;
                    return Poll::Ready(Err(err));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        // flush 也必须透传，否则 agent 侧可能看不到及时写出的响应。
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending_write_len.is_some() {
            match Pin::new(&mut self.writer).poll_flush(cx) {
                Poll::Ready(Ok(())) => self.pending_write_len = None,
                Poll::Ready(Err(err)) => {
                    self.pending_write_len = None;
                    return Poll::Ready(Err(err));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        // shutdown 关闭写半边，用于中继结束时通知对端。
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}
