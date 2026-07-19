use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct AgentIo<R, W> {
    /// 从 agent 方向读入的数据流。
    pub reader: R,
    /// 写回 agent 方向的数据流。
    pub writer: W,
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
        // SinkWriter::poll_write 只把帧放入编码缓冲区。在每次写入后强制
        // flush 会让 64KB 的中继块立即单独发送，增加外层 TCP 的小写入和调度开销。
        // 上层 copy/copy_bidirectional 会在读取 Pending、EOF 或关闭时显式 flush。
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // 显式 flush 仍完整透传。
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // shutdown 关闭写半边，用于中继结束时通知对端。
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[derive(Default)]
    struct RecordingWriter {
        buffered: Vec<u8>,
        committed: Vec<Vec<u8>>,
        flush_count: usize,
        shutdown_count: usize,
    }

    impl RecordingWriter {
        fn commit(&mut self) {
            if !self.buffered.is_empty() {
                self.committed.push(std::mem::take(&mut self.buffered));
            }
        }
    }

    impl AsyncWrite for RecordingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.buffered.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.flush_count += 1;
            self.commit();
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.shutdown_count += 1;
            self.commit();
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn batches_writes_until_flush_and_delegates_shutdown() {
        let mut io = AgentIo {
            reader: tokio::io::empty(),
            writer: RecordingWriter::default(),
        };

        io.write_all(b"first").await.unwrap();
        io.write_all(b"-second").await.unwrap();

        assert_eq!(io.writer.buffered, b"first-second");
        assert!(io.writer.committed.is_empty());
        assert_eq!(io.writer.flush_count, 0);

        io.flush().await.unwrap();
        assert_eq!(io.writer.committed, [b"first-second".to_vec()]);
        assert_eq!(io.writer.flush_count, 1);

        io.write_all(b"tail").await.unwrap();
        io.shutdown().await.unwrap();
        assert_eq!(
            io.writer.committed,
            [b"first-second".to_vec(), b"tail".to_vec()]
        );
        assert_eq!(io.writer.shutdown_count, 1);
    }
}
