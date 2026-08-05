use proxy_entry::connection::AgentIo;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncWrite, AsyncWriteExt};

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
