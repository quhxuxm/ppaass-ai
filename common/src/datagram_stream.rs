use bytes::Bytes;
use futures::stream::{SplitSink, SplitStream};
use futures::{Sink, Stream};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tokio_util::io::{SinkWriter, StreamReader};

const MAX_DATAGRAM_FRAME_SIZE: usize = 1024 * 1024;

type DatagramFramed<S> = Framed<S, LengthDelimitedCodec>;
type DatagramWriter<S> = SplitSink<DatagramFramed<S>, Bytes>;
type DatagramReader<S> = SplitStream<DatagramFramed<S>>;

pub struct DatagramStreamIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    reader: StreamReader<DatagramResponseStream<S>, Bytes>,
    writer: SinkWriter<DatagramSink<S>>,
}

impl<S> DatagramStreamIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: S) -> Self {
        let codec = LengthDelimitedCodec::builder()
            .max_frame_length(MAX_DATAGRAM_FRAME_SIZE)
            .new_codec();
        let framed = Framed::new(stream, codec);
        let (writer, reader) = futures::StreamExt::split(framed);

        Self {
            reader: StreamReader::new(DatagramResponseStream { reader }),
            writer: SinkWriter::new(DatagramSink { writer }),
        }
    }
}

impl<S> AsyncRead for DatagramStreamIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for DatagramStreamIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

impl<S> Unpin for DatagramStreamIo<S> where S: AsyncRead + AsyncWrite + Unpin {}

pub struct DatagramSink<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    writer: DatagramWriter<S>,
}

impl<'a, S> Sink<&'a [u8]> for DatagramSink<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer)
            .poll_ready(cx)
            .map_err(|e| io::Error::other(e.to_string()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: &'a [u8]) -> io::Result<()> {
        Pin::new(&mut self.writer)
            .start_send(Bytes::copy_from_slice(item))
            .map_err(|e| io::Error::other(e.to_string()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer)
            .poll_flush(cx)
            .map_err(|e| io::Error::other(e.to_string()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer)
            .poll_close(cx)
            .map_err(|e| io::Error::other(e.to_string()))
    }
}

pub struct DatagramResponseStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    reader: DatagramReader<S>,
}

impl<S> Stream for DatagramResponseStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.reader).poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => Poll::Ready(Some(Ok(bytes.freeze()))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(io::Error::other(e.to_string())))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
