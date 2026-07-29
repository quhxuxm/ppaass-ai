use super::super::*;
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

pub(super) struct ShutdownErrorTarget {
    state: Arc<Mutex<ShutdownErrorTargetState>>,
}

struct ShutdownErrorTargetState {
    body: VecDeque<u8>,
    body_released: bool,
    read_waker: Option<Waker>,
}

impl ShutdownErrorTarget {
    pub(super) fn new(body: &[u8]) -> Self {
        Self {
            state: Arc::new(Mutex::new(ShutdownErrorTargetState {
                body: body.iter().copied().collect(),
                body_released: false,
                read_waker: None,
            })),
        }
    }
}

impl AsyncRead for ShutdownErrorTarget {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut state = self.state.lock().unwrap();
        if !state.body_released {
            state.read_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        while buf.remaining() > 0 {
            let Some(byte) = state.body.pop_front() else {
                break;
            };
            buf.put_slice(&[byte]);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ShutdownErrorTarget {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.state.lock().unwrap();
        state.body_released = true;
        if let Some(waker) = state.read_waker.take() {
            waker.wake();
        }
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "synthetic shutdown error",
        )))
    }
}

pub(super) struct PendingShutdownTarget {
    body: VecDeque<u8>,
}

impl PendingShutdownTarget {
    pub(super) fn new(body: &[u8]) -> Self {
        Self {
            body: body.iter().copied().collect(),
        }
    }
}

impl AsyncRead for PendingShutdownTarget {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        while buf.remaining() > 0 {
            let Some(byte) = self.body.pop_front() else {
                break;
            };
            buf.put_slice(&[byte]);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for PendingShutdownTarget {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}
