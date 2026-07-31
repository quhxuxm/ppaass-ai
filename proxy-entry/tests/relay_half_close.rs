use proxy_entry::connection::{TcpRelayTimeouts, relay_tcp_with_half_close};
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

struct ShutdownErrorTarget {
    state: Arc<Mutex<ShutdownErrorTargetState>>,
}

struct ShutdownErrorTargetState {
    body: VecDeque<u8>,
    body_released: bool,
    read_waker: Option<Waker>,
}

impl ShutdownErrorTarget {
    fn new(body: &[u8]) -> Self {
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

struct PendingShutdownTarget {
    body: VecDeque<u8>,
}

impl PendingShutdownTarget {
    fn new(body: &[u8]) -> Self {
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

#[tokio::test]
async fn relay_keeps_target_response_after_agent_half_close() {
    let (mut target_relay, mut target_peer) = tokio::io::duplex(1024);
    let (mut agent_relay, mut agent_peer) = tokio::io::duplex(1024);
    let relay = tokio::spawn(async move {
        relay_tcp_with_half_close(
            &mut target_relay,
            &mut agent_relay,
            TcpRelayTimeouts::from_durations(
                Some(Duration::from_secs(5)),
                Some(Duration::from_secs(5)),
            ),
        )
        .await
    });

    agent_peer.write_all(b"GET").await.unwrap();
    agent_peer.shutdown().await.unwrap();
    let mut request = [0u8; 3];
    target_peer.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"GET");
    assert_eq!(target_peer.read(&mut [0u8; 1]).await.unwrap(), 0);

    target_peer.write_all(b"complete-body").await.unwrap();
    target_peer.shutdown().await.unwrap();
    let mut response = Vec::new();
    agent_peer.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"complete-body");

    let (up, down) = tokio::time::timeout(Duration::from_secs(5), relay)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!((up, down), (3, b"complete-body".len() as u64));
}

#[tokio::test]
async fn relay_keeps_half_close_when_idle_timeout_disabled() {
    let (mut target_relay, mut target_peer) = tokio::io::duplex(1024);
    let (mut agent_relay, mut agent_peer) = tokio::io::duplex(1024);
    let relay = tokio::spawn(async move {
        relay_tcp_with_half_close(
            &mut target_relay,
            &mut agent_relay,
            TcpRelayTimeouts::from_durations(None, None),
        )
        .await
    });

    agent_peer.write_all(b"GET").await.unwrap();
    agent_peer.shutdown().await.unwrap();
    let mut request = [0u8; 3];
    target_peer.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"GET");
    assert_eq!(target_peer.read(&mut [0u8; 1]).await.unwrap(), 0);

    target_peer.write_all(b"complete-body").await.unwrap();
    target_peer.shutdown().await.unwrap();
    let mut response = Vec::new();
    agent_peer.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"complete-body");
    assert_eq!(relay.await.unwrap().unwrap(), (3, 13));
}

#[tokio::test]
async fn relay_keeps_response_when_request_shutdown_errors() {
    let mut target_relay = ShutdownErrorTarget::new(b"complete-body");
    let (mut agent_relay, mut agent_peer) = tokio::io::duplex(1024);
    let relay = tokio::spawn(async move {
        relay_tcp_with_half_close(
            &mut target_relay,
            &mut agent_relay,
            TcpRelayTimeouts::from_durations(
                Some(Duration::from_secs(5)),
                Some(Duration::from_secs(5)),
            ),
        )
        .await
    });

    agent_peer.write_all(b"GET").await.unwrap();
    agent_peer.shutdown().await.unwrap();
    let mut response = Vec::new();
    agent_peer.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"complete-body");
    assert_eq!(relay.await.unwrap().unwrap(), (3, 13));
}

#[tokio::test]
async fn relay_drains_response_when_request_shutdown_stalls() {
    let mut target_relay = PendingShutdownTarget::new(b"complete-body");
    let (mut agent_relay, mut agent_peer) = tokio::io::duplex(1024);
    let relay = tokio::spawn(async move {
        relay_tcp_with_half_close(
            &mut target_relay,
            &mut agent_relay,
            TcpRelayTimeouts::from_durations(
                Some(Duration::from_millis(100)),
                Some(Duration::from_millis(100)),
            ),
        )
        .await
    });

    agent_peer.write_all(b"GET").await.unwrap();
    agent_peer.shutdown().await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(5),
        agent_peer.read_to_end(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response, b"complete-body");
    assert_eq!(relay.await.unwrap().unwrap(), (3, 13));
}
