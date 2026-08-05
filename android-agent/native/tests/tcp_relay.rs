use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use android_agent::{TcpRelayOptions, relay_tcp_bidirectional};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

#[tokio::test]
async fn tun_relay_keeps_response_after_client_half_close() {
    assert_half_close_keeps_response(TcpRelayOptions::tun("test")).await;
}

#[tokio::test]
async fn http_proxy_relay_keeps_response_after_client_half_close() {
    assert_half_close_keeps_response(TcpRelayOptions::http_proxy("test")).await;
}

async fn assert_half_close_keeps_response(options: TcpRelayOptions<'static>) {
    let (mut client_relay, mut client_peer) = tokio::io::duplex(1024);
    let (mut remote_relay, mut remote_peer) = tokio::io::duplex(1024);

    let relay = tokio::spawn(async move {
        relay_tcp_bidirectional(&mut client_relay, &mut remote_relay, options).await
    });

    client_peer.write_all(b"GET").await.unwrap();
    client_peer.shutdown().await.unwrap();

    let mut request = [0u8; 3];
    remote_peer.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"GET");

    let mut eof_probe = [0u8; 1];
    assert_eq!(remote_peer.read(&mut eof_probe).await.unwrap(), 0);

    remote_peer.write_all(b"complete-body").await.unwrap();
    remote_peer.shutdown().await.unwrap();

    let mut response = Vec::new();
    client_peer.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"complete-body");

    let stats = tokio::time::timeout(Duration::from_secs(5), relay)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(stats.client_to_remote, 3);
    assert_eq!(stats.remote_to_client, b"complete-body".len() as u64);
}

#[tokio::test]
async fn relay_keeps_response_when_request_shutdown_errors() {
    let (mut client_relay, mut client_peer) = tokio::io::duplex(1024);
    let mut remote = ShutdownErrorRemote::new(b"complete-body");

    let relay = tokio::spawn(async move {
        relay_tcp_bidirectional(
            &mut client_relay,
            &mut remote,
            TcpRelayOptions::http_proxy("test"),
        )
        .await
    });

    client_peer.write_all(b"GET").await.unwrap();
    client_peer.shutdown().await.unwrap();

    let mut response = Vec::new();
    client_peer.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"complete-body");

    let stats = tokio::time::timeout(Duration::from_secs(5), relay)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(stats.client_to_remote, 3);
    assert_eq!(stats.remote_to_client, b"complete-body".len() as u64);
}

struct ShutdownErrorRemote {
    state: Arc<Mutex<ShutdownErrorRemoteState>>,
}

struct ShutdownErrorRemoteState {
    body: VecDeque<u8>,
    body_released: bool,
    read_waker: Option<Waker>,
}

impl ShutdownErrorRemote {
    fn new(body: &[u8]) -> Self {
        Self {
            state: Arc::new(Mutex::new(ShutdownErrorRemoteState {
                body: body.iter().copied().collect(),
                body_released: false,
                read_waker: None,
            })),
        }
    }
}

impl AsyncRead for ShutdownErrorRemote {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
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

impl AsyncWrite for ShutdownErrorRemote {
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
