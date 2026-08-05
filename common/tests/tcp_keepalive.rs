#[cfg(target_os = "linux")]
use common::PROXY_TCP_USER_TIMEOUT;
use common::configure_proxy_tcp_stream;
use socket2::SockRef;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn configures_proxy_tcp_keepalive_on_tokio_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = stream.shutdown().await;
    });

    let stream = TcpStream::connect(address).await.unwrap();
    configure_proxy_tcp_stream(&stream).unwrap();
    let socket = SockRef::from(&stream);
    assert!(socket.keepalive().unwrap());

    #[cfg(target_os = "linux")]
    assert_eq!(
        socket.tcp_user_timeout().unwrap(),
        Some(PROXY_TCP_USER_TIMEOUT)
    );

    drop(stream);
    server.await.unwrap();
}
