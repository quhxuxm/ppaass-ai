use socket2::{SockRef, Socket, TcpKeepalive};
use std::io;
use std::time::Duration;
use tokio::net::TcpStream;

pub const PROXY_TCP_KEEPALIVE_TIME: Duration = Duration::from_secs(10);
pub const PROXY_TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
pub const PROXY_TCP_KEEPALIVE_RETRIES: u32 = 3;
pub const PROXY_TCP_USER_TIMEOUT: Duration = Duration::from_secs(20);

pub fn configure_proxy_tcp_socket(socket: &Socket) -> io::Result<()> {
    configure_socket(socket)
}

pub fn configure_proxy_tcp_stream(stream: &TcpStream) -> io::Result<()> {
    let socket = SockRef::from(stream);
    configure_socket(&socket)
}

fn configure_socket(socket: &Socket) -> io::Result<()> {
    let keepalive = TcpKeepalive::new()
        .with_time(PROXY_TCP_KEEPALIVE_TIME)
        .with_interval(PROXY_TCP_KEEPALIVE_INTERVAL)
        .with_retries(PROXY_TCP_KEEPALIVE_RETRIES);
    socket.set_tcp_keepalive(&keepalive)?;
    set_tcp_user_timeout(socket)
}

#[cfg(target_os = "linux")]
fn set_tcp_user_timeout(socket: &Socket) -> io::Result<()> {
    socket.set_tcp_user_timeout(Some(PROXY_TCP_USER_TIMEOUT))
}

#[cfg(not(target_os = "linux"))]
fn set_tcp_user_timeout(_socket: &Socket) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket2::SockRef;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn configures_proxy_tcp_keepalive_on_tokio_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = stream.shutdown().await;
        });

        let stream = TcpStream::connect(addr).await.unwrap();
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
}
