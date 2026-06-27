use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpSocket, TcpStream};

use crate::config::ANDROID_SOCKET_BUFFER_SIZE;

// 直连请求必须 protect socket，避免 Android VPN 模式下把代理出口又送回 TUN。
pub(crate) async fn connect_direct_tcp(target: &str) -> std::io::Result<TcpStream> {
    let mut last_error = None;
    for address in tokio::net::lookup_host(target).await? {
        match connect_direct_socket(address).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last_error = Some(err),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "no target address resolved")
    }))
}

async fn connect_direct_socket(target: SocketAddr) -> std::io::Result<TcpStream> {
    let socket = Socket::new(
        Domain::for_address(target),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    protect_socket(&socket)?;
    tune_socket(&socket);
    socket.set_nonblocking(true)?;

    let socket = TcpSocket::from_std_stream(socket.into());
    socket.connect(target).await
}

fn protect_socket(socket: &Socket) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;

        crate::socket_protector::protect_fd(socket.as_raw_fd())
    }

    #[cfg(not(unix))]
    {
        let _ = socket;
        Ok(())
    }
}

fn tune_socket(socket: &Socket) {
    let _ = socket.set_tcp_nodelay(true);
    let _ = socket.set_recv_buffer_size(ANDROID_SOCKET_BUFFER_SIZE);
    let _ = socket.set_send_buffer_size(ANDROID_SOCKET_BUFFER_SIZE);
}
