use std::io;
use std::net::{SocketAddr, ToSocketAddrs};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::TcpListener;

/// Default backlog for high-concurrency local proxy entrypoints.
///
/// Kernels may clamp this to their system limit (for example macOS `somaxconn`),
/// but passing an explicit large value avoids inheriting smaller library defaults
/// on platforms that allow deeper queues.
pub const DEFAULT_TCP_LISTEN_BACKLOG: i32 = 4096;

pub fn bind_tcp_listener_with_backlog<A>(addr: A, backlog: i32) -> io::Result<TcpListener>
where
    A: ToSocketAddrs,
{
    let mut last_error = None;
    let backlog = backlog.max(1);

    for addr in addr.to_socket_addrs()? {
        match bind_one(addr, backlog) {
            Ok(listener) => return Ok(listener),
            Err(err) => last_error = Some(err),
        }
    }

    Err(last_error.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "no socket addresses resolved")
    }))
}

fn bind_one(addr: SocketAddr, backlog: i32) -> io::Result<TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&SockAddr::from(addr))?;
    socket.listen(backlog)?;

    let listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(listener)
}
