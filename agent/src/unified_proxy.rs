use crate::{config::AgentConfig, connection_pool::ConnectionPool, http_proxy, socks5_proxy};
use anyhow::Result;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};

/// Auto-detect protocol by peeking at the first few bytes
async fn detect_protocol(stream: &mut TcpStream) -> Result<Protocol> {
    let mut buf = [0u8; 1];

    // Peek at the first byte without consuming it
    stream.peek(&mut buf).await?;

    match buf[0] {
        // SOCKS5 version byte
        0x05 => Ok(Protocol::Socks5),
        // HTTP methods start with ASCII letters
        b'C' | b'D' | b'G' | b'H' | b'O' | b'P' | b'T' => Ok(Protocol::Http),
        _ => {
            // Default to HTTP for unknown protocols
            debug!("Unknown protocol, defaulting to HTTP");
            Ok(Protocol::Http)
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Protocol {
    Http,
    Socks5,
}

pub async fn start_server(config: Arc<AgentConfig>, pool: Arc<ConnectionPool>) -> Result<()> {
    let listener = TcpListener::bind(&config.listen_addr).await?;
    info!(
        "Unified proxy listening on {} (auto-detecting HTTP/SOCKS5)",
        config.listen_addr
    );

    loop {
        let (mut stream, addr) = listener.accept().await?;
        debug!("Accepted connection from {}", addr);

        let config = config.clone();
        let pool = pool.clone();

        tokio::spawn(async move {
            match detect_protocol(&mut stream).await {
                Ok(Protocol::Http) => {
                    debug!("Detected HTTP protocol from {}", addr);
                    if let Err(e) = http_proxy::handle_connection(stream, config, pool).await {
                        error!("HTTP connection error from {}: {}", addr, e);
                    }
                }
                Ok(Protocol::Socks5) => {
                    debug!("Detected SOCKS5 protocol from {}", addr);
                    if let Err(e) = socks5_proxy::handle_connection(stream, pool).await {
                        error!("SOCKS5 connection error from {}: {}", addr, e);
                    }
                }
                Err(e) => {
                    error!("Protocol detection error from {}: {}", addr, e);
                }
            }
        });
    }
}
