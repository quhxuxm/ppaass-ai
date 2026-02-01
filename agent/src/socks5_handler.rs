use crate::connection_pool::{ConnectedStream, ConnectionPool};
use crate::error::{AgentError, Result};
use fast_socks5::server::{
    NoAuthentication, Socks5ServerProtocol, SocksServerError, states::Opened,
};
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{ReplyError, Socks5Command};
use protocol::Address;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tracing::{debug, error, info};

pub async fn handle_socks5_connection(stream: TcpStream, pool: Arc<ConnectionPool>) -> Result<()> {
    info!("Handling SOCKS5 connection");

    // Using the new fast-socks5 1.0 API with Socks5ServerProtocol
    let protocol: Socks5ServerProtocol<TcpStream, Opened> = Socks5ServerProtocol::start(stream);

    // Negotiate authentication - use NoAuthentication for simplicity
    let auth_state = protocol
        .negotiate_auth::<NoAuthentication>(&[NoAuthentication])
        .await
        .map_err(|e: SocksServerError| AgentError::Socks5(e.to_string()))?;

    // Finish authentication and get authenticated state
    let authenticated = Socks5ServerProtocol::finish_auth(auth_state);

    // Read the SOCKS5 command (CONNECT, BIND, etc.)
    let (protocol, command, target_addr) = authenticated
        .read_command()
        .await
        .map_err(|e: SocksServerError| AgentError::Socks5(e.to_string()))?;

    info!("SOCKS5 command: {:?}, target: {:?}", command, target_addr);

    // Only handle CONNECT command
    if command != Socks5Command::TCPConnect {
        let _ = protocol.reply_error(&ReplyError::CommandNotSupported).await;
        return Err(AgentError::Socks5(
            "Only CONNECT command is supported".to_string(),
        ));
    }

    // Convert target address to protocol Address
    let address = convert_target_addr(&target_addr);

    // Get a connected stream from the pool
    let connected_stream = match pool.get_connected_stream(address).await {
        Ok(stream) => {
            info!(
                "Got connected stream from pool, stream_id: {}",
                stream.stream_id()
            );
            stream
        }
        Err(e) => {
            error!("Failed to get stream from pool: {}", e);
            let _ = protocol.reply_error(&ReplyError::HostUnreachable).await;
            return Err(e);
        }
    };

    // Send success reply with a dummy bind address
    let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let mut client_stream = protocol
        .reply_success(bind_addr)
        .await
        .map_err(|e: SocksServerError| AgentError::Socks5(e.to_string()))?;

    info!("SOCKS5 tunnel established, starting data relay");

    // Start bidirectional data relay
    relay_data(&mut client_stream, connected_stream).await
}

fn convert_target_addr(target: &TargetAddr) -> Address {
    match target {
        TargetAddr::Ip(addr) => match addr {
            std::net::SocketAddr::V4(v4) => Address::Ipv4 {
                addr: v4.ip().octets(),
                port: v4.port(),
            },
            std::net::SocketAddr::V6(v6) => Address::Ipv6 {
                addr: v6.ip().octets(),
                port: v6.port(),
            },
        },
        TargetAddr::Domain(host, port) => Address::Domain {
            host: host.clone(),
            port: *port,
        },
    }
}

async fn relay_data(
    client_stream: &mut TcpStream,
    connected_stream: ConnectedStream,
) -> Result<()> {
    // Convert to AsyncRead + AsyncWrite compatible types
    let mut proxy_io = connected_stream.into_async_io();

    // Use tokio's optimized bidirectional copy
    // This is more efficient than manual select loops as it:
    // 1. Uses zero-copy when possible
    // 2. Has optimized buffering
    // 3. Handles backpressure properly
    match tokio::io::copy_bidirectional(client_stream, &mut proxy_io).await {
        Ok((client_to_proxy, proxy_to_client)) => {
            info!(
                "SOCKS5 relay completed: {} bytes client->proxy, {} bytes proxy->client",
                client_to_proxy, proxy_to_client
            );
        }
        Err(e) => {
            // Connection errors are expected when client closes connection
            debug!("SOCKS5 relay ended: {}", e);
        }
    }

    Ok(())
}
