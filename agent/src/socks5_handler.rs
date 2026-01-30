use crate::error::{AgentError, Result};
use crate::multiplexer::{MultiplexedPool, StreamHandle};
use fast_socks5::server::{
    Socks5ServerProtocol, NoAuthentication, SocksServerError,
    states::Opened,
};
use fast_socks5::{Socks5Command, ReplyError};
use fast_socks5::util::target_addr::TargetAddr;
use protocol::Address;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info};

pub async fn handle_socks5_connection(stream: TcpStream, pool: Arc<MultiplexedPool>) -> Result<()> {
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
        return Err(AgentError::Socks5("Only CONNECT command is supported".to_string()));
    }

    // Convert target address to protocol Address
    let address = convert_target_addr(&target_addr);

    // Get a stream from the multiplexed pool
    let stream_handle = match pool.get_stream(address).await {
        Ok(handle) => {
            info!("Got stream from pool, stream_id: {}", handle.stream_id());
            handle
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
    relay_data(&mut client_stream, stream_handle).await
}

fn convert_target_addr(target: &TargetAddr) -> Address {
    match target {
        TargetAddr::Ip(addr) => {
            match addr {
                std::net::SocketAddr::V4(v4) => Address::Ipv4 {
                    addr: v4.ip().octets(),
                    port: v4.port(),
                },
                std::net::SocketAddr::V6(v6) => Address::Ipv6 {
                    addr: v6.ip().octets(),
                    port: v6.port(),
                },
            }
        }
        TargetAddr::Domain(host, port) => Address::Domain {
            host: host.clone(),
            port: *port,
        },
    }
}

async fn relay_data(
    client_stream: &mut TcpStream,
    stream_handle: StreamHandle,
) -> Result<()> {
    let (mut client_read, mut client_write) = tokio::io::split(client_stream);

    // Split stream handle into sender and receiver for concurrent use
    let (stream_sender, mut stream_receiver) = stream_handle.split();

    // Task to read from client and send to proxy
    let client_to_proxy = async move {
        let mut buffer = vec![0u8; 8192];
        loop {
            match client_read.read(&mut buffer).await {
                Ok(0) => {
                    debug!("Client closed connection");
                    let _ = stream_sender.send_data(vec![], true).await;
                    break;
                }
                Ok(n) => {
                    let data = buffer[..n].to_vec();
                    debug!("Received {} bytes from client, forwarding to proxy", n);
                    if let Err(e) = stream_sender.send_data(data, false).await {
                        error!("Failed to send data to proxy: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    error!("Failed to read from client: {}", e);
                    break;
                }
            }
        }
    };

    // Task to read from proxy and send to client
    let proxy_to_client = async move {
        loop {
            match stream_receiver.receive_data().await {
                Some(packet) => {
                    if !packet.data.is_empty() {
                        debug!("Received {} bytes from proxy, forwarding to client", packet.data.len());
                        if let Err(e) = client_write.write_all(&packet.data).await {
                            error!("Failed to write to client: {}", e);
                            break;
                        }
                        if let Err(e) = client_write.flush().await {
                            error!("Failed to flush to client: {}", e);
                            break;
                        }
                    }

                    if packet.is_end {
                        debug!("Proxy indicated end of stream");
                        break;
                    }
                }
                None => {
                    debug!("Stream channel closed");
                    break;
                }
            }
        }
    };

    // Run both tasks concurrently - wait for both to complete
    tokio::join!(client_to_proxy, proxy_to_client);

    info!("SOCKS5 data relay completed");
    Ok(())
}
