use crate::error::{AgentError, Result};
use crate::pool::ProxyPool;
use fast_socks5::server::{
    Socks5ServerProtocol, NoAuthentication, SocksServerError,
    states::Opened,
};
use fast_socks5::{Socks5Command, ReplyError};
use fast_socks5::util::target_addr::TargetAddr;
use protocol::Address;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info};

pub async fn handle_socks5_connection(stream: TcpStream, pool: ProxyPool) -> Result<()> {
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

    // Get connection from pool
    let proxy_conn = pool
        .get()
        .await
        .map_err(|e| {
            error!("Failed to get connection from pool: {}", e);
            AgentError::Pool(e.to_string())
        })?;

    // Connect to target through proxy
    let stream_id = match proxy_conn.connect_target(address).await {
        Ok(id) => {
            info!("Connected to target via proxy, stream_id: {}", id);
            id
        }
        Err(e) => {
            error!("Failed to connect to target: {}", e);
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
    relay_data(&mut client_stream, proxy_conn, stream_id).await
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
    proxy_conn: deadpool::managed::Object<crate::pool::ProxyConnectionManager>,
    stream_id: String,
) -> Result<()> {
    use std::sync::Arc;

    let proxy_conn = Arc::new(proxy_conn);
    let (mut client_read, mut client_write) = tokio::io::split(client_stream);

    let stream_id_for_send = stream_id.clone();
    let proxy_conn_for_send = Arc::clone(&proxy_conn);

    // Task to read from client and send to proxy
    let client_to_proxy = async move {
        let mut buffer = vec![0u8; 8192];
        loop {
            match client_read.read(&mut buffer).await {
                Ok(0) => {
                    debug!("Client closed connection");
                    let _ = proxy_conn_for_send.send_data(stream_id_for_send.clone(), vec![], true).await;
                    break;
                }
                Ok(n) => {
                    let data = buffer[..n].to_vec();
                    debug!("Received {} bytes from client, forwarding to proxy", n);
                    if let Err(e) = proxy_conn_for_send.send_data(stream_id_for_send.clone(), data, false).await {
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

    let proxy_conn_for_recv = Arc::clone(&proxy_conn);

    // Task to read from proxy and send to client
    let proxy_to_client = async move {
        loop {
            match proxy_conn_for_recv.receive_data().await {
                Ok(data_packet) => {
                    if !data_packet.data.is_empty() {
                        debug!("Received {} bytes from proxy, forwarding to client", data_packet.data.len());
                        if let Err(e) = client_write.write_all(&data_packet.data).await {
                            error!("Failed to write to client: {}", e);
                            break;
                        }
                        let _ = client_write.flush().await;
                    }

                    if data_packet.is_end {
                        debug!("Proxy indicated end of stream");
                        break;
                    }
                }
                Err(e) => {
                    error!("Failed to receive data from proxy: {}", e);
                    break;
                }
            }
        }
    };

    // Run both tasks concurrently
    tokio::select! {
        _ = client_to_proxy => {},
        _ = proxy_to_client => {},
    }

    info!("SOCKS5 data relay completed");
    Ok(())
}
