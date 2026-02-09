use crate::connection_pool::{ConnectedStream, ConnectionPool};
use crate::error::{AgentError, Result};
use dashmap::DashMap;
use fast_socks5::server::{
    states::{CommandRead, Opened}, NoAuthentication, Socks5ServerProtocol,
    SocksServerError,
};
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{ReplyError, Socks5Command};
use protocol::{Address, TransportProtocol};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc::{channel, Sender};
use tracing::{debug, error, info, instrument};

#[instrument(skip(stream, pool))]
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

    match command {
        Socks5Command::TCPConnect => handle_tcp_connect(protocol, target_addr, pool).await,
        Socks5Command::TCPBind => handle_tcp_bind(protocol, target_addr, pool).await,
        Socks5Command::UDPAssociate => handle_udp_associate(protocol, target_addr, pool).await,
    }
}

async fn handle_tcp_connect(
    protocol: Socks5ServerProtocol<TcpStream, CommandRead>,
    target_addr: TargetAddr,
    pool: Arc<ConnectionPool>,
) -> Result<()> {
    // Convert target address to protocol Address
    let address = convert_target_addr(&target_addr);

    // Get a connected stream from the pool
    let connected_stream = match pool
        .as_ref()
        .get_connected_stream(address, TransportProtocol::Tcp)
        .await
    {
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

async fn handle_tcp_bind(
    protocol: Socks5ServerProtocol<TcpStream, CommandRead>,
    target_addr: TargetAddr,
    pool: Arc<ConnectionPool>,
) -> Result<()> {
    info!("Handling SOCKS5 BIND command for target: {:?}", target_addr);

    // Convert target address to protocol Address
    let address = convert_target_addr(&target_addr);

    // Bind a TCP socket on a random port to accept incoming connections
    let listener = TcpListener::bind("0.0.0.0:0")
        .await
        .map_err(|e| AgentError::Socks5(format!("Failed to bind TCP socket: {}", e)))?;

    let bind_addr = listener
        .local_addr()
        .map_err(|e| AgentError::Socks5(format!("Failed to get local addr: {}", e)))?;

    info!("SOCKS5 BIND listening on {}", bind_addr);

    // Send first success reply with the bind address
    let _tcp_stream = protocol
        .reply_success(bind_addr)
        .await
        .map_err(|e: SocksServerError| AgentError::Socks5(e.to_string()))?;

    // Wait for an incoming connection on the bind address
    match tokio::time::timeout(std::time::Duration::from_secs(30), listener.accept()).await {
        Ok(Ok((mut incoming_stream, peer_addr))) => {
            info!(
                "SOCKS5 BIND: Accepted connection from {} for target {:?}",
                peer_addr, address
            );

            // Get a connected stream from the pool for the target
            let connected_stream = match pool
                .as_ref()
                .get_connected_stream(address, TransportProtocol::Tcp)
                .await
            {
                Ok(stream) => {
                    info!(
                        "Got connected stream from pool, stream_id: {}",
                        stream.stream_id()
                    );
                    stream
                }
                Err(e) => {
                    error!("Failed to get stream from pool: {}", e);
                    return Err(e);
                }
            };

            info!("SOCKS5 BIND tunnel established, starting data relay");

            // Start bidirectional data relay
            relay_data(&mut incoming_stream, connected_stream).await
        }
        Ok(Err(e)) => {
            error!("Failed to accept incoming connection: {}", e);
            Err(AgentError::Socks5(format!(
                "Failed to accept connection: {}",
                e
            )))
        }
        Err(_) => {
            error!("SOCKS5 BIND: Timeout waiting for incoming connection");
            Err(AgentError::Socks5(
                "Timeout waiting for incoming connection".to_string(),
            ))
        }
    }
}

async fn handle_udp_associate(
    protocol: Socks5ServerProtocol<TcpStream, CommandRead>,
    _target_addr: TargetAddr,
    pool: Arc<ConnectionPool>,
) -> Result<()> {
    info!("Handling UDP ASSOCIATE");

    // Bind a UDP socket on a random port
    let udp_socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| AgentError::Socks5(format!("Failed to bind UDP socket: {}", e)))?;

    let bind_addr = udp_socket
        .local_addr()
        .map_err(|e| AgentError::Socks5(format!("Failed to get local addr: {}", e)))?;

    info!("UDP Associate bound to {}", bind_addr);

    // Reply success with the bind address
    let mut tcp_stream = protocol
        .reply_success(bind_addr)
        .await
        .map_err(|e: SocksServerError| AgentError::Socks5(e.to_string()))?;

    let udp_socket = Arc::new(udp_socket);
    let pool = pool.clone();

    // The client sends UDP packets to `bind_addr`

    // We need to keep the TCP stream alive to maintain association
    let keep_alive = async move {
        let mut buf = [0u8; 1];
        // If read returns 0 (EOF) or error, the client closed connection
        let _ = tcp_stream.read(&mut buf).await;
        debug!("UDP Associate TCP control channel closed");
    };

    let udp_handler = process_udp_traffic(udp_socket, pool);

    tokio::select! {
        _ = keep_alive => {
           // Client closed TCP connection, we should stop
        }
        result = udp_handler => {
            if let Err(e) = result {
                error!("UDP handler error: {}", e);
            }
        }
    }

    Ok(())
}

async fn process_udp_traffic(udp_socket: Arc<UdpSocket>, pool: Arc<ConnectionPool>) -> Result<()> {
    let mut buf = [0u8; 65535];
    type StreamMap = DashMap<String, Sender<Vec<u8>>>;
    let streams: Arc<StreamMap> = Arc::new(DashMap::new());

    loop {
        let (n, client_addr) = udp_socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| AgentError::Socks5(e.to_string()))?;
        let packet_data = &buf[..n];
        // Parse SOCKS5 UDP header
        if n < 10 {
            continue;
        }
        if packet_data[0] != 0 || packet_data[1] != 0 {
            continue;
        }
        if packet_data[2] != 0 {
            continue;
        }
        let address_result = parse_udp_address(&packet_data[3..]);
        let (dest_addr, header_len) = match address_result {
            Ok(res) => res,
            Err(e) => {
                error!("Failed to parse UDP dest address: {}", e);
                continue;
            }
        };
        let payload = packet_data[3 + header_len..].to_vec();
        let dest_key = format!("{:?}", dest_addr);
        debug!("Parse UDP destination address: {:?}", dest_addr);
        if !streams.contains_key(&dest_key) {
            info!("New UDP session for destination: {:?}", dest_addr);
            match pool
                .as_ref()
                .get_connected_stream(dest_addr.clone(), TransportProtocol::Udp)
                .await
            {
                Ok(connected_stream) => {
                    let (tx, mut rx) = channel::<Vec<u8>>(32);
                    streams.insert(dest_key.clone(), tx);
                    let udp_socket_clone = udp_socket.clone();
                    let dest_addr_clone = dest_addr.clone();
                    let streams_clone = streams.clone();
                    let dest_key_clone = dest_key.clone();
                    tokio::spawn(async move {
                        // Use the AsyncRead + AsyncWrite wrapper to properly encode data as DataPacket messages

                        let proxy_io = connected_stream.into_async_io();
                        let (mut reader, mut writer) = tokio::io::split(proxy_io);
                        let write_task = async {
                            while let Some(data) = rx.recv().await {
                                use tokio::io::AsyncWriteExt;
                                debug!(
                                    "Write UDP data to proxy for target: {dest_addr:?}\n{}",
                                    pretty_hex::pretty_hex(&data)
                                );
                                if let Err(e) = writer.write_all(&data).await {
                                    error!("Failed to write to proxy UDP stream: {}", e);
                                    break;
                                }
                                if let Err(e) = writer.flush().await {
                                    error!("Failed to flush to proxy UDP stream: {}", e);
                                    break;
                                }
                            }
                        };
                        let read_task = async {
                            let mut read_buf = [0u8; 65535];
                            loop {
                                debug!("Waiting for UDP packet from target: {dest_addr:?}",);
                                match reader.read(&mut read_buf).await {
                                    Ok(0) => break,
                                    Ok(len) => {
                                        let data = &read_buf[..len];
                                        debug!(
                                            "Read UDP data from proxy for target: {dest_addr:?}\n{}",
                                            pretty_hex::pretty_hex(&data)
                                        );
                                        match create_udp_packet(&dest_addr_clone, data) {
                                            Ok(packet) => {
                                                if let Err(e) = udp_socket_clone
                                                    .send_to(&packet, client_addr)
                                                    .await
                                                {
                                                    error!(
                                                        "Failed to send UDP packet to client: {}",
                                                        e
                                                    );
                                                }
                                            }
                                            Err(e) => error!("Failed to create UDP packet: {}", e),
                                        }
                                    }
                                    Err(e) => {
                                        error!("Error reading from proxy UDP stream: {}", e);
                                        break;
                                    }
                                }
                            }
                        };
                        tokio::select! {
                            _ = write_task => {}
                            _ = read_task => {}
                        }
                        streams_clone.remove(&dest_key_clone);
                        info!("UDP session finished: {:?}", dest_addr_clone);
                    });
                }
                Err(e) => {
                    error!("Failed to connect to proxy for UDP: {}", e);
                    continue;
                }
            }
        }
        let sender = streams.get(&dest_key).map(|s| s.clone());
        if let Some(sender) = sender {
            let _ = sender.send(payload).await;
        }
    }
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

fn parse_udp_address(buf: &[u8]) -> Result<(Address, usize)> {
    if buf.is_empty() {
        return Err(AgentError::Socks5("Invalid UDP header".to_string()));
    }
    let atyp = buf[0];
    match atyp {
        1 => {
            if buf.len() < 7 {
                return Err(AgentError::Socks5("Invalid IPv4 address".to_string()));
            }
            let mut ip_bytes = [0u8; 4];
            ip_bytes.copy_from_slice(&buf[1..5]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok((
                Address::Ipv4 {
                    addr: ip_bytes,
                    port,
                },
                7,
            ))
        }
        3 => {
            let len = buf[1] as usize;
            if buf.len() < 2 + len + 2 {
                return Err(AgentError::Socks5("Invalid Domain address".to_string()));
            }
            let domain = String::from_utf8_lossy(&buf[2..2 + len]).to_string();
            let port = u16::from_be_bytes([buf[2 + len], buf[2 + len + 1]]);
            Ok((Address::Domain { host: domain, port }, 2 + len + 2))
        }
        4 => {
            if buf.len() < 19 {
                return Err(AgentError::Socks5("Invalid IPv6 address".to_string()));
            }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&buf[1..17]);
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok((
                Address::Ipv6 {
                    addr: ip_bytes,
                    port,
                },
                19,
            ))
        }
        _ => Err(AgentError::Socks5("Unsupported address type".to_string())),
    }
}

fn create_udp_packet(addr: &Address, data: &[u8]) -> Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(10 + data.len());
    packet.extend_from_slice(&[0, 0, 0]);
    match addr {
        Address::Ipv4 { addr, port } => {
            packet.push(1);
            packet.extend_from_slice(addr);
            packet.extend_from_slice(&port.to_be_bytes());
        }
        Address::Domain { host, port } => {
            packet.push(3);
            if host.len() > 255 {
                return Err(AgentError::Socks5("Domain too long".to_string()));
            }
            packet.push(host.len() as u8);
            packet.extend_from_slice(host.as_bytes());
            packet.extend_from_slice(&port.to_be_bytes());
        }
        Address::Ipv6 { addr, port } => {
            packet.push(4);
            packet.extend_from_slice(addr);
            packet.extend_from_slice(&port.to_be_bytes());
        }
    }
    packet.extend_from_slice(data);
    Ok(packet)
}
