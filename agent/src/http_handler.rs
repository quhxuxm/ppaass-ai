use crate::error::{AgentError, Result};
use crate::connection_pool::{ConnectionPool, ConnectedStream};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use protocol::Address;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info};

/// Extract host and port from HTTP request, handling IPv6 addresses correctly
fn extract_host_port(req: &Request<Incoming>, uri: &Uri) -> (String, u16) {
    // Try to get from Host header first
    if let Some(host_header) = req.headers()
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
    {
        // Handle IPv6 addresses: [::1]:8080
        if host_header.starts_with('[') {
            // IPv6 format
            if let Some(bracket_end) = host_header.find(']') {
                let host = host_header[1..bracket_end].to_string();
                let port = if host_header.len() > bracket_end + 2 && host_header.as_bytes()[bracket_end + 1] == b':' {
                    host_header[bracket_end + 2..].parse().unwrap_or(80)
                } else {
                    80
                };
                return (host, port);
            }
        }

        // Regular host:port format
        if let Some(colon_pos) = host_header.rfind(':') {
            // Check if there's a port number after the colon
            if let Ok(port) = host_header[colon_pos + 1..].parse::<u16>() {
                return (host_header[..colon_pos].to_string(), port);
            }
        }

        // No port in header
        return (host_header.to_string(), uri.port_u16().unwrap_or(80));
    }

    // Fall back to URI
    let host = uri.host().unwrap_or("").to_string();
    let port = uri.port_u16().unwrap_or(80);
    (host, port)
}

pub async fn handle_http_connection(stream: TcpStream, pool: Arc<ConnectionPool>) -> Result<()> {
    info!("Handling HTTP connection");

    let io = TokioIo::new(stream);
    let pool_clone = pool.clone();

    let service = service_fn(move |req| {
        let pool = pool_clone.clone();
        async move { handle_http_request(req, pool).await }
    });

    let conn = http1::Builder::new()
        .serve_connection(io, service)
        .with_upgrades();

    if let Err(e) = conn.await {
        error!("Error serving HTTP connection: {}", e);
    }

    Ok(())
}

async fn handle_http_request(
    req: Request<Incoming>,
    pool: Arc<ConnectionPool>,
) -> std::result::Result<Response<Full<Bytes>>, hyper::Error> {
    info!("HTTP request: {} {}", req.method(), req.uri());

    if req.method() == Method::CONNECT {
        handle_connect(req, pool).await
    } else {
        handle_regular_request(req, pool).await
    }
}

async fn handle_connect(
    mut req: Request<Incoming>,
    pool: Arc<ConnectionPool>,
) -> std::result::Result<Response<Full<Bytes>>, hyper::Error> {
    let uri = req.uri().clone();
    let host = uri.host().unwrap_or("").to_string();
    let port = uri.port_u16().unwrap_or(443);

    info!("CONNECT request to {}:{}", host, port);

    let address = Address::Domain { host: host.clone(), port };

    // Get connected stream from pool
    let connected_stream = match pool.get_connected_stream(address).await {
        Ok(stream) => {
            info!("Got connected stream from pool, stream_id: {}", stream.stream_id());
            stream
        }
        Err(e) => {
            error!("Failed to get stream from pool: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("Failed to connect to proxy")))
                .unwrap());
        }
    };

    // Spawn a task to handle the upgraded connection
    tokio::spawn(async move {
        match hyper::upgrade::on(&mut req).await {
            Ok(upgraded) => {
                info!("HTTP CONNECT upgrade successful for {}:{}", host, port);
                if let Err(e) = tunnel(upgraded, connected_stream).await {
                    error!("Tunnel error: {}", e);
                }
            }
            Err(e) => {
                error!("HTTP CONNECT upgrade failed: {}", e);
            }
        }
    });

    // Send 200 Connection Established response
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::new()))
        .unwrap())
}

async fn tunnel(
    upgraded: Upgraded,
    connected_stream: ConnectedStream,
) -> std::result::Result<(), AgentError> {
    let io = TokioIo::new(upgraded);
    let (mut read_half, mut write_half) = tokio::io::split(io);

    // Split connected stream into sender and receiver for concurrent use
    let (stream_sender, mut stream_receiver) = connected_stream.split();

    // Use select to handle both directions and terminate when either ends
    let mut buffer = vec![0u8; 8192];
    let mut client_closed = false;
    let mut proxy_closed = false;

    loop {
        if client_closed && proxy_closed {
            break;
        }

        tokio::select! {
            // Read from client and send to proxy
            result = read_half.read(&mut buffer), if !client_closed => {
                match result {
                    Ok(0) => {
                        debug!("Client closed CONNECT tunnel");
                        let _ = stream_sender.send_data(vec![], true).await;
                        client_closed = true;
                    }
                    Ok(n) => {
                        let data = buffer[..n].to_vec();
                        debug!("CONNECT tunnel: {} bytes client -> proxy", n);
                        if let Err(e) = stream_sender.send_data(data, false).await {
                            error!("Failed to send data to proxy: {}", e);
                            client_closed = true;
                        }
                    }
                    Err(e) => {
                        error!("Failed to read from CONNECT tunnel client: {}", e);
                        let _ = stream_sender.send_data(vec![], true).await;
                        client_closed = true;
                    }
                }
            }

            // Read from proxy and send to client
            packet = stream_receiver.receive_data(), if !proxy_closed => {
                match packet {
                    Some(packet) => {
                        if !packet.data.is_empty() {
                            debug!("CONNECT tunnel: {} bytes proxy -> client", packet.data.len());
                            if let Err(e) = write_half.write_all(&packet.data).await {
                                error!("Failed to write to CONNECT tunnel client: {}", e);
                                proxy_closed = true;
                                continue;
                            }
                            if let Err(e) = write_half.flush().await {
                                error!("Failed to flush to CONNECT tunnel client: {}", e);
                                proxy_closed = true;
                                continue;
                            }
                        }

                        if packet.is_end {
                            debug!("Proxy indicated end of CONNECT tunnel stream");
                            proxy_closed = true;
                        }
                    }
                    None => {
                        debug!("Stream channel closed");
                        proxy_closed = true;
                    }
                }
            }
        }
    }

    info!("CONNECT tunnel closed");
    Ok(())
}

async fn handle_regular_request(
    req: Request<Incoming>,
    pool: Arc<ConnectionPool>,
) -> std::result::Result<Response<Full<Bytes>>, hyper::Error> {
    let uri = req.uri();

    // Extract host and port from Host header or URI
    let (host, port) = extract_host_port(&req, uri);

    info!("HTTP request to {}:{}", host, port);

    if host.is_empty() {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::new(Bytes::from("Missing host")))
            .unwrap());
    }

    let address = Address::Domain { host: host.clone(), port };

    // Get connected stream from pool
    let connected_stream = match pool.get_connected_stream(address).await {
        Ok(stream) => stream,
        Err(e) => {
            error!("Failed to get stream from pool: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("Failed to connect to proxy")))
                .unwrap());
        }
    };

    // Split stream for send/receive
    let (stream_sender, mut stream_receiver) = connected_stream.split();

    // Build the HTTP request to send to target
    let path = uri.path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    // Format Host header - only include port if non-standard
    let host_header = if port == 80 {
        host.clone()
    } else {
        format!("{}:{}", host, port)
    };

    let mut request_bytes = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\n",
        req.method(), path, host_header
    );

    // Add other headers, but modify Connection header
    let mut has_connection = false;
    for (name, value) in req.headers() {
        if name == hyper::header::HOST {
            continue;
        }
        if name == hyper::header::CONNECTION {
            has_connection = true;
            // Force close connection to get complete response
            request_bytes.push_str("Connection: close\r\n");
            continue;
        }
        if let Ok(v) = value.to_str() {
            request_bytes.push_str(&format!("{}: {}\r\n", name, v));
        }
    }

    // Add Connection: close if not present to ensure we get complete response
    if !has_connection {
        request_bytes.push_str("Connection: close\r\n");
    }

    request_bytes.push_str("\r\n");

    // Collect body
    let body_bytes = match req.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            error!("Failed to collect request body: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from("Failed to read request body")))
                .unwrap());
        }
    };

    let mut full_request = request_bytes.into_bytes();
    full_request.extend_from_slice(&body_bytes);

    debug!("Sending HTTP request: {} bytes", full_request.len());

    // Send request to proxy (don't send is_end yet - we need the response first)
    if let Err(e) = stream_sender.send_data(full_request, false).await {
        error!("Failed to send request to proxy: {}", e);
        return Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Full::new(Bytes::from("Failed to send request")))
            .unwrap());
    }

    // Receive complete response from proxy
    let mut response_data = Vec::new();
    loop {
        match stream_receiver.receive_data().await {
            Some(data_packet) => {
                debug!("Received {} bytes from proxy", data_packet.data.len());
                response_data.extend_from_slice(&data_packet.data);
                if data_packet.is_end {
                    debug!("Received end of stream signal");
                    break;
                }
            }
            None => {
                debug!("Stream channel closed");
                break;
            }
        }
    }

    // Now signal end of stream (cleanup)
    let _ = stream_sender.send_data(vec![], true).await;

    debug!("Total response size: {} bytes", response_data.len());

    if response_data.is_empty() {
        return Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Full::new(Bytes::from("No response from target")))
            .unwrap());
    }

    // Parse the HTTP response
    match parse_http_response(&response_data) {
        Ok((status, headers, body)) => {
            let mut builder = Response::builder().status(status);
            for (name, value) in headers {
                builder = builder.header(name, value);
            }
            Ok(builder.body(Full::new(Bytes::from(body))).unwrap())
        }
        Err(e) => {
            error!("Failed to parse HTTP response: {}", e);
            // Return raw response as fallback
            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::from(response_data)))
                .unwrap())
        }
    }
}

/// Parse HTTP response into status, headers, and body
fn parse_http_response(data: &[u8]) -> std::result::Result<(StatusCode, Vec<(String, String)>, Vec<u8>), String> {
    // Find header/body separator
    let header_end = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("No header/body separator found")?;

    let header_bytes = &data[..header_end];
    let body = data[header_end + 4..].to_vec();

    let header_str = std::str::from_utf8(header_bytes)
        .map_err(|e| format!("Invalid header encoding: {}", e))?;

    let mut lines = header_str.lines();

    // Parse status line
    let status_line = lines.next().ok_or("Missing status line")?;
    let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err("Invalid status line".to_string());
    }

    let status_code: u16 = parts[1].parse()
        .map_err(|_| "Invalid status code")?;
    let status = StatusCode::from_u16(status_code)
        .map_err(|_| "Invalid status code")?;

    // Parse headers
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(pos) = line.find(':') {
            let name = line[..pos].trim().to_string();
            let value = line[pos + 1..].trim().to_string();
            // Skip hop-by-hop headers
            if !name.eq_ignore_ascii_case("transfer-encoding")
                && !name.eq_ignore_ascii_case("connection")
                && !name.eq_ignore_ascii_case("keep-alive")
                && !name.eq_ignore_ascii_case("proxy-authenticate")
                && !name.eq_ignore_ascii_case("proxy-authorization")
                && !name.eq_ignore_ascii_case("te")
                && !name.eq_ignore_ascii_case("trailer")
                && !name.eq_ignore_ascii_case("upgrade") {
                headers.push((name, value));
            }
        }
    }

    Ok((status, headers, body))
}
