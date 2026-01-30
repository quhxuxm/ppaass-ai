use crate::error::{AgentError, Result};
use crate::multiplexer::{MultiplexedPool, StreamHandle};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use protocol::Address;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info};

pub async fn handle_http_connection(stream: TcpStream, pool: Arc<MultiplexedPool>) -> Result<()> {
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
    pool: Arc<MultiplexedPool>,
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
    pool: Arc<MultiplexedPool>,
) -> std::result::Result<Response<Full<Bytes>>, hyper::Error> {
    let uri = req.uri().clone();
    let host = uri.host().unwrap_or("").to_string();
    let port = uri.port_u16().unwrap_or(443);

    info!("CONNECT request to {}:{}", host, port);

    let address = Address::Domain { host: host.clone(), port };

    // Get stream from multiplexed pool
    let stream_handle = match pool.get_stream(address).await {
        Ok(handle) => {
            info!("Got stream from pool, stream_id: {}", handle.stream_id());
            handle
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
                if let Err(e) = tunnel(upgraded, stream_handle).await {
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
    stream_handle: StreamHandle,
) -> std::result::Result<(), AgentError> {
    let io = TokioIo::new(upgraded);
    let (mut read_half, mut write_half) = tokio::io::split(io);

    // Split stream handle into sender and receiver for concurrent use
    let (stream_sender, mut stream_receiver) = stream_handle.split();

    // Read from client and send to proxy
    let client_to_proxy = async move {
        let mut buffer = vec![0u8; 8192];
        loop {
            match read_half.read(&mut buffer).await {
                Ok(0) => {
                    debug!("Client closed CONNECT tunnel");
                    let _ = stream_sender.send_data(vec![], true).await;
                    break;
                }
                Ok(n) => {
                    let data = buffer[..n].to_vec();
                    debug!("CONNECT tunnel: {} bytes client -> proxy", n);
                    if let Err(e) = stream_sender.send_data(data, false).await {
                        error!("Failed to send data to proxy: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    error!("Failed to read from CONNECT tunnel client: {}", e);
                    break;
                }
            }
        }
    };

    // Read from proxy and send to client
    let proxy_to_client = async move {
        loop {
            match stream_receiver.receive_data().await {
                Some(packet) => {
                    if !packet.data.is_empty() {
                        debug!("CONNECT tunnel: {} bytes proxy -> client", packet.data.len());
                        if let Err(e) = write_half.write_all(&packet.data).await {
                            error!("Failed to write to CONNECT tunnel client: {}", e);
                            break;
                        }
                        if let Err(e) = write_half.flush().await {
                            error!("Failed to flush to CONNECT tunnel client: {}", e);
                            break;
                        }
                    }

                    if packet.is_end {
                        debug!("Proxy indicated end of CONNECT tunnel stream");
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

    info!("CONNECT tunnel closed");
    Ok(())
}

async fn handle_regular_request(
    req: Request<Incoming>,
    pool: Arc<MultiplexedPool>,
) -> std::result::Result<Response<Full<Bytes>>, hyper::Error> {
    let uri = req.uri();

    // Extract host from Host header or URI
    let host = req.headers()
        .get(hyper::header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .or_else(|| uri.host().map(|h| h.to_string()))
        .unwrap_or_default();

    let port = uri.port_u16().unwrap_or(80);

    info!("HTTP request to {}:{}", host, port);

    if host.is_empty() {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::new(Bytes::from("Missing host")))
            .unwrap());
    }

    let address = Address::Domain { host: host.clone(), port };

    // Get stream from multiplexed pool
    let stream_handle = match pool.get_stream(address).await {
        Ok(handle) => handle,
        Err(e) => {
            error!("Failed to get stream from pool: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("Failed to connect to proxy")))
                .unwrap());
        }
    };

    // Split stream handle for send/receive
    let (stream_sender, mut stream_receiver) = stream_handle.split();

    // Build the HTTP request to send to target
    let path = uri.path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let mut request_bytes = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\n",
        req.method(), path, host
    );

    // Add other headers
    for (name, value) in req.headers() {
        if name != hyper::header::HOST {
            if let Ok(v) = value.to_str() {
                request_bytes.push_str(&format!("{}: {}\r\n", name, v));
            }
        }
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

    // Send request to proxy
    if let Err(e) = stream_sender.send_data(full_request, false).await {
        error!("Failed to send request to proxy: {}", e);
        return Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Full::new(Bytes::from("Failed to send request")))
            .unwrap());
    }

    // Receive response from proxy
    let mut response_data = Vec::new();
    loop {
        match stream_receiver.receive_data().await {
            Some(data_packet) => {
                response_data.extend_from_slice(&data_packet.data);
                if data_packet.is_end {
                    break;
                }
                // Simple check for end of HTTP response
                if response_data.len() > 4 {
                    // Check for Content-Length or chunked to know when complete
                    // For simplicity, we'll just return after first data packet
                    break;
                }
            }
            None => {
                debug!("Stream channel closed");
                break;
            }
        }
    }

    // Parse and return the response (simplified)
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::from(response_data)))
        .unwrap())
}
