use crate::error::{AgentError, Result};
use crate::pool::ProxyPool;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use protocol::Address;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info};

pub async fn handle_http_connection(stream: TcpStream, pool: ProxyPool) -> Result<()> {
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
    pool: ProxyPool,
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
    pool: ProxyPool,
) -> std::result::Result<Response<Full<Bytes>>, hyper::Error> {
    let uri = req.uri().clone();
    let host = uri.host().unwrap_or("").to_string();
    let port = uri.port_u16().unwrap_or(443);

    info!("CONNECT request to {}:{}", host, port);

    let address = Address::Domain { host: host.clone(), port };

    // Get connection from pool
    let proxy_conn = match pool.get().await {
        Ok(conn) => conn,
        Err(e) => {
            error!("Failed to get connection from pool: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("Failed to connect to proxy")))
                .unwrap());
        }
    };

    // Connect to target through proxy
    let stream_id = match proxy_conn.connect_target(address).await {
        Ok(id) => {
            info!("Connected to target via proxy, stream_id: {}", id);
            id
        }
        Err(e) => {
            error!("Failed to connect to target: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("Failed to connect to target")))
                .unwrap());
        }
    };

    // Spawn a task to handle the upgraded connection
    tokio::spawn(async move {
        match hyper::upgrade::on(&mut req).await {
            Ok(upgraded) => {
                info!("HTTP CONNECT upgrade successful for {}:{}", host, port);
                if let Err(e) = tunnel(upgraded, proxy_conn, stream_id).await {
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
    proxy_conn: deadpool::managed::Object<crate::pool::ProxyConnectionManager>,
    stream_id: String,
) -> std::result::Result<(), AgentError> {
    use std::sync::Arc;

    let io = TokioIo::new(upgraded);
    let (mut read_half, mut write_half) = tokio::io::split(io);

    let proxy_conn = Arc::new(proxy_conn);
    let stream_id_for_send = stream_id.clone();
    let proxy_conn_for_send = Arc::clone(&proxy_conn);

    // Read from client and send to proxy
    let client_to_proxy = async move {
        let mut buffer = vec![0u8; 8192];
        loop {
            match read_half.read(&mut buffer).await {
                Ok(0) => {
                    debug!("Client closed CONNECT tunnel");
                    let _ = proxy_conn_for_send.send_data(stream_id_for_send.clone(), vec![], true).await;
                    break;
                }
                Ok(n) => {
                    let data = buffer[..n].to_vec();
                    debug!("CONNECT tunnel: {} bytes client -> proxy", n);
                    if let Err(e) = proxy_conn_for_send.send_data(stream_id_for_send.clone(), data, false).await {
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

    let proxy_conn_for_recv = Arc::clone(&proxy_conn);

    // Read from proxy and send to client
    let proxy_to_client = async move {
        loop {
            match proxy_conn_for_recv.receive_data().await {
                Ok(data_packet) => {
                    if !data_packet.data.is_empty() {
                        debug!("CONNECT tunnel: {} bytes proxy -> client", data_packet.data.len());
                        if let Err(e) = write_half.write_all(&data_packet.data).await {
                            error!("Failed to write to CONNECT tunnel client: {}", e);
                            break;
                        }
                        let _ = write_half.flush().await;
                    }

                    if data_packet.is_end {
                        debug!("Proxy indicated end of CONNECT tunnel stream");
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

    tokio::select! {
        _ = client_to_proxy => {},
        _ = proxy_to_client => {},
    }

    info!("CONNECT tunnel closed");
    Ok(())
}

async fn handle_regular_request(
    req: Request<Incoming>,
    pool: ProxyPool,
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

    // Get connection from pool
    let proxy_conn = match pool.get().await {
        Ok(conn) => conn,
        Err(e) => {
            error!("Failed to get connection from pool: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("Failed to connect to proxy")))
                .unwrap());
        }
    };

    // Connect to target through proxy
    let stream_id = match proxy_conn.connect_target(address).await {
        Ok(id) => id,
        Err(e) => {
            error!("Failed to connect to target: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("Failed to connect to target")))
                .unwrap());
        }
    };

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
    if let Err(e) = proxy_conn.send_data(stream_id.clone(), full_request, false).await {
        error!("Failed to send request to proxy: {}", e);
        return Ok(Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Full::new(Bytes::from("Failed to send request")))
            .unwrap());
    }

    // Receive response from proxy
    let mut response_data = Vec::new();
    loop {
        match proxy_conn.receive_data().await {
            Ok(data_packet) => {
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
            Err(e) => {
                error!("Failed to receive response: {}", e);
                return Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Full::new(Bytes::from("Failed to receive response")))
                    .unwrap());
            }
        }
    }

    // Parse and return the response (simplified)
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::from(response_data)))
        .unwrap())
}
