use crate::connection_pool::{ConnectedStream, ConnectionPool};
use crate::error::{AgentError, Result};
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use protocol::Address;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tracing::{debug, error, info};

/// Extract host and port from HTTP request, handling IPv6 addresses correctly
fn extract_host_port(req: &Request<Incoming>, uri: &Uri) -> (String, u16) {
    // Try to get from Host header first
    if let Some(host_header) = req
        .headers()
        .get(hyper::header::HOST)
        // Explicitly annotate closure argument type to help inference
        .and_then(|h: &hyper::header::HeaderValue| h.to_str().ok())
    {
        let host_header: &str = host_header;
        // Handle IPv6 addresses: [::1]:8080
        if host_header.starts_with('[') {
            // IPv6 format
            if let Some(bracket_end) = host_header.find(']') {
                let host = host_header[1..bracket_end].to_string();
                let port = if host_header.len() > bracket_end + 2
                    && host_header.as_bytes()[bracket_end + 1] == b':'
                {
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
) -> std::result::Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
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
) -> std::result::Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let uri = req.uri().clone();
    let host = uri.host().unwrap_or("").to_string();
    let port = uri.port_u16().unwrap_or(443);

    info!("CONNECT request to {}:{}", host, port);

    let address = Address::Domain {
        host: host.clone(),
        port,
    };

    // Get connected stream from pool
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
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(boxed(Full::new(Bytes::from("Failed to connect to proxy")).map_err(|e| match e {})))
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
        .body(empty())
        .unwrap())
}

async fn tunnel(
    upgraded: Upgraded,
    connected_stream: ConnectedStream,
) -> std::result::Result<(), AgentError> {
    // Convert to AsyncRead + AsyncWrite compatible types
    let mut client_io = TokioIo::new(upgraded);
    let mut proxy_io = connected_stream.into_async_io();

    // Use tokio's optimized bidirectional copy
    // This is more efficient than manual select loops as it:
    // 1. Uses zero-copy when possible
    // 2. Has optimized buffering
    // 3. Handles backpressure properly
    match tokio::io::copy_bidirectional(&mut client_io, &mut proxy_io).await {
        Ok((client_to_proxy, proxy_to_client)) => {
            info!(
                "CONNECT tunnel closed: {} bytes client->proxy, {} bytes proxy->client",
                client_to_proxy, proxy_to_client
            );
        }
        Err(e) => {
            // Connection errors are expected when client closes connection
            debug!("CONNECT tunnel ended: {}", e);
        }
    }

    Ok(())
}

async fn handle_regular_request(
    mut req: Request<Incoming>,
    pool: Arc<ConnectionPool>,
) -> std::result::Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let uri = req.uri();

    // Extract host and port from Host header or URI
    let (host, port) = extract_host_port(&req, uri);

    info!("HTTP request to {}:{}", host, port);

    if host.is_empty() {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(boxed(Full::new(Bytes::from("Missing host")).map_err(|e| match e {})))
            .unwrap());
    }

    let address = Address::Domain {
        host: host.clone(),
        port,
    };

    // Get connected stream from pool
    let connected_stream = match pool.get_connected_stream(address).await {
        Ok(stream) => stream,
        Err(e) => {
            error!("Failed to get stream from pool: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(boxed(Full::new(Bytes::from("Failed to connect to proxy")).map_err(|e| match e {})))
                .unwrap());
        }
    };

    // Convert into async IO
    let proxy_io = connected_stream.into_async_io();

    // Fix up the URI to be a relative path (origin-form) for the target server
    let path = req.uri().path_and_query().map(|pq: &hyper::http::uri::PathAndQuery| pq.as_str()).unwrap_or("/");

    if let Ok(new_uri) = Uri::from_str(path) {
        *req.uri_mut() = new_uri;
    }

    // Handshake with the target (via proxy tunnel)
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(proxy_io)).await?;

    tokio::spawn(async move {
        if let Err(err) = conn.await {
            error!("Connection failed: {:?}", err);
        }
    });

    // Send the request
    let response = sender.send_request(req).await?;

    // Convert the response body to our BoxBody type
    let (parts, body) = response.into_parts();
    let body = boxed(body);

    Ok(Response::from_parts(parts, body))
}

// Helper for unknown body
type AgentBody = BoxBody<Bytes, hyper::Error>;

fn boxed<B>(body: B) -> AgentBody
where
    B: hyper::body::Body<Data = Bytes, Error = hyper::Error> + Send + Sync + 'static,
{
    BoxBody::new(body)
}

fn empty() -> AgentBody {
    boxed(Full::new(Bytes::new()).map_err(|e| match e {}))
}

