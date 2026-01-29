use crate::{config::AgentConfig, connection_pool::ConnectionPool};
use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, Response, StatusCode, body::Incoming, server::conn::http1, service::service_fn,
};
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tokio::net::TcpStream;
use tracing::debug;

/// Handle an already-accepted HTTP connection
pub async fn handle_connection(
    stream: TcpStream,
    _config: Arc<AgentConfig>,
    pool: Arc<ConnectionPool>,
) -> Result<()> {
    let io = TokioIo::new(stream);
    http1::Builder::new()
        .serve_connection(
            io,
            service_fn(move |req| {
                let pool = pool.clone();
                handle_request(req, pool)
            }),
        )
        .await?;
    Ok(())
}

async fn handle_request(
    req: Request<Incoming>,
    pool: Arc<ConnectionPool>,
) -> Result<Response<Full<Bytes>>> {
    debug!("HTTP request: {} {}", req.method(), req.uri());

    if req.method() == Method::CONNECT {
        // HTTPS CONNECT tunneling
        handle_connect(req, pool).await
    } else {
        // Regular HTTP request
        handle_http(req, pool).await
    }
}

async fn handle_connect(
    req: Request<Incoming>,
    pool: Arc<ConnectionPool>,
) -> Result<Response<Full<Bytes>>> {
    let uri = req.uri();
    let host = uri.host().unwrap_or("").to_string();
    let port = uri.port_u16().unwrap_or(443);

    debug!("CONNECT tunnel to {}:{}", host, port);

    // Get connection from pool
    let _conn = pool.get_connection().await?;

    // For CONNECT, we need to establish the tunnel
    // This is simplified - in production, you'd upgrade the connection
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::from("Connection established")))
        .unwrap();

    Ok(response)
}

async fn handle_http(
    req: Request<Incoming>,
    pool: Arc<ConnectionPool>,
) -> Result<Response<Full<Bytes>>> {
    let uri = req.uri().clone();
    let host = uri.host().unwrap_or("").to_string();
    let port = uri.port_u16().unwrap_or(80);

    debug!("HTTP request to {}:{}{}", host, port, uri.path());

    // Collect request body
    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await?.to_bytes();

    // Build request to send to proxy
    let request_data = format!(
        "{} {} HTTP/1.1\r\nHost: {}:{}\r\n",
        parts.method,
        uri.path(),
        host,
        port
    );

    let mut full_request = request_data.into_bytes();
    for (name, value) in parts.headers.iter() {
        full_request.extend_from_slice(name.as_str().as_bytes());
        full_request.extend_from_slice(b": ");
        full_request.extend_from_slice(value.as_bytes());
        full_request.extend_from_slice(b"\r\n");
    }
    full_request.extend_from_slice(b"\r\n");
    full_request.extend_from_slice(&body_bytes);

    // Get connection from pool
    let conn = pool.get_connection().await?;

    // Send through proxy
    let response_data = conn
        .send_data(&full_request, Some(host), Some(port))
        .await?;

    // Parse response (simplified)
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::from(response_data)))
        .unwrap();

    Ok(response)
}
