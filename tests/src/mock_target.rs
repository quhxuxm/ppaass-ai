use anyhow::Result;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

/// Mock HTTP target server that responds to various test endpoints
pub struct MockHttpServer {
    port: u16,
}

impl MockHttpServer {
    pub fn new(port: u16) -> Self {
        Self { port }
    }

    pub async fn run(&self) -> Result<()> {
        let addr: SocketAddr = format!("127.0.0.1:{}", self.port).parse()?;
        let listener = TcpListener::bind(addr).await?;
        info!("Mock HTTP server listening on {}", addr);

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        if let Err(e) = http1::Builder::new()
                            .serve_connection(io, service_fn(handle_http_request))
                            .await
                        {
                            error!("Error serving connection: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }
}

/// Mock TCP echo server that echoes back whatever it receives
pub struct MockTcpServer {
    port: u16,
}

impl MockTcpServer {
    pub fn new(port: u16) -> Self {
        Self { port }
    }

    pub async fn run(&self) -> Result<()> {
        let addr: SocketAddr = format!("127.0.0.1:{}", self.port).parse()?;
        let listener = TcpListener::bind(addr).await?;
        info!("Mock TCP echo server listening on {}", addr);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!("TCP echo connection from {}", addr);
                    tokio::spawn(async move {
                        if let Err(e) = handle_tcp_echo(stream).await {
                            error!("TCP echo error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept TCP connection: {}", e);
                }
            }
        }
    }
}

async fn handle_http_request(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let path = req.uri().path();
    info!("HTTP request: {} {}", req.method(), path);

    let response = match path {
        "/health" => Response::builder()
            .status(StatusCode::OK)
            .body(full_body("OK"))?,
        "/echo" => {
            // Echo back the request body
            let body = req.collect().await?.to_bytes();
            Response::builder()
                .status(StatusCode::OK)
                .body(BoxBody::new(Full::new(body).map_err(|e| match e {})))? 
        }
        "/large" => {
            // Return a large response for throughput testing
            let data = vec![b'A'; 1024 * 1024]; // 1MB
            Response::builder()
                .status(StatusCode::OK)
                .body(full_body(data))? 
        }
        "/json" => {
            let json_data = r#"{"status":"success","message":"Mock target response"}"#;
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(full_body(json_data))? 
        }
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(full_body("Not Found"))?,
    };

    Ok(response)
}

fn full_body<T: Into<Bytes>>(body: T) -> BoxBody<Bytes, hyper::Error> {
    BoxBody::new(Full::new(body.into()).map_err(|e| match e {}))
}

async fn handle_tcp_echo(mut stream: TcpStream) -> Result<()> {
    let mut buffer = vec![0u8; 8192];

    loop {
        let n = stream.read(&mut buffer).await?;
        if n == 0 {
            // Connection closed
            break;
        }

        // Echo back
        stream.write_all(&buffer[..n]).await?;
        stream.flush().await?;
    }

    Ok(())
}

/// Run both mock servers
pub async fn run_mock_servers(http_port: u16, tcp_port: u16) -> Result<()> {
    let http_server = MockHttpServer::new(http_port);
    let tcp_server = MockTcpServer::new(tcp_port);

    tokio::select! {
        res = http_server.run() => {
            error!("HTTP server stopped: {:?}", res);
            res
        }
        res = tcp_server.run() => {
            error!("TCP server stopped: {:?}", res);
            res
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_http_server() {
        // This is a basic test to ensure the server can be instantiated
        let server = MockHttpServer::new(19090);
        assert_eq!(server.port, 19090);
    }

    #[tokio::test]
    async fn test_mock_tcp_server() {
        let server = MockTcpServer::new(19091);
        assert_eq!(server.port, 19091);
    }
}
