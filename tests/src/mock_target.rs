use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{error, info, trace};

/// 响应多个测试端点的模拟 HTTP 目标服务器
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
        info!("模拟 HTTP 服务器正在监听 {}", addr);

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        if let Err(e) = http1::Builder::new()
                            .serve_connection(io, service_fn(handle_http_request))
                            .await
                        {
                            error!("服务连接时出错：{}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("接受连接失败：{}", e);
                }
            }
        }
    }
}

/// 模拟 TCP 回显服务器，会回显收到的所有数据
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
        info!("模拟 TCP 回显服务器正在监听 {}", addr);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!("来自 {} 的 TCP 回显连接", addr);
                    tokio::spawn(async move {
                        if let Err(e) = handle_tcp_echo(stream).await {
                            error!("TCP 回显错误：{}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("接受 TCP 连接失败：{}", e);
                }
            }
        }
    }
}

/// 模拟 UDP 回显服务器
pub struct MockUdpServer {
    port: u16,
}

impl MockUdpServer {
    pub fn new(port: u16) -> Self {
        Self { port }
    }

    pub async fn run(&self) -> Result<()> {
        let addr: SocketAddr = format!("127.0.0.1:{}", self.port).parse()?;
        let socket = UdpSocket::bind(addr).await?;
        let socket = Arc::new(socket);
        info!("模拟 UDP 回显服务器正在监听 {}", addr);

        let mut buf = [0u8; 8192];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, client_addr)) => {
                    let socket_clone = socket.clone();
                    let data = buf[..n].to_vec();
                    trace!(
                        "收到来自 {} 的 UDP 数据：\n{}",
                        client_addr,
                        pretty_hex::pretty_hex(&data)
                    );
                    tokio::spawn(async move {
                        if let Err(e) = socket_clone.send_to(&data, client_addr).await {
                            error!("向 {} 发送 UDP 回显失败：{}", client_addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("接收 UDP 失败：{}", e);
                }
            }
        }
    }
}

async fn handle_http_request(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let path = req.uri().path();
    info!("HTTP 请求：{} {}", req.method(), path);

    let response = match path {
        "/health" => Response::builder()
            .status(StatusCode::OK)
            .body(full_body("OK"))?,
        "/echo" => {
            // 回显请求体
            let body = req.collect().await?.to_bytes();
            Response::builder()
                .status(StatusCode::OK)
                .body(BoxBody::new(Full::new(body).map_err(|e| match e {})))?
        }
        "/large" => {
            // 返回用于吞吐测试的大响应
            let data = vec![b'A'; 1024 * 1024]; // 1 MB
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
            // 连接已关闭
            break;
        }

        // 回显数据
        stream.write_all(&buffer[..n]).await?;
        stream.flush().await?;
    }

    Ok(())
}

/// 运行模拟服务器
pub async fn run_mock_servers(http_port: u16, tcp_port: u16, udp_port: u16) -> Result<()> {
    let http_server = MockHttpServer::new(http_port);
    let tcp_server = MockTcpServer::new(tcp_port);
    let udp_server = MockUdpServer::new(udp_port);

    tokio::select! {
        res = http_server.run() => {
            error!("HTTP 服务器已停止：{:?}", res);
            res
        }
        res = tcp_server.run() => {
            error!("TCP 服务器已停止：{:?}", res);
            res
        }
        res = udp_server.run() => {
            error!("UDP 服务器已停止：{:?}", res);
            res
        }
        _ = tokio::signal::ctrl_c() => {
            info!("收到关闭信号");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_http_server() {
        // 这是一个基础测试，用于确保服务器可以实例化
        let server = MockHttpServer::new(19090);
        assert_eq!(server.port, 19090);
    }

    #[tokio::test]
    async fn test_mock_tcp_server() {
        let server = MockTcpServer::new(19091);
        assert_eq!(server.port, 19091);
    }

    #[tokio::test]
    async fn test_mock_udp_server() {
        let server = MockUdpServer::new(19092);
        assert_eq!(server.port, 19092);
    }
}
