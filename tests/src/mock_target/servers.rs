use super::*;

pub struct MockHttpServer {
    pub(super) port: u16,
}

impl MockHttpServer {
    pub fn new(port: u16) -> Self {
        Self { port }
    }

    pub async fn run(&self) -> Result<()> {
        let addr: SocketAddr = format!("127.0.0.1:{}", self.port).parse()?;
        let listener = bind_tcp_listener_with_backlog(addr, DEFAULT_TCP_LISTEN_BACKLOG)?;
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

/// 模拟 HTTP/2 cleartext 目标服务器，用于测试 CONNECT/SOCKS5 隧道内多路复用。
pub struct MockH2Server {
    pub(super) port: u16,
}

impl MockH2Server {
    pub fn new(port: u16) -> Self {
        Self { port }
    }

    pub async fn run(&self) -> Result<()> {
        let addr: SocketAddr = format!("127.0.0.1:{}", self.port).parse()?;
        let listener = bind_tcp_listener_with_backlog(addr, DEFAULT_TCP_LISTEN_BACKLOG)?;
        info!("模拟 HTTP/2 服务器正在监听 {}", addr);

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        if let Err(e) = http2::Builder::new(TokioExecutor::new())
                            .serve_connection(io, service_fn(handle_http_request))
                            .await
                        {
                            error!("服务 HTTP/2 连接时出错：{}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("接受 HTTP/2 连接失败：{}", e);
                }
            }
        }
    }
}

/// 模拟 TCP 回显服务器，会回显收到的所有数据
pub struct MockTcpServer {
    pub(super) port: u16,
}

impl MockTcpServer {
    pub fn new(port: u16) -> Self {
        Self { port }
    }

    pub async fn run(&self) -> Result<()> {
        let addr: SocketAddr = format!("127.0.0.1:{}", self.port).parse()?;
        let listener = bind_tcp_listener_with_backlog(addr, DEFAULT_TCP_LISTEN_BACKLOG)?;
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
    pub(super) port: u16,
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
/// 运行模拟服务器
pub async fn run_mock_servers(
    http_port: u16,
    h2_port: u16,
    tcp_port: u16,
    udp_port: u16,
) -> Result<()> {
    let http_server = MockHttpServer::new(http_port);
    let h2_server = MockH2Server::new(h2_port);
    let tcp_server = MockTcpServer::new(tcp_port);
    let udp_server = MockUdpServer::new(udp_port);

    tokio::select! {
        res = http_server.run() => {
            error!("HTTP 服务器已停止：{:?}", res);
            res
        }
        res = h2_server.run() => {
            error!("HTTP/2 服务器已停止：{:?}", res);
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
