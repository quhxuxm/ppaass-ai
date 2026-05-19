use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_util::rt::TokioIo;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::debug;

/// 通过 agent 发送请求的模拟 HTTP 客户端
pub struct MockHttpClient {
    agent_addr: String,
}

impl MockHttpClient {
    pub fn new(agent_addr: String) -> Self {
        Self { agent_addr }
    }

    /// 通过代理发送 HTTP GET 请求
    pub async fn get(&self, url: &str) -> Result<(Duration, String)> {
        let start = Instant::now();

        // 连接到 agent
        let stream = TcpStream::connect(&self.agent_addr)
            .await
            .context("Failed to connect to agent")?;

        let io = TokioIo::new(stream);

        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .context("HTTP handshake failed")?;

        // 启动连接处理任务
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("连接错误：{}", e);
            }
        });

        // 构建并发送请求
        let req = Request::builder()
            .uri(url)
            .body(Empty::<Bytes>::new())
            .context("Failed to build request")?;

        let res = sender
            .send_request(req)
            .await
            .context("Failed to send request")?;

        let status = res.status();
        let body_bytes = res.collect().await?.to_bytes();
        let body = String::from_utf8_lossy(&body_bytes).to_string();

        let duration = start.elapsed();

        debug!(
            "HTTP GET {} - 状态：{} - 耗时：{:?}",
            url, status, duration
        );

        Ok((duration, body))
    }

    /// 通过代理发送 HTTP POST 请求
    pub async fn post(&self, url: &str, body: Vec<u8>) -> Result<(Duration, String)> {
        let start = Instant::now();

        // POST 请求创建新连接（因 body 类型不匹配，无法复用）
        let stream = TcpStream::connect(&self.agent_addr)
            .await
            .context("Failed to connect to agent")?;

        let io = TokioIo::new(stream);

        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .context("HTTP handshake failed")?;

        // 启动连接处理任务
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("连接错误：{}", e);
            }
        });

        // 构建并发送请求
        let req = Request::builder()
            .method("POST")
            .uri(url)
            .body(http_body_util::Full::new(Bytes::from(body)))
            .context("Failed to build request")?;

        let res = sender
            .send_request(req)
            .await
            .context("Failed to send request")?;

        let status = res.status();
        let body_bytes = res.collect().await?.to_bytes();
        let body = String::from_utf8_lossy(&body_bytes).to_string();

        let duration = start.elapsed();

        debug!(
            "HTTP POST {} - 状态：{} - 耗时：{:?}",
            url, status, duration
        );

        Ok((duration, body))
    }
}

/// 通过 agent 发送数据的模拟 SOCKS5 客户端
pub struct MockSocks5Client {
    agent_addr: String,
}

impl MockSocks5Client {
    pub fn new(agent_addr: String) -> Self {
        Self { agent_addr }
    }

    /// 通过 SOCKS5 代理连接目标并收发数据
    pub async fn send_receive(
        &self,
        target_host: &str,
        target_port: u16,
        data: &[u8],
    ) -> Result<(Duration, Vec<u8>)> {
        let start = Instant::now();

        // 使用 async-socks5 建立 TCP 连接
        let proxy_addr = &self.agent_addr;

        // 1. 连接到代理
        let mut stream = TcpStream::connect(proxy_addr)
            .await
            .context("Failed to connect to proxy")?;

        // 2. 执行 SOCKS5 握手（CONNECT）
        let _ = async_socks5::connect(&mut stream, (target_host.to_string(), target_port), None)
            .await
            .context("Failed to connect via SOCKS5")?;

        // 连接成功后发送数据
        stream.write_all(data).await?;
        stream.flush().await?;
        stream.shutdown().await?;

        // 带超时接收响应
        let mut response_data = Vec::new();
        match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            stream.read_to_end(&mut response_data),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => anyhow::bail!("Read timeout"),
        };

        let duration = start.elapsed();

        debug!(
            "SOCKS5 {}:{} - 已发送 {} 字节，已接收 {} 字节 - 耗时：{:?}",
            target_host,
            target_port,
            data.len(),
            response_data.len(),
            duration
        );

        Ok((duration, response_data))
    }

    /// 通过 SOCKS5 代理连接目标，并经 UDP 关联收发数据
    pub async fn udp_send_receive(
        &self,
        target_host: &str,
        target_port: u16,
        data: &[u8],
    ) -> Result<(Duration, Vec<u8>)> {
        let start = Instant::now();

        // 使用 async-socks5 crate 执行 UDP 关联

        // 1. 与 SOCKS5 服务器（代理）建立 TCP 连接
        let stream = TcpStream::connect(&self.agent_addr)
            .await
            .context("Failed to connect to agent")?;

        // 2. 绑定本地 UDP 套接字
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to bind local UDP socket")?;

        // 3. 与代理建立关联
        // 调用 associate(stream, socket, auth, target)
        let datagram = async_socks5::SocksDatagram::associate(
            stream,
            socket,
            None,                         // 无认证
            None::<std::net::SocketAddr>, // 目标地址可选
        )
        .await
        .context("Failed to associate via SOCKS5")?;

        let target_addr = format!("{}:{}", target_host, target_port);
        let target_socket_addr: std::net::SocketAddr = target_addr
            .parse()
            .context("Failed to parse target address")?;

        // 4. 发送数据
        datagram
            .send_to(data, target_socket_addr)
            .await
            .context("Failed to send UDP data via proxy")?;

        // 5. 接收响应
        let mut buf = vec![0u8; 4096];
        let (n, _src) = match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            datagram.recv_from(&mut buf),
        )
        .await
        {
            Ok(Ok(res)) => res,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => anyhow::bail!("Read timeout"),
        };

        buf.truncate(n);
        let duration = start.elapsed();

        debug!(
            "SOCKS5 UDP {}:{} - 已发送 {} 字节，已接收 {} 字节 - 耗时：{:?}",
            target_host,
            target_port,
            data.len(),
            n,
            duration
        );

        Ok((duration, buf))
    }
}

/// 用于测试的简单 TCP 客户端
pub struct MockTcpClient {
    target_addr: String,
}

impl MockTcpClient {
    pub fn new(target_addr: String) -> Self {
        Self { target_addr }
    }

    /// 发送数据并接收响应
    pub async fn send_receive(&self, data: &[u8]) -> Result<(Duration, Vec<u8>)> {
        let start = Instant::now();

        let mut stream = TcpStream::connect(&self.target_addr)
            .await
            .context("Failed to connect to target")?;

        stream.write_all(data).await?;
        stream.flush().await?;

        let mut response = vec![0u8; 8192];
        let n = stream.read(&mut response).await?;
        response.truncate(n);

        let duration = start.elapsed();

        Ok((duration, response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_http_client() {
        let client = MockHttpClient::new("127.0.0.1:7070".to_string());
        assert_eq!(client.agent_addr, "127.0.0.1:7070");
    }

    #[test]
    fn test_mock_socks5_client() {
        let client = MockSocks5Client::new("127.0.0.1:7070".to_string());
        assert_eq!(client.agent_addr, "127.0.0.1:7070");
    }

    #[test]
    fn test_mock_tcp_client() {
        let client = MockTcpClient::new("127.0.0.1:9091".to_string());
        assert_eq!(client.target_addr, "127.0.0.1:9091");
    }
}
