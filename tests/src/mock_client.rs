use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_util::rt::TokioIo;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::debug;

/// Mock HTTP client that sends requests through the agent
pub struct MockHttpClient {
    agent_addr: String,
}

impl MockHttpClient {
    pub fn new(agent_addr: String) -> Self {
        Self { agent_addr }
    }

    /// Send an HTTP GET request through the proxy
    pub async fn get(&self, url: &str) -> Result<(Duration, String)> {
        let start = Instant::now();
        
        // Connect to agent
        let stream = TcpStream::connect(&self.agent_addr)
            .await
            .context("Failed to connect to agent")?;
        
        let io = TokioIo::new(stream);
        
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .context("HTTP handshake failed")?;
        
        // Spawn connection handler
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("Connection error: {}", e);
            }
        });
        
        // Build and send request
        let req = Request::builder()
            .uri(url)
            .body(Empty::<Bytes>::new())
            .context("Failed to build request")?;
        
        let res = sender.send_request(req)
            .await
            .context("Failed to send request")?;
        
        let status = res.status();
        let body_bytes = res.collect().await?.to_bytes();
        let body = String::from_utf8_lossy(&body_bytes).to_string();
        
        let duration = start.elapsed();
        
        debug!("HTTP GET {} - Status: {} - Duration: {:?}", url, status, duration);
        
        Ok((duration, body))
    }

    /// Send an HTTP POST request through the proxy
    pub async fn post(&self, url: &str, body: Vec<u8>) -> Result<(Duration, String)> {
        let start = Instant::now();
        
        // For POST, create a new connection (can't reuse due to body type mismatch)
        let stream = TcpStream::connect(&self.agent_addr)
            .await
            .context("Failed to connect to agent")?;
        
        let io = TokioIo::new(stream);
        
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .context("HTTP handshake failed")?;
        
        // Spawn connection handler
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("Connection error: {}", e);
            }
        });
        
        // Build and send request
        let req = Request::builder()
            .method("POST")
            .uri(url)
            .body(http_body_util::Full::new(Bytes::from(body)))
            .context("Failed to build request")?;
        
        let res = sender.send_request(req)
            .await
            .context("Failed to send request")?;
        
        let status = res.status();
        let body_bytes = res.collect().await?.to_bytes();
        let body = String::from_utf8_lossy(&body_bytes).to_string();
        
        let duration = start.elapsed();
        
        debug!("HTTP POST {} - Status: {} - Duration: {:?}", url, status, duration);
        
        Ok((duration, body))
    }
}

/// Mock SOCKS5 client that sends data through the agent
pub struct MockSocks5Client {
    agent_addr: String,
}

impl MockSocks5Client {
    pub fn new(agent_addr: String) -> Self {
        Self { agent_addr }
    }

    /// Connect to a target through SOCKS5 proxy and send/receive data
    pub async fn send_receive(&self, target_host: &str, target_port: u16, data: &[u8]) -> Result<(Duration, Vec<u8>)> {
        let start = Instant::now();
        
        // Use async-socks5 for TCP connect
        let proxy_addr = &self.agent_addr;

        // 1. Connect to the proxy
        let mut stream = TcpStream::connect(proxy_addr).await
            .context("Failed to connect to proxy")?;

        // 2. Perform SOCKS5 handshake (CONNECT)
        let _ = async_socks5::connect(&mut stream, (target_host.to_string(), target_port), None).await
            .context("Failed to connect via SOCKS5")?;

        // Now connected, send data
        stream.write_all(data).await?;
        stream.flush().await?;
        stream.shutdown().await?;

        // Receive response with timeout
        let mut response_data = Vec::new();
        match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            stream.read_to_end(&mut response_data)
        ).await {
            Ok(Ok(_)) => {},
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => anyhow::bail!("Read timeout"),
        };

        let duration = start.elapsed();
        
        debug!("SOCKS5 {}:{} - Sent {} bytes, Received {} bytes - Duration: {:?}", 
              target_host, target_port, data.len(), response_data.len(), duration);

        Ok((duration, response_data))
    }

    /// Connect to a target through SOCKS5 proxy and send/receive data via UDP Associate
    pub async fn udp_send_receive(&self, target_host: &str, target_port: u16, data: &[u8]) -> Result<(Duration, Vec<u8>)> {
        let start = Instant::now();

        // Use async-socks5 crate for UDP Associate

        // 1. Establish TCP connection to SOCKS5 server (proxy)
        let stream = TcpStream::connect(&self.agent_addr)
            .await
            .context("Failed to connect to agent")?;

        // 2. Bind a local UDP socket
        let socket = UdpSocket::bind("0.0.0.0:0").await
            .context("Failed to bind local UDP socket")?;

        // 3. Associate with the proxy
        // associate(stream, socket, auth, target)
        let datagram = async_socks5::SocksDatagram::associate(
            stream,
            socket,
            None, // No auth
            None::<std::net::SocketAddr>, // Target address optional
        ).await.context("Failed to associate via SOCKS5")?;

        let target_addr = format!("{}:{}", target_host, target_port);
        let target_socket_addr: std::net::SocketAddr = target_addr.parse()
            .context("Failed to parse target address")?;

        // 4. Send data
        datagram.send_to(data, target_socket_addr).await
            .context("Failed to send UDP data via proxy")?;

        // 5. Receive response
        let mut buf = vec![0u8; 4096];
        let (n, _src) = match tokio::time::timeout(
             std::time::Duration::from_secs(10),
             datagram.recv_from(&mut buf)
        ).await {
             Ok(Ok(res)) => res,
             Ok(Err(e)) => return Err(e.into()),
             Err(_) => anyhow::bail!("Read timeout"),
        };

        buf.truncate(n);
        let duration = start.elapsed();

        debug!("SOCKS5 UDP {}:{} - Sent {} bytes, Received {} bytes - Duration: {:?}",
              target_host, target_port, data.len(), n, duration);

        Ok((duration, buf))
    }
}

/// Simple TCP client for testing
pub struct MockTcpClient {
    target_addr: String,
}

impl MockTcpClient {
    pub fn new(target_addr: String) -> Self {
        Self { target_addr }
    }

    /// Send data and receive response
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
