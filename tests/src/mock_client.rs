use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_util::rt::TokioIo;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
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
        
        let mut stream = TcpStream::connect(&self.agent_addr)
            .await
            .context("Failed to connect to agent")?;
        
        // SOCKS5 handshake
        stream.write_all(&[0x05, 0x01, 0x00]).await?; // Version 5, 1 method, no auth
        
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        if buf[0] != 0x05 || buf[1] != 0x00 {
            anyhow::bail!("SOCKS5 handshake failed");
        }
        
        // Send connection request
        let mut request = vec![0x05, 0x01, 0x00, 0x03]; // Version, Connect, Reserved, Domain name
        request.push(target_host.len() as u8);
        request.extend_from_slice(target_host.as_bytes());
        request.extend_from_slice(&target_port.to_be_bytes());
        
        stream.write_all(&request).await?;
        
        // Read connection response
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await?;
        if response[1] != 0x00 {
            anyhow::bail!("SOCKS5 connection failed: status={}", response[1]);
        }
        
        
        // Read remaining address (skip it)
        match response[3] {
            0x01 => { // IPv4
                let mut addr = [0u8; 6]; // 4 bytes IP + 2 bytes port
                stream.read_exact(&mut addr).await?;
            }
            0x03 => { // Domain
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut addr = vec![0u8; len[0] as usize + 2];
                stream.read_exact(&mut addr).await?;
            }
            0x04 => { // IPv6
                let mut addr = [0u8; 18]; // 16 bytes IP + 2 bytes port
                stream.read_exact(&mut addr).await?;
            }
            _ => anyhow::bail!("Unknown address type"),
        }
        
        // Now connected, send data
        stream.write_all(data).await?;
        stream.flush().await?;
        
        // Receive response with timeout
        let mut response_data = vec![0u8; 4096]; // Reduced buffer size
        let n = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read(&mut response_data)
        ).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => anyhow::bail!("Read timeout"),
        };
        response_data.truncate(n);
        
        let duration = start.elapsed();
        
        debug!("SOCKS5 {}:{} - Sent {} bytes, Received {} bytes - Duration: {:?}", 
              target_host, target_port, data.len(), n, duration);
        
        Ok((duration, response_data))
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
