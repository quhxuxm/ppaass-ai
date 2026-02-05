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
        
        // Use tokio-socks for TCP connect
        let proxy_addr = self.agent_addr.clone();
        let target_addr = format!("{}:{}", target_host, target_port);

        let mut stream = tokio_socks::tcp::Socks5Stream::connect(proxy_addr.as_str(), target_addr.as_str())
            .await
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

        // 1. Establish TCP connection to SOCKS5 server
        let mut stream = TcpStream::connect(&self.agent_addr)
            .await
            .context("Failed to connect to agent")?;

        // 2. Client greeting: VER=5, NMETHODS=1, METHODS=[0x00] (No Auth)
        stream.write_all(&[0x05, 0x01, 0x00]).await?;

        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        if buf[0] != 0x05 || buf[1] != 0x00 {
            anyhow::bail!("SOCKS5 handshake failed or auth required");
        }

        // 3. Send UDP ASSOCIATE request
        // CMD=0x03 (UDP ASSOCIATE)
        // ADDR/PORT is the client's address/port where it wants to send UDP from.
        // We use 0.0.0.0:0 to let server accept from anywhere (or we don't care to specify)
        let request = vec![
            0x05, // VER
            0x03, // CMD = UDP ASSOCIATE
            0x00, // RSV
            0x01, // ATYP = IPv4
            0x00, 0x00, 0x00, 0x00, // 0.0.0.0
            0x00, 0x00 // Port 0
        ];

        stream.write_all(&request).await?;

        // 4. Read UDP ASSOCIATE response
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await?;
        // VER | REP | RSV | ATYP
        if response[0] != 0x05 || response[1] != 0x00 {
             anyhow::bail!("SOCKS5 UDP Associate failed: status={}", response[1]);
        }

        // Parse bind address from response (where we should send UDP packets)
        let bind_addr = match response[3] {
            0x01 => { // IPv4
                let mut addr = [0u8; 6];
                stream.read_exact(&mut addr).await?;
                format!("{}.{}.{}.{}:{}", addr[0], addr[1], addr[2], addr[3], u16::from_be_bytes([addr[4], addr[5]]))
            }
            0x03 => { // Domain
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut addr = vec![0u8; len[0] as usize + 2];
                stream.read_exact(&mut addr).await?;
                let host = String::from_utf8_lossy(&addr[..len[0] as usize]);
                let port = u16::from_be_bytes([addr[addr.len()-2], addr[addr.len()-1]]);
                format!("{}:{}", host, port)
            }
            0x04 => { // IPv6
                let mut addr = [0u8; 18];
                stream.read_exact(&mut addr).await?;
                // Just use localhost for now as fallback or construct ipv6 string
                // But mock environment usually ipv4.
                // Assuming we can send to loopback if needed or original address
                // Since test runs locally, localhost usually works if bind_addr is 0.0.0.0 or ::
                "127.0.0.1:0".to_string()
            }
            _ => anyhow::bail!("Unknown address type"),
        };

        // If bind_addr is 0.0.0.0, we replace with the proxy IP we connected to
        // For local tests (127.0.0.1) it works.
        let bind_addr = if bind_addr.starts_with("0.0.0.0") {
             let proxy_host = self.agent_addr.split(':').next().unwrap_or("127.0.0.1");
             let bind_port = bind_addr.split(':').last().unwrap_or("0");
             format!("{}:{}", proxy_host, bind_port)
        } else {
            bind_addr
        };

        debug!("SOCKS5 UDP Associate success, bind addr: {}", bind_addr);

        // 5. Send encapsulated UDP packet to bind_addr
        // The packet must be encapsulated with SOCKS5 UDP header
        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        // Construct SOCKS5 UDP header + Data
        // RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT DATA
        let mut packet = vec![0x00, 0x00, 0x00];

        if let Ok(ip) = target_host.parse::<std::net::Ipv4Addr>() {
             packet.push(0x01); // ATYP IPv4
             packet.extend_from_slice(&ip.octets());
        } else {
             // Domain
             packet.push(0x03);
             packet.push(target_host.len() as u8);
             packet.extend_from_slice(target_host.as_bytes());
        }

        packet.extend_from_slice(&target_port.to_be_bytes());
        packet.extend_from_slice(data);

        socket.send_to(&packet, &bind_addr).await?;

        // 6. Receive response
        let mut recv_buf = [0u8; 4096];
        let (n, _src) = match tokio::time::timeout(
             std::time::Duration::from_secs(10),
             socket.recv_from(&mut recv_buf)
        ).await {
             Ok(Ok(res)) => res,
             Ok(Err(e)) => return Err(e.into()),
             Err(_) => anyhow::bail!("Read timeout"),
        };

        // Parse response header
        if n < 10 {
             anyhow::bail!("Response too short");
        }

        // RSV(2) FRAG(1) ATYP(1)
        // Note: FRAG usually 0 for no fragmentation
        if recv_buf[0] != 0 || recv_buf[1] != 0 || recv_buf[2] != 0 {
             // Warn but proceed? Or fail. Standard says 00 00 00.
             // Sometimes implementation might vary, but fast-socks5 implies strict.
        }

        let header_len = match recv_buf[3] {
            0x01 => 10, // 3 + 1 + 4 + 2
            0x03 => 7 + recv_buf[4] as usize, // 3 + 1 + 1 + len + 2
            0x04 => 22, // 3 + 1 + 16 + 2
            _ => anyhow::bail!("Unknown address type in response"),
        };

        if n < header_len {
            anyhow::bail!("Response header incomplete");
        }

        let response_data = recv_buf[header_len..n].to_vec();
        let duration = start.elapsed();

        // Keep TCP stream alive until end
        drop(stream);

        debug!("SOCKS5 UDP {}:{} - Sent {} bytes, Received {} bytes - Duration: {:?}",
              target_host, target_port, data.len(), response_data.len(), duration);

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
