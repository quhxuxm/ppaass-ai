use super::*;

/// 通过 agent 发送数据的模拟 SOCKS5 客户端
pub struct MockSocks5Client {
    pub(super) agent_addr: String,
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
        let mut stream =
            connect_to_agent_with_retry(proxy_addr, "Failed to connect to proxy").await?;

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
        let stream =
            connect_to_agent_with_retry(&self.agent_addr, "Failed to connect to agent").await?;

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
