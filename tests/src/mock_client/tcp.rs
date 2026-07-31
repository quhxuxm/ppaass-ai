use super::*;

pub async fn connect_to_agent_with_retry(
    addr: &str,
    context_msg: &'static str,
) -> Result<TcpStream> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut delay = Duration::from_millis(5);

    loop {
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(err) => {
                if Instant::now() + delay >= deadline {
                    return Err(err).context(context_msg);
                }
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_millis(50));
            }
        }
    }
}

/// 用于测试的简单 TCP 客户端
pub struct MockTcpClient {
    pub(super) target_addr: String,
}

impl MockTcpClient {
    pub fn new(target_addr: String) -> Self {
        Self { target_addr }
    }

    pub fn target_addr(&self) -> &str {
        &self.target_addr
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
