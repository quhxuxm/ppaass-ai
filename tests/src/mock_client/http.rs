use super::*;

pub struct MockHttpClient {
    pub(super) agent_addr: String,
}

impl MockHttpClient {
    pub fn new(agent_addr: String) -> Self {
        Self { agent_addr }
    }

    /// 通过代理发送 HTTP GET 请求
    pub async fn get(&self, url: &str) -> Result<(Duration, String)> {
        let (duration, status, _headers, body_bytes) =
            self.get_bytes_with_headers(url, &[]).await?;
        let body = String::from_utf8_lossy(&body_bytes).to_string();

        debug!("HTTP GET {} - 状态：{} - 耗时：{:?}", url, status, duration);

        Ok((duration, body))
    }

    /// 通过代理发送 HTTP GET 请求，并返回原始响应字节与响应头
    pub async fn get_bytes_with_headers(
        &self,
        url: &str,
        headers: &[(&str, String)],
    ) -> Result<(Duration, StatusCode, HeaderMap, Bytes)> {
        let start = Instant::now();

        // 连接到 agent。高并发本地压测会瞬间打满 macOS 默认 128 listen backlog；
        // 对 transient connect 拒绝做短重试，数据通路错误仍在后续握手/读写阶段暴露。
        let stream =
            connect_to_agent_with_retry(&self.agent_addr, "Failed to connect to agent").await?;

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
        let mut builder = Request::builder().uri(url);
        for (name, value) in headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .with_context(|| format!("Invalid request header name: {name}"))?;
            let value = HeaderValue::from_str(value)
                .with_context(|| format!("Invalid request header value for {name}"))?;
            builder = builder.header(name, value);
        }
        let req = builder
            .body(Empty::<Bytes>::new())
            .context("Failed to build request")?;

        let res = sender
            .send_request(req)
            .await
            .context("Failed to send request")?;

        let status = res.status();
        let headers = res.headers().clone();
        let body_bytes = res.collect().await?.to_bytes();

        let duration = start.elapsed();

        debug!(
            "HTTP GET {} - 状态：{} - {} 字节 - 耗时：{:?}",
            url,
            status,
            body_bytes.len(),
            duration
        );

        Ok((duration, status, headers, body_bytes))
    }

    /// 先通过 HTTP CONNECT 建立隧道，再在隧道内发送普通 HTTP GET。
    ///
    /// 浏览器访问 HTTPS 视频分片时，agent 看到的是 CONNECT 后的双向字节流；
    /// 这里不用 TLS，只验证 CONNECT tunnel 的半关闭、flush 和 Range 响应完整性。
    pub async fn connect_tunnel_get_bytes_with_headers(
        &self,
        authority: &str,
        path: &str,
        headers: &[(&str, String)],
    ) -> Result<(Duration, StatusCode, HeaderMap, Bytes)> {
        let start = Instant::now();

        let mut stream =
            connect_to_agent_with_retry(&self.agent_addr, "Failed to connect to agent").await?;

        let connect_request = format!(
            "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: keep-alive\r\n\r\n"
        );
        stream
            .write_all(connect_request.as_bytes())
            .await
            .context("Failed to write CONNECT request")?;
        stream
            .flush()
            .await
            .context("Failed to flush CONNECT request")?;

        read_connect_response(&mut stream).await?;

        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .context("HTTP tunnel handshake failed")?;

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("CONNECT tunnel HTTP connection error: {}", e);
            }
        });

        let mut builder = Request::builder()
            .uri(path)
            .header(hyper::header::HOST, authority);
        for (name, value) in headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .with_context(|| format!("Invalid request header name: {name}"))?;
            let value = HeaderValue::from_str(value)
                .with_context(|| format!("Invalid request header value for {name}"))?;
            builder = builder.header(name, value);
        }

        let req = builder
            .body(Empty::<Bytes>::new())
            .context("Failed to build tunneled request")?;

        let res = sender
            .send_request(req)
            .await
            .context("Failed to send tunneled request")?;

        let status = res.status();
        let headers = res.headers().clone();
        let body_bytes = res.collect().await?.to_bytes();
        let duration = start.elapsed();

        debug!(
            "HTTP CONNECT GET {}{} - 状态：{} - {} 字节 - 耗时：{:?}",
            authority,
            path,
            status,
            body_bytes.len(),
            duration
        );

        Ok((duration, status, headers, body_bytes))
    }

    /// 通过代理发送 HTTP POST 请求
    pub async fn post(&self, url: &str, body: Vec<u8>) -> Result<(Duration, String)> {
        let start = Instant::now();

        // POST 请求创建新连接（因 body 类型不匹配，无法复用）
        let stream =
            connect_to_agent_with_retry(&self.agent_addr, "Failed to connect to agent").await?;

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

pub(super) async fn read_connect_response(stream: &mut TcpStream) -> Result<()> {
    let mut response_head = Vec::with_capacity(128);
    let read = async {
        let mut byte = [0u8; 1];
        while response_head.len() < 8192 {
            let n = stream.read(&mut byte).await?;
            anyhow::ensure!(n != 0, "CONNECT closed before response headers");
            response_head.push(byte[0]);
            if response_head.ends_with(b"\r\n\r\n") {
                return Ok(());
            }
        }
        anyhow::bail!("CONNECT response headers too large")
    };

    tokio::time::timeout(Duration::from_secs(10), read)
        .await
        .context("CONNECT response timeout")??;

    let response = std::str::from_utf8(&response_head).context("CONNECT response is not UTF-8")?;
    let status_line = response.lines().next().unwrap_or_default();
    anyhow::ensure!(
        status_line.contains(" 200 "),
        "CONNECT failed: {status_line}"
    );

    Ok(())
}
