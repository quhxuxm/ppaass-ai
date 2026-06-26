use crate::mock_client::{MockHttpClient, MockSocks5Client};
use anyhow::{Context, Result};
use bytes::Bytes;
use hyper::HeaderMap;
use hyper::StatusCode;
use hyper::header::{HeaderName, HeaderValue};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{error, info};

const BLOCKED_TARGET_HOST: &str = "203.0.113.1";
const BLOCKED_TARGET_PORT: u16 = 81;
const BLOCKED_TARGET_TIMEOUT: Duration = Duration::from_millis(350);
const FLUCTUATING_TARGET_TIMEOUT: Duration = Duration::from_secs(20);

pub struct IntegrationTestResults {
    pub total_tests: usize,
    pub passed: usize,
    pub failed: usize,
    pub test_details: Vec<TestResult>,
}

pub struct TestResult {
    pub name: String,
    pub passed: bool,
    pub error: Option<String>,
    pub duration_ms: u128,
}

/// 运行所有集成测试
pub async fn run_all_tests(agent_addr: &str) -> Result<IntegrationTestResults> {
    info!("=== 开始集成测试 ===");

    let mut results = IntegrationTestResults {
        total_tests: 0,
        passed: 0,
        failed: 0,
        test_details: Vec::new(),
    };

    // 测试 HTTP 健康检查端点
    results.add_test(test_http_health(agent_addr).await);

    // 测试 HTTP 回显端点
    results.add_test(test_http_echo(agent_addr).await);

    // 测试 HTTP 大响应
    results.add_test(test_http_large_response(agent_addr).await);

    // 测试 HTTP Range 分片下载
    results.add_test(test_http_large_range_response(agent_addr).await);

    // 测试 HTTP CONNECT 隧道内的 Range 分片下载
    results.add_test(test_http_connect_large_range_response(agent_addr).await);

    // 测试阻塞/失败目标连接不会截断同一 Yamux session 上的分片下载
    results
        .add_test(test_blocked_target_connects_do_not_truncate_range_downloads(agent_addr).await);

    // 测试目标网络波动时仍能读完整 Content-Length 指定的分片 body
    results.add_test(test_fluctuating_target_does_not_truncate_range_downloads(agent_addr).await);

    // 测试 HTTP JSON 响应
    results.add_test(test_http_json(agent_addr).await);

    // 测试 SOCKS5 连接
    results.add_test(test_socks5_echo(agent_addr).await);

    // 测试 SOCKS5 大数据传输
    results.add_test(test_socks5_large_data(agent_addr).await);

    // 测试 SOCKS5 UDP 关联
    results.add_test(test_socks5_udp(agent_addr).await);

    info!("=== 集成测试完成 ===");
    info!(
        "总数：{}，通过：{}，失败：{}",
        results.total_tests, results.passed, results.failed
    );

    Ok(results)
}

impl IntegrationTestResults {
    fn add_test(&mut self, result: TestResult) {
        self.total_tests += 1;
        if result.passed {
            self.passed += 1;
            info!("✓ {} - 通过（{} ms）", result.name, result.duration_ms);
        } else {
            self.failed += 1;
            error!(
                "✗ {} - 失败：{}",
                result.name,
                result.error.as_ref().unwrap_or(&"未知错误".to_string())
            );
        }
        self.test_details.push(result);
    }
}

async fn test_http_health(agent_addr: &str) -> TestResult {
    let start = std::time::Instant::now();
    let name = "HTTP 健康检查".to_string();

    let client = MockHttpClient::new(agent_addr.to_string());

    match client.get("http://127.0.0.1:9090/health").await {
        Ok((_, body)) => {
            let passed = body.contains("OK");
            TestResult {
                name,
                passed,
                error: if !passed {
                    Some("响应未包含 'OK'".to_string())
                } else {
                    None
                },
                duration_ms: start.elapsed().as_millis(),
            }
        }
        Err(e) => TestResult {
            name,
            passed: false,
            error: Some(e.to_string()),
            duration_ms: start.elapsed().as_millis(),
        },
    }
}

async fn test_http_echo(agent_addr: &str) -> TestResult {
    let start = std::time::Instant::now();
    let name = "HTTP 回显".to_string();

    let client = MockHttpClient::new(agent_addr.to_string());
    let test_data = b"Hello, World!".to_vec();

    match client
        .post("http://127.0.0.1:9090/echo", test_data.clone())
        .await
    {
        Ok((_, body)) => {
            let passed = body.as_bytes() == test_data.as_slice();
            TestResult {
                name,
                passed,
                error: if !passed {
                    Some("回显响应与请求不匹配".to_string())
                } else {
                    None
                },
                duration_ms: start.elapsed().as_millis(),
            }
        }
        Err(e) => TestResult {
            name,
            passed: false,
            error: Some(e.to_string()),
            duration_ms: start.elapsed().as_millis(),
        },
    }
}

async fn test_http_large_response(agent_addr: &str) -> TestResult {
    let start = std::time::Instant::now();
    let name = "HTTP 大响应".to_string();

    let client = MockHttpClient::new(agent_addr.to_string());

    match client.get("http://127.0.0.1:9090/large").await {
        Ok((_, body)) => {
            let passed = body.len() >= 1024 * 1024; // 至少应为 1 MB
            TestResult {
                name,
                passed,
                error: if !passed {
                    Some(format!("响应过小：{} 字节", body.len()))
                } else {
                    None
                },
                duration_ms: start.elapsed().as_millis(),
            }
        }
        Err(e) => TestResult {
            name,
            passed: false,
            error: Some(e.to_string()),
            duration_ms: start.elapsed().as_millis(),
        },
    }
}

async fn test_http_large_range_response(agent_addr: &str) -> TestResult {
    let start = std::time::Instant::now();
    let name = "HTTP Range 分片下载".to_string();
    let client = MockHttpClient::new(agent_addr.to_string());

    let file_size = 2 * 1024 * 1024;
    let range_start = 128 * 1024 + 7;
    let range_end = range_start + 4095;
    let headers = [("Range", format!("bytes={range_start}-{range_end}"))];

    match client
        .get_bytes_with_headers(
            &format!("http://127.0.0.1:9090/large?size={file_size}"),
            &headers,
        )
        .await
    {
        Ok((_, status, headers, body)) => {
            let check = verify_large_range_response(
                "HTTP Range",
                file_size,
                range_start,
                range_end,
                status,
                &headers,
                &body,
            );
            let passed = check.is_ok();

            TestResult {
                name,
                passed,
                error: check.err().map(|err| err.to_string()),
                duration_ms: start.elapsed().as_millis(),
            }
        }
        Err(e) => TestResult {
            name,
            passed: false,
            error: Some(e.to_string()),
            duration_ms: start.elapsed().as_millis(),
        },
    }
}

async fn test_http_connect_large_range_response(agent_addr: &str) -> TestResult {
    let start = std::time::Instant::now();
    let name = "HTTP CONNECT Range 分片下载".to_string();
    let client = MockHttpClient::new(agent_addr.to_string());

    let file_size = 3 * 1024 * 1024;
    let range_start = 512 * 1024 + 33;
    let range_end = range_start + 8191;
    let headers = [("Range", format!("bytes={range_start}-{range_end}"))];

    match client
        .connect_tunnel_get_bytes_with_headers(
            "127.0.0.1:9090",
            &format!("/large?size={file_size}"),
            &headers,
        )
        .await
    {
        Ok((_, status, headers, body)) => {
            let check = verify_large_range_response(
                "CONNECT Range",
                file_size,
                range_start,
                range_end,
                status,
                &headers,
                &body,
            );
            let passed = check.is_ok();

            TestResult {
                name,
                passed,
                error: check.err().map(|err| err.to_string()),
                duration_ms: start.elapsed().as_millis(),
            }
        }
        Err(e) => TestResult {
            name,
            passed: false,
            error: Some(e.to_string()),
            duration_ms: start.elapsed().as_millis(),
        },
    }
}

async fn test_blocked_target_connects_do_not_truncate_range_downloads(
    agent_addr: &str,
) -> TestResult {
    let start = std::time::Instant::now();
    let name = "Yamux 阻塞连接不截断分片下载".to_string();

    let result = run_blocked_target_connect_range_regression(agent_addr).await;

    TestResult {
        name,
        passed: result.is_ok(),
        error: result.err().map(|err| err.to_string()),
        duration_ms: start.elapsed().as_millis(),
    }
}

async fn test_fluctuating_target_does_not_truncate_range_downloads(agent_addr: &str) -> TestResult {
    let start = std::time::Instant::now();
    let name = "网络波动不截断分片下载".to_string();

    let result = run_fluctuating_target_range_regression(agent_addr).await;

    TestResult {
        name,
        passed: result.is_ok(),
        error: result.err().map(|err| err.to_string()),
        duration_ms: start.elapsed().as_millis(),
    }
}

async fn run_blocked_target_connect_range_regression(agent_addr: &str) -> Result<()> {
    let file_size = 8 * 1024 * 1024_u64;
    let chunk_size = 64 * 1024_u64;
    let chunk_count = 24_u64;

    let mut blocker_handles = Vec::with_capacity(18);
    for worker_id in 0..18 {
        let agent_addr = agent_addr.to_string();
        blocker_handles.push(tokio::spawn(async move {
            run_blocked_target_connect_attempt(agent_addr, worker_id).await;
        }));
    }

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut download_handles = Vec::with_capacity(chunk_count as usize);
    for chunk_idx in 0..chunk_count {
        let agent_addr = agent_addr.to_string();
        download_handles.push(tokio::spawn(async move {
            let range_start = chunk_idx * chunk_size;
            let range_end = range_start + chunk_size - 1;

            if chunk_idx % 2 == 0 {
                verify_http_range_chunk(&agent_addr, file_size, range_start, range_end).await
            } else {
                verify_connect_range_chunk(&agent_addr, file_size, range_start, range_end).await
            }
        }));
    }

    let mut errors = Vec::new();
    for handle in download_handles {
        match handle.await.context("range download task panicked")? {
            Ok(()) => {}
            Err(err) => errors.push(err.to_string()),
        }
    }

    for handle in blocker_handles {
        let _ = handle.await;
    }

    anyhow::ensure!(
        errors.is_empty(),
        "分片下载在阻塞连接扰动下失败：{}",
        errors.join("; ")
    );

    Ok(())
}

async fn run_fluctuating_target_range_regression(agent_addr: &str) -> Result<()> {
    let target_authority = "127.0.0.1:9090".to_string();
    let file_size = 4 * 1024 * 1024_u64;
    let chunk_size = 48 * 1024_u64;
    let chunk_count = 12_u64;

    let mut handles = Vec::with_capacity(chunk_count as usize);
    for chunk_idx in 0..chunk_count {
        let agent_addr = agent_addr.to_string();
        let target_authority = target_authority.clone();
        handles.push(tokio::spawn(async move {
            let range_start = chunk_idx * chunk_size + (chunk_idx % 5);
            let range_end = range_start + chunk_size - 1;

            let check = match chunk_idx % 3 {
                0 => {
                    verify_fluctuating_http_range_chunk(
                        &agent_addr,
                        &target_authority,
                        file_size,
                        range_start,
                        range_end,
                    )
                    .await
                }
                1 => {
                    verify_fluctuating_connect_range_chunk(
                        &agent_addr,
                        &target_authority,
                        file_size,
                        range_start,
                        range_end,
                    )
                    .await
                }
                _ => {
                    verify_fluctuating_socks5_range_chunk(
                        &agent_addr,
                        &target_authority,
                        file_size,
                        range_start,
                        range_end,
                    )
                    .await
                }
            };

            check.with_context(|| {
                format!("fluctuating target range {range_start}-{range_end} failed")
            })
        }));
    }

    let mut errors = Vec::new();
    for handle in handles {
        match tokio::time::timeout(FLUCTUATING_TARGET_TIMEOUT, handle)
            .await
            .context("fluctuating range download task timeout")?
            .context("fluctuating range download task panicked")?
        {
            Ok(()) => {}
            Err(err) => errors.push(err.to_string()),
        }
    }

    anyhow::ensure!(
        errors.is_empty(),
        "分片下载在网络波动目标下失败：{}",
        errors.join("; ")
    );

    Ok(())
}

async fn verify_fluctuating_http_range_chunk(
    agent_addr: &str,
    target_authority: &str,
    file_size: u64,
    range_start: u64,
    range_end: u64,
) -> Result<()> {
    let client = MockHttpClient::new(agent_addr.to_string());
    let headers = [("Range", format!("bytes={range_start}-{range_end}"))];
    let target_url = format!("http://{target_authority}/fluctuating-large?size={file_size}");
    let request = client.get_bytes_with_headers(&target_url, &headers);
    let (_, status, headers, body) = tokio::time::timeout(FLUCTUATING_TARGET_TIMEOUT, request)
        .await
        .context("HTTP fluctuating range timeout")??;

    verify_large_range_response(
        "HTTP Range with fluctuating target",
        file_size,
        range_start,
        range_end,
        status,
        &headers,
        &body,
    )
}

async fn verify_fluctuating_connect_range_chunk(
    agent_addr: &str,
    target_authority: &str,
    file_size: u64,
    range_start: u64,
    range_end: u64,
) -> Result<()> {
    let client = MockHttpClient::new(agent_addr.to_string());
    let headers = [("Range", format!("bytes={range_start}-{range_end}"))];
    let target_path = format!("/fluctuating-large?size={file_size}");
    let request =
        client.connect_tunnel_get_bytes_with_headers(target_authority, &target_path, &headers);
    let (_, status, headers, body) = tokio::time::timeout(FLUCTUATING_TARGET_TIMEOUT, request)
        .await
        .context("CONNECT fluctuating range timeout")??;

    verify_large_range_response(
        "CONNECT Range with fluctuating target",
        file_size,
        range_start,
        range_end,
        status,
        &headers,
        &body,
    )
}

async fn verify_fluctuating_socks5_range_chunk(
    agent_addr: &str,
    target_authority: &str,
    file_size: u64,
    range_start: u64,
    range_end: u64,
) -> Result<()> {
    let target_addr: SocketAddr = target_authority
        .parse()
        .context("invalid fluctuating target addr")?;
    let mut stream = TcpStream::connect(agent_addr)
        .await
        .context("failed to connect to agent for SOCKS5 fluctuating range")?;

    async_socks5::connect(
        &mut stream,
        (target_addr.ip().to_string(), target_addr.port()),
        None,
    )
    .await
    .context("failed to connect through SOCKS5 for fluctuating range")?;

    let request = format!(
        "GET /fluctuating-large?size={file_size} HTTP/1.1\r\nHost: {target_authority}\r\nRange: bytes={range_start}-{range_end}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .context("failed to write SOCKS5 fluctuating range request")?;
    stream
        .flush()
        .await
        .context("failed to flush SOCKS5 fluctuating range request")?;

    let (status, headers, body) = tokio::time::timeout(
        FLUCTUATING_TARGET_TIMEOUT,
        read_raw_http_response(&mut stream),
    )
    .await
    .context("SOCKS5 fluctuating range timeout")??;

    verify_large_range_response(
        "SOCKS5 Range with fluctuating target",
        file_size,
        range_start,
        range_end,
        status,
        &headers,
        &body,
    )
}

async fn verify_http_range_chunk(
    agent_addr: &str,
    file_size: u64,
    range_start: u64,
    range_end: u64,
) -> Result<()> {
    let client = MockHttpClient::new(agent_addr.to_string());
    let headers = [("Range", format!("bytes={range_start}-{range_end}"))];
    let (_, status, headers, body) = client
        .get_bytes_with_headers(
            &format!("http://127.0.0.1:9090/large?size={file_size}"),
            &headers,
        )
        .await
        .with_context(|| format!("HTTP range {range_start}-{range_end} failed"))?;

    verify_large_range_response(
        "HTTP Range with blocked target connects",
        file_size,
        range_start,
        range_end,
        status,
        &headers,
        &body,
    )
}

async fn verify_connect_range_chunk(
    agent_addr: &str,
    file_size: u64,
    range_start: u64,
    range_end: u64,
) -> Result<()> {
    let client = MockHttpClient::new(agent_addr.to_string());
    let headers = [("Range", format!("bytes={range_start}-{range_end}"))];
    let (_, status, headers, body) = client
        .connect_tunnel_get_bytes_with_headers(
            "127.0.0.1:9090",
            &format!("/large?size={file_size}"),
            &headers,
        )
        .await
        .with_context(|| format!("CONNECT range {range_start}-{range_end} failed"))?;

    verify_large_range_response(
        "CONNECT Range with blocked target connects",
        file_size,
        range_start,
        range_end,
        status,
        &headers,
        &body,
    )
}

async fn run_blocked_target_connect_attempt(agent_addr: String, worker_id: usize) {
    match worker_id % 3 {
        0 => {
            let client = MockHttpClient::new(agent_addr);
            let _ = tokio::time::timeout(
                BLOCKED_TARGET_TIMEOUT,
                client.get(&format!(
                    "http://{BLOCKED_TARGET_HOST}:{BLOCKED_TARGET_PORT}/"
                )),
            )
            .await;
        }
        1 => {
            let client = MockHttpClient::new(agent_addr);
            let _ = tokio::time::timeout(
                BLOCKED_TARGET_TIMEOUT,
                client.connect_tunnel_get_bytes_with_headers(
                    &format!("{BLOCKED_TARGET_HOST}:{BLOCKED_TARGET_PORT}"),
                    "/",
                    &[],
                ),
            )
            .await;
        }
        _ => {
            let client = MockSocks5Client::new(agent_addr);
            let _ = tokio::time::timeout(
                BLOCKED_TARGET_TIMEOUT,
                client.send_receive(BLOCKED_TARGET_HOST, BLOCKED_TARGET_PORT, b"probe"),
            )
            .await;
        }
    }
}

async fn read_http_head_bytes(stream: &mut TcpStream) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut bytes = Vec::with_capacity(1024);
    let mut buf = [0_u8; 1024];

    loop {
        let n = stream
            .read(&mut buf)
            .await
            .context("failed to read HTTP head")?;
        anyhow::ensure!(n != 0, "connection closed before HTTP head");
        bytes.extend_from_slice(&buf[..n]);

        if let Some(end) = find_http_head_end(&bytes) {
            let leftover = bytes.split_off(end);
            return Ok((bytes, leftover));
        }

        anyhow::ensure!(bytes.len() <= 16 * 1024, "HTTP head too large");
    }
}

fn find_http_head_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

async fn read_raw_http_response(stream: &mut TcpStream) -> Result<(StatusCode, HeaderMap, Bytes)> {
    let (head_bytes, leftover) = read_http_head_bytes(stream).await?;
    let head = String::from_utf8(head_bytes).context("HTTP response head is not UTF-8")?;
    let mut lines = head.lines();
    let status_line = lines.next().context("missing HTTP response status line")?;
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .context("missing HTTP response status code")?
        .parse::<u16>()
        .context("invalid HTTP response status code")?;
    let status = StatusCode::from_u16(status_code).context("unsupported HTTP status code")?;

    let mut headers = HeaderMap::new();
    for line in lines {
        if line.trim().is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = HeaderName::from_bytes(name.trim().as_bytes())
            .with_context(|| format!("invalid response header name: {name}"))?;
        let value = HeaderValue::from_str(value.trim())
            .with_context(|| format!("invalid response header value for {name}"))?;
        headers.append(name, value);
    }

    let content_length = headers
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .context("missing or invalid raw response content-length")?;

    let mut body = leftover;
    if body.len() < content_length {
        let remaining = content_length - body.len();
        let mut tail = vec![0_u8; remaining];
        stream
            .read_exact(&mut tail)
            .await
            .context("failed to read raw response body")?;
        body.extend_from_slice(&tail);
    }
    body.truncate(content_length);

    Ok((status, headers, Bytes::from(body)))
}

fn verify_large_range_response(
    label: &str,
    file_size: u64,
    range_start: u64,
    range_end: u64,
    status: StatusCode,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<()> {
    let expected_len = range_end - range_start + 1;
    let actual_body_len = body.len() as u64;
    let content_length = headers
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .with_context(|| {
            format!("{label} missing or invalid content-length for range {range_start}-{range_end}")
        })?;

    anyhow::ensure!(
        status == StatusCode::PARTIAL_CONTENT,
        "{label} unexpected status {status} for range {range_start}-{range_end}"
    );
    anyhow::ensure!(
        content_length == expected_len,
        "{label} content-length mismatch for range {range_start}-{range_end}: header {content_length}, expected {expected_len}"
    );
    anyhow::ensure!(
        content_length == actual_body_len,
        "{label} content-length/body mismatch for range {range_start}-{range_end}: header {content_length}, body {actual_body_len}"
    );

    let expected_content_range = format!("bytes {range_start}-{range_end}/{file_size}");
    let actual_content_range = headers
        .get(hyper::header::CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    anyhow::ensure!(
        actual_content_range == expected_content_range,
        "{label} unexpected content-range for range {range_start}-{range_end}: {actual_content_range}"
    );

    if let Some((offset, byte)) = body.iter().enumerate().find(|(offset, byte)| {
        **byte != crate::mock_target::large_file_byte_at(range_start + *offset as u64)
    }) {
        anyhow::bail!(
            "{label} body mismatch at absolute offset {}: got {}, expected {}",
            range_start + offset as u64,
            byte,
            crate::mock_target::large_file_byte_at(range_start + offset as u64)
        );
    }

    Ok(())
}

async fn test_http_json(agent_addr: &str) -> TestResult {
    let start = std::time::Instant::now();
    let name = "HTTP JSON 响应".to_string();

    let client = MockHttpClient::new(agent_addr.to_string());

    match client.get("http://127.0.0.1:9090/json").await {
        Ok((_, body)) => {
            let passed = body.contains("status") && body.contains("success");
            TestResult {
                name,
                passed,
                error: if !passed {
                    Some("JSON 响应无效".to_string())
                } else {
                    None
                },
                duration_ms: start.elapsed().as_millis(),
            }
        }
        Err(e) => TestResult {
            name,
            passed: false,
            error: Some(e.to_string()),
            duration_ms: start.elapsed().as_millis(),
        },
    }
}

async fn test_socks5_echo(agent_addr: &str) -> TestResult {
    let start = std::time::Instant::now();
    let name = "SOCKS5 TCP 回显".to_string();

    let client = MockSocks5Client::new(agent_addr.to_string());
    let test_data = b"SOCKS5 Echo Test";

    match client.send_receive("127.0.0.1", 9091, test_data).await {
        Ok((_, response)) => {
            let passed = response == test_data;
            TestResult {
                name,
                passed,
                error: if !passed {
                    Some("回显响应与请求不匹配".to_string())
                } else {
                    None
                },
                duration_ms: start.elapsed().as_millis(),
            }
        }
        Err(e) => TestResult {
            name,
            passed: false,
            error: Some(e.to_string()),
            duration_ms: start.elapsed().as_millis(),
        },
    }
}

async fn test_socks5_large_data(agent_addr: &str) -> TestResult {
    let start = std::time::Instant::now();
    let name = "SOCKS5 大数据传输".to_string();

    let client = MockSocks5Client::new(agent_addr.to_string());
    let test_data: Vec<u8> = (0..8192).map(|i| (i % 256) as u8).collect();

    match client.send_receive("127.0.0.1", 9091, &test_data).await {
        Ok((_, response)) => {
            let passed = response.len() == test_data.len() && response == test_data;
            TestResult {
                name,
                passed,
                error: if !passed {
                    Some(format!(
                        "数据传输失败。已发送 {}，已接收 {}",
                        test_data.len(),
                        response.len()
                    ))
                } else {
                    None
                },
                duration_ms: start.elapsed().as_millis(),
            }
        }
        Err(e) => TestResult {
            name,
            passed: false,
            error: Some(e.to_string()),
            duration_ms: start.elapsed().as_millis(),
        },
    }
}

async fn test_socks5_udp(agent_addr: &str) -> TestResult {
    let start = std::time::Instant::now();
    let name = "SOCKS5 UDP 关联".to_string();

    let client = MockSocks5Client::new(agent_addr.to_string());
    let test_data = b"SOCKS5 UDP Echo Test";

    match client.udp_send_receive("127.0.0.1", 9092, test_data).await {
        Ok((_, response)) => {
            let passed = response == test_data;
            TestResult {
                name,
                passed,
                error: if !passed {
                    Some(format!(
                        "回显响应与请求不匹配。已发送：{:?}，已接收：{:?}",
                        test_data, response
                    ))
                } else {
                    None
                },
                duration_ms: start.elapsed().as_millis(),
            }
        }
        Err(e) => TestResult {
            name,
            passed: false,
            error: Some(e.to_string()),
            duration_ms: start.elapsed().as_millis(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integration_results() {
        let mut results = IntegrationTestResults {
            total_tests: 0,
            passed: 0,
            failed: 0,
            test_details: Vec::new(),
        };

        results.add_test(TestResult {
            name: "Test 1".to_string(),
            passed: true,
            error: None,
            duration_ms: 100,
        });

        assert_eq!(results.total_tests, 1);
        assert_eq!(results.passed, 1);
        assert_eq!(results.failed, 0);
    }
}
