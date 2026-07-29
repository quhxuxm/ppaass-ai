use super::*;

pub(super) async fn test_http_health(agent_addr: &str) -> TestResult {
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

pub(super) async fn test_http_echo(agent_addr: &str) -> TestResult {
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

pub(super) async fn test_http_large_response(agent_addr: &str) -> TestResult {
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

pub(super) async fn test_http_large_range_response(agent_addr: &str) -> TestResult {
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

pub(super) async fn test_http_connect_large_range_response(agent_addr: &str) -> TestResult {
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
pub(super) async fn test_http_json(agent_addr: &str) -> TestResult {
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

pub(super) async fn test_socks5_echo(agent_addr: &str) -> TestResult {
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

pub(super) async fn test_socks5_large_data(agent_addr: &str) -> TestResult {
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

pub(super) async fn test_socks5_udp(agent_addr: &str) -> TestResult {
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
