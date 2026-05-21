use crate::mock_client::{MockHttpClient, MockSocks5Client};
use anyhow::Result;
use tracing::{error, info};

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
