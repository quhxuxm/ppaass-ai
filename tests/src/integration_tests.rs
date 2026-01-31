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

/// Run all integration tests
pub async fn run_all_tests(agent_addr: &str) -> Result<IntegrationTestResults> {
    info!("=== Starting Integration Tests ===");
    
    let mut results = IntegrationTestResults {
        total_tests: 0,
        passed: 0,
        failed: 0,
        test_details: Vec::new(),
    };
    
    // Test HTTP health endpoint
    results.add_test(test_http_health(agent_addr).await);
    
    // Test HTTP echo endpoint
    results.add_test(test_http_echo(agent_addr).await);
    
    // Test HTTP large response
    results.add_test(test_http_large_response(agent_addr).await);
    
    // Test HTTP JSON response
    results.add_test(test_http_json(agent_addr).await);
    
    // Test SOCKS5 connection
    results.add_test(test_socks5_echo(agent_addr).await);
    
    // Test SOCKS5 large data transfer
    results.add_test(test_socks5_large_data(agent_addr).await);
    
    info!("=== Integration Tests Complete ===");
    info!("Total: {}, Passed: {}, Failed: {}", 
          results.total_tests, results.passed, results.failed);
    
    Ok(results)
}

impl IntegrationTestResults {
    fn add_test(&mut self, result: TestResult) {
        self.total_tests += 1;
        if result.passed {
            self.passed += 1;
            info!("✓ {} - PASSED ({} ms)", result.name, result.duration_ms);
        } else {
            self.failed += 1;
            error!("✗ {} - FAILED: {}", result.name, result.error.as_ref().unwrap_or(&"Unknown error".to_string()));
        }
        self.test_details.push(result);
    }
}

async fn test_http_health(agent_addr: &str) -> TestResult {
    let start = std::time::Instant::now();
    let name = "HTTP Health Check".to_string();
    
    let client = MockHttpClient::new(agent_addr.to_string());
    
    match client.get("http://127.0.0.1:9090/health").await {
        Ok((_, body)) => {
            let passed = body.contains("OK");
            TestResult {
                name,
                passed,
                error: if !passed { Some("Response didn't contain 'OK'".to_string()) } else { None },
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
    let name = "HTTP Echo".to_string();
    
    let client = MockHttpClient::new(agent_addr.to_string());
    let test_data = b"Hello, World!".to_vec();
    
    match client.post("http://127.0.0.1:9090/echo", test_data.clone()).await {
        Ok((_, body)) => {
            let passed = body.as_bytes() == test_data.as_slice();
            TestResult {
                name,
                passed,
                error: if !passed { Some("Echo response didn't match request".to_string()) } else { None },
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
    let name = "HTTP Large Response".to_string();
    
    let client = MockHttpClient::new(agent_addr.to_string());
    
    match client.get("http://127.0.0.1:9090/large").await {
        Ok((_, body)) => {
            let passed = body.len() >= 1024 * 1024; // Should be at least 1MB
            TestResult {
                name,
                passed,
                error: if !passed { Some(format!("Response too small: {} bytes", body.len())) } else { None },
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
    let name = "HTTP JSON Response".to_string();
    
    let client = MockHttpClient::new(agent_addr.to_string());
    
    match client.get("http://127.0.0.1:9090/json").await {
        Ok((_, body)) => {
            let passed = body.contains("status") && body.contains("success");
            TestResult {
                name,
                passed,
                error: if !passed { Some("JSON response invalid".to_string()) } else { None },
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
    let name = "SOCKS5 TCP Echo".to_string();
    
    let client = MockSocks5Client::new(agent_addr.to_string());
    let test_data = b"SOCKS5 Echo Test";
    
    match client.send_receive("127.0.0.1", 9091, test_data).await {
        Ok((_, response)) => {
            let passed = response == test_data;
            TestResult {
                name,
                passed,
                error: if !passed { Some("Echo response didn't match request".to_string()) } else { None },
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
    let name = "SOCKS5 Large Data Transfer".to_string();
    
    let client = MockSocks5Client::new(agent_addr.to_string());
    let test_data: Vec<u8> = (0..8192).map(|i| (i % 256) as u8).collect();
    
    match client.send_receive("127.0.0.1", 9091, &test_data).await {
        Ok((_, response)) => {
            let passed = response == test_data;
            TestResult {
                name,
                passed,
                error: if !passed { 
                    Some(format!("Data mismatch: sent {} bytes, received {} bytes", 
                                 test_data.len(), response.len())) 
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
