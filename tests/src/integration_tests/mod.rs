use crate::mock_client::{MockHttpClient, MockSocks5Client};
use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::HeaderMap;
use hyper::Request;
use hyper::StatusCode;
use hyper::header::{HeaderName, HeaderValue};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{error, info};

const BLOCKED_TARGET_HOST: &str = "203.0.113.1";
const BLOCKED_TARGET_PORT: u16 = 81;
const BLOCKED_TARGET_TIMEOUT: Duration = Duration::from_millis(350);
const FLUCTUATING_TARGET_TIMEOUT: Duration = Duration::from_secs(20);
const BROWSER_LIKE_TIMEOUT: Duration = Duration::from_secs(25);

#[derive(Clone, Copy)]
enum RangeProtocol {
    Http,
    Connect,
    Socks5,
}

#[derive(Clone, Copy)]
enum RangeEndpoint {
    Large,
    Fluctuating,
}

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
mod backpressure;
mod concurrency;
mod protocol_tests;
mod range_protocols;
mod raw_requests;
mod raw_response;
mod regression_tests;
mod session_regressions;

use backpressure::*;
use concurrency::*;
use protocol_tests::*;
use range_protocols::*;
use raw_requests::*;
use raw_response::*;
use regression_tests::*;
use session_regressions::*;

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

    // 测试浏览器式长连接复用不会截断同一连接上的连续分片
    results.add_test(test_browser_like_reused_connections_do_not_truncate_ranges(agent_addr).await);

    // 测试并发大/小分片都严格满足 Content-Length
    results.add_test(test_concurrent_segment_sizes_match_content_length(agent_addr).await);

    // 测试 HTTP/2 多路复用隧道不会截断并发分片
    results.add_test(test_http2_multiplexed_tunnels_do_not_truncate_ranges(agent_addr).await);

    // 测试浏览器取消/seek 后不会污染后续正常分片
    results.add_test(test_client_cancellations_do_not_poison_range_downloads(agent_addr).await);

    // 测试 client 慢读/backpressure 下仍然读完整 Content-Length
    results.add_test(test_slow_clients_do_not_truncate_range_downloads(agent_addr).await);

    // 测试长连接、取消、慢读和失败目标混跑后 session 仍可继续服务分片
    results.add_test(test_connection_churn_does_not_exhaust_yamux_sessions(agent_addr).await);

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
    pub fn add_test(&mut self, result: TestResult) {
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
