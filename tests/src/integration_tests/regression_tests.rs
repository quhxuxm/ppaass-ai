use super::*;

pub(super) async fn test_blocked_target_connects_do_not_truncate_range_downloads(
    agent_addr: &str,
) -> TestResult {
    let start = std::time::Instant::now();
    let name = "Yamux 阻塞连接不截断分片下载".to_string();

    let result = run_blocked_target_connect_range_regression(agent_addr).await;

    TestResult {
        name,
        passed: result.is_ok(),
        error: result.err().map(format_anyhow_error),
        duration_ms: start.elapsed().as_millis(),
    }
}

pub(super) async fn test_fluctuating_target_does_not_truncate_range_downloads(
    agent_addr: &str,
) -> TestResult {
    let start = std::time::Instant::now();
    let name = "网络波动不截断分片下载".to_string();

    let result = run_fluctuating_target_range_regression(agent_addr).await;

    TestResult {
        name,
        passed: result.is_ok(),
        error: result.err().map(format_anyhow_error),
        duration_ms: start.elapsed().as_millis(),
    }
}

pub(super) async fn test_browser_like_reused_connections_do_not_truncate_ranges(
    agent_addr: &str,
) -> TestResult {
    let start = std::time::Instant::now();
    let name = "浏览器式长连接复用不截断分片".to_string();

    let result = run_browser_like_reused_connection_regression(agent_addr).await;

    TestResult {
        name,
        passed: result.is_ok(),
        error: result.err().map(format_anyhow_error),
        duration_ms: start.elapsed().as_millis(),
    }
}

pub(super) async fn test_http2_multiplexed_tunnels_do_not_truncate_ranges(
    agent_addr: &str,
) -> TestResult {
    let start = std::time::Instant::now();
    let name = "HTTP/2 多路复用隧道不截断分片".to_string();

    let result = run_http2_multiplexed_tunnel_regression(agent_addr).await;

    TestResult {
        name,
        passed: result.is_ok(),
        error: result.err().map(format_anyhow_error),
        duration_ms: start.elapsed().as_millis(),
    }
}

pub(super) async fn test_concurrent_segment_sizes_match_content_length(
    agent_addr: &str,
) -> TestResult {
    let start = std::time::Instant::now();
    let name = "并发大小分片长度一致".to_string();

    let result = run_concurrent_segment_size_regression(agent_addr).await;

    TestResult {
        name,
        passed: result.is_ok(),
        error: result.err().map(format_anyhow_error),
        duration_ms: start.elapsed().as_millis(),
    }
}

pub(super) async fn test_client_cancellations_do_not_poison_range_downloads(
    agent_addr: &str,
) -> TestResult {
    let start = std::time::Instant::now();
    let name = "客户端取消不污染后续分片".to_string();

    let result = run_client_cancellation_regression(agent_addr).await;

    TestResult {
        name,
        passed: result.is_ok(),
        error: result.err().map(format_anyhow_error),
        duration_ms: start.elapsed().as_millis(),
    }
}

pub(super) async fn test_slow_clients_do_not_truncate_range_downloads(
    agent_addr: &str,
) -> TestResult {
    let start = std::time::Instant::now();
    let name = "慢读客户端不截断分片下载".to_string();

    let result = run_slow_client_backpressure_regression(agent_addr).await;

    TestResult {
        name,
        passed: result.is_ok(),
        error: result.err().map(format_anyhow_error),
        duration_ms: start.elapsed().as_millis(),
    }
}

pub(super) async fn test_connection_churn_does_not_exhaust_yamux_sessions(
    agent_addr: &str,
) -> TestResult {
    let start = std::time::Instant::now();
    let name = "连接 churn 不耗尽 Yamux session".to_string();

    let result = run_connection_churn_regression(agent_addr).await;

    TestResult {
        name,
        passed: result.is_ok(),
        error: result.err().map(format_anyhow_error),
        duration_ms: start.elapsed().as_millis(),
    }
}

pub(super) fn format_anyhow_error(err: anyhow::Error) -> String {
    format!("{err:#}")
}
