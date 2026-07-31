use anyhow::Result;
use hdrhistogram::Histogram;
use integration_test_support::integration_tests::{IntegrationTestResults, TestResult};
use integration_test_support::mock_client::{MockHttpClient, MockSocks5Client, MockTcpClient};
use integration_test_support::mock_target::{
    MockHttpServer, MockTcpServer, MockUdpServer, parse_range_header,
};
use integration_test_support::performance_tests::{
    PerformanceTestResults, RequestMetrics, SystemMetrics, calculate_metrics,
    calculate_tcp_metrics, calculate_udp_metrics, format_quic_version,
    parse_quic_version_negotiation_response, quic_version_negotiation_probe,
};
use integration_test_support::report::generate_reports;

#[test]
fn integration_results_track_passed_tests() {
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

#[test]
fn metrics_calculation_counts_successes() {
    let mut histogram = Histogram::<u64>::new(3).unwrap();
    histogram.record(100).unwrap();
    histogram.record(200).unwrap();
    histogram.record(300).unwrap();

    let metrics = calculate_metrics(&histogram, 3, 0);
    assert_eq!(metrics.total_requests, 3);
    assert_eq!(metrics.successful, 3);
    assert_eq!(metrics.failed, 0);
    assert!(metrics.avg_latency_ms > 0.0);
}

#[test]
fn udp_metrics_calculation_uses_microseconds() {
    let mut histogram = Histogram::<u64>::new(3).unwrap();
    histogram.record(500).unwrap();
    histogram.record(1500).unwrap();
    histogram.record(2500).unwrap();

    let metrics = calculate_udp_metrics(&histogram, 3, 1, 4096);
    assert_eq!(metrics.total_datagrams, 4);
    assert_eq!(metrics.successful, 3);
    assert_eq!(metrics.failed, 1);
    assert!(metrics.avg_rtt_ms > 0.0);
    assert_eq!(metrics.total_bytes_transferred, 4096);
}

#[test]
fn tcp_metrics_calculation_uses_microseconds() {
    let mut histogram = Histogram::<u64>::new(3).unwrap();
    histogram.record(1000).unwrap();
    histogram.record(2000).unwrap();
    histogram.record(3000).unwrap();

    let metrics = calculate_tcp_metrics(&histogram, 3, 2, 128 * 1024);
    assert_eq!(metrics.total_chunks, 5);
    assert_eq!(metrics.successful, 3);
    assert_eq!(metrics.failed, 2);
    assert!(metrics.avg_rtt_ms >= 1.0);
    assert_eq!(metrics.total_bytes_transferred, 128 * 1024);
}

#[test]
fn quic_probe_is_padded_to_minimum_udp_payload() {
    let probe = quic_version_negotiation_probe(7, 42, 32);

    assert_eq!(probe.len(), 1200);
    assert_eq!(probe[0], 0xc0);
    assert_eq!(&probe[1..5], &0x0a0a_0a0a_u32.to_be_bytes());
}

#[test]
fn parses_quic_version_negotiation_versions() {
    let mut response = Vec::new();
    response.push(0x80);
    response.extend_from_slice(&0u32.to_be_bytes());
    response.push(8);
    response.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    response.push(8);
    response.extend_from_slice(&[8, 7, 6, 5, 4, 3, 2, 1]);
    response.extend_from_slice(&1u32.to_be_bytes());
    response.extend_from_slice(&0x6b33_43cf_u32.to_be_bytes());

    let versions = parse_quic_version_negotiation_response(&response).unwrap();

    assert_eq!(versions, vec![1, 0x6b33_43cf]);
    assert_eq!(format_quic_version(1), "0x00000001");
}

#[test]
fn mock_clients_keep_their_target_addresses() {
    let http = MockHttpClient::new("127.0.0.1:7070".to_string());
    let socks = MockSocks5Client::new("127.0.0.1:7070".to_string());
    let tcp = MockTcpClient::new("127.0.0.1:9091".to_string());

    assert_eq!(http.agent_addr(), "127.0.0.1:7070");
    assert_eq!(socks.agent_addr(), "127.0.0.1:7070");
    assert_eq!(tcp.target_addr(), "127.0.0.1:9091");
}

#[test]
fn mock_servers_keep_their_ports() {
    assert_eq!(MockHttpServer::new(19090).port(), 19090);
    assert_eq!(MockTcpServer::new(19091).port(), 19091);
    assert_eq!(MockUdpServer::new(19092).port(), 19092);
}

#[test]
fn parses_http_range_headers() {
    assert_eq!(
        parse_range_header(Some("bytes=10-19"), 100).unwrap(),
        Some((10, 19))
    );
    assert_eq!(
        parse_range_header(Some("bytes=90-200"), 100).unwrap(),
        Some((90, 99))
    );
    assert_eq!(
        parse_range_header(Some("bytes=-10"), 100).unwrap(),
        Some((90, 99))
    );
    assert!(parse_range_header(Some("bytes=100-101"), 100).is_err());
}

#[test]
fn generates_all_report_formats() -> Result<()> {
    let results = sample_performance_results();
    let directory = tempfile::tempdir()?;
    let html_path = directory.path().join("test-report.html");

    generate_reports(&results, html_path.to_str().unwrap())?;

    assert!(html_path.exists());
    assert!(directory.path().join("test-report.json").exists());
    assert!(directory.path().join("test-report.md").exists());
    Ok(())
}

fn sample_performance_results() -> PerformanceTestResults {
    PerformanceTestResults {
        test_duration_secs: 60,
        total_requests: 1000,
        successful_requests: 950,
        failed_requests: 50,
        requests_per_second: 16.67,
        throughput_mbps: 10.5,
        http_metrics: request_metrics(600, 570, 30, 1_024_000),
        socks5_metrics: request_metrics(400, 380, 20, 512_000),
        system_metrics: SystemMetrics {
            cpu_usage_percent: 45.5,
            memory_usage_mb: 256,
            peak_memory_mb: 300,
        },
    }
}

fn request_metrics(
    total_requests: usize,
    successful: usize,
    failed: usize,
    total_bytes_transferred: u64,
) -> RequestMetrics {
    RequestMetrics {
        total_requests,
        successful,
        failed,
        avg_latency_ms: 50.0,
        min_latency_ms: 10.0,
        max_latency_ms: 200.0,
        p50_latency_ms: 45.0,
        p95_latency_ms: 100.0,
        p99_latency_ms: 150.0,
        total_bytes_transferred,
    }
}
