use anyhow::Result;
use integration_test_support::performance_tests::{
    DirectionalThroughput, InterfaceTestStatus, InterfaceThroughputResult,
    MaxThroughputTestResults, ThroughputInterface, ThroughputStageResult, build_concurrency_levels,
    calculate_directional_loss, merge_max_throughput_results, parse_route_interface,
    select_peak_stage,
};
use integration_test_support::report::generate_max_throughput_reports;

#[test]
fn concurrency_sweep_reaches_non_power_of_two_maximum() -> Result<()> {
    assert_eq!(
        build_concurrency_levels(1, 70)?,
        vec![1, 2, 4, 8, 16, 32, 64, 70]
    );
    assert_eq!(build_concurrency_levels(8, 8)?, vec![8]);
    assert!(build_concurrency_levels(0, 8).is_err());
    assert!(build_concurrency_levels(8, 4).is_err());
    Ok(())
}

#[test]
fn peak_selection_rejects_unstable_faster_stage() {
    let stages = vec![
        stage(8, 450.0, 440.0, true),
        stage(16, 600.0, 590.0, false),
        stage(32, 520.0, 510.0, true),
    ];
    let peak = select_peak_stage(&stages).unwrap();
    assert_eq!(peak.concurrency, 32);
    assert_eq!(peak.throughput.aggregate_mbps, 1_030.0);
}

#[test]
fn calculates_upload_and_download_loss_independently() {
    let loss = calculate_directional_loss(throughput(1_000.0, 800.0), throughput(900.0, 600.0));
    assert_eq!(loss.upload_mbps, 100.0);
    assert_eq!(loss.upload_percent, 10.0);
    assert_eq!(loss.download_mbps, 200.0);
    assert_eq!(loss.download_percent, 25.0);
    assert!((loss.aggregate_percent - 16.666_666).abs() < 0.001);
}

#[test]
fn parses_macos_and_linux_tun_route_interfaces() {
    assert_eq!(
        parse_route_interface("route to: 1.1.1.1\ninterface: utun8\n").as_deref(),
        Some("utun8")
    );
    assert_eq!(
        parse_route_interface("1.1.1.1 via 10.0.0.1 dev tun0 src 10.0.0.2\n").as_deref(),
        Some("tun0")
    );
    assert_eq!(parse_route_interface("default 10.0.0.1"), None);
}

#[test]
fn merge_preserves_failed_high_stages_and_confirms_peak() -> Result<()> {
    let baseline = throughput(900.0, 900.0);
    let mut base = partial_results(
        vec![1, 256],
        vec![
            completed_interface(ThroughputInterface::UpstreamUdp, baseline, None),
            completed_interface(
                ThroughputInterface::UdpRelay,
                throughput(400.0, 390.0),
                None,
            ),
        ],
    );
    base.interfaces[1].stages = vec![stage(256, 400.0, 390.0, true)];
    let mut continuation = partial_results(
        vec![512, 1024, 2048],
        vec![completed_interface(
            ThroughputInterface::UdpRelay,
            throughput(500.0, 490.0),
            None,
        )],
    );
    continuation.interfaces[0].stages = vec![
        stage(512, 500.0, 490.0, true),
        stage(1024, 300.0, 295.0, true),
        stage(2048, 100.0, 90.0, false),
    ];

    merge_max_throughput_results(&mut base, continuation)?;
    let relay = &base.interfaces[1];
    assert_eq!(relay.best_concurrency, Some(512));
    assert!(relay.peak_confirmed);
    assert_eq!(relay.stages.len(), 4);
    assert!(!relay.stages.last().unwrap().sustainable);
    assert!(relay.loss_from_upstream.is_some());
    Ok(())
}

#[test]
fn generates_chinese_directional_reports() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let html_path = directory.path().join("max-throughput-report.html");
    let baseline = throughput(500.0, 480.0);
    let socks = throughput(450.0, 420.0);
    let results = MaxThroughputTestResults {
        test_duration_secs: 20,
        agent_addr: "127.0.0.1:7080".to_string(),
        tcp_target: "127.0.0.1:9091".to_string(),
        udp_target: "127.0.0.1:9092".to_string(),
        tcp_payload_size: 65_536,
        udp_payload_size: 1_200,
        stage_duration_secs: 5,
        max_failure_rate_percent: 1.0,
        tested_concurrency_levels: vec![1, 2, 4],
        interfaces: vec![
            completed_interface(ThroughputInterface::UpstreamTcp, baseline, None),
            completed_interface(ThroughputInterface::UpstreamUdp, baseline, None),
            failed_tun(),
            completed_interface(
                ThroughputInterface::HttpProxy,
                socks,
                Some(calculate_directional_loss(baseline, socks)),
            ),
            completed_interface(
                ThroughputInterface::SocksProxy,
                socks,
                Some(calculate_directional_loss(baseline, socks)),
            ),
            completed_interface(
                ThroughputInterface::UdpRelay,
                socks,
                Some(calculate_directional_loss(baseline, socks)),
            ),
        ],
    };

    generate_max_throughput_reports(&results, html_path.to_str().unwrap())?;
    let markdown = std::fs::read_to_string(directory.path().join("max-throughput-report.md"))?;
    let html = std::fs::read_to_string(&html_path)?;
    let json = std::fs::read_to_string(directory.path().join("max-throughput-report.json"))?;
    assert!(markdown.contains("上行损失"));
    assert!(markdown.contains("下行损失"));
    assert!(markdown.contains("未完成原因"));
    assert!(html.contains("各接口最高网速测试报告"));
    assert!(html.contains("450.00 Mbps"));
    assert!(json.contains("upload_mbps"));
    Ok(())
}

fn completed_interface(
    interface: ThroughputInterface,
    peak: DirectionalThroughput,
    loss: Option<integration_test_support::performance_tests::DirectionalLoss>,
) -> InterfaceThroughputResult {
    InterfaceThroughputResult {
        interface,
        interface_name: interface.name_zh().to_string(),
        status: InterfaceTestStatus::Completed,
        error: None,
        route_interface: None,
        best_concurrency: Some(4),
        peak_confirmed: false,
        peak,
        upstream_interface: interface.upstream(),
        loss_from_upstream: loss,
        stages: vec![stage(4, peak.upload_mbps, peak.download_mbps, true)],
    }
}

fn partial_results(
    levels: Vec<usize>,
    interfaces: Vec<InterfaceThroughputResult>,
) -> MaxThroughputTestResults {
    MaxThroughputTestResults {
        test_duration_secs: 10,
        agent_addr: "127.0.0.1:7080".to_string(),
        tcp_target: "127.0.0.1:9091".to_string(),
        udp_target: "127.0.0.1:9092".to_string(),
        tcp_payload_size: 65_536,
        udp_payload_size: 1_200,
        stage_duration_secs: 5,
        max_failure_rate_percent: 1.0,
        tested_concurrency_levels: levels,
        interfaces,
    }
}

fn failed_tun() -> InterfaceThroughputResult {
    InterfaceThroughputResult {
        interface: ThroughputInterface::Tun,
        interface_name: ThroughputInterface::Tun.name_zh().to_string(),
        status: InterfaceTestStatus::Failed,
        error: Some("目标没有经过 TUN".to_string()),
        route_interface: None,
        best_concurrency: None,
        peak_confirmed: false,
        peak: DirectionalThroughput::default(),
        upstream_interface: Some(ThroughputInterface::UpstreamTcp),
        loss_from_upstream: None,
        stages: Vec::new(),
    }
}

fn throughput(upload_mbps: f64, download_mbps: f64) -> DirectionalThroughput {
    DirectionalThroughput {
        upload_mbps,
        download_mbps,
        aggregate_mbps: upload_mbps + download_mbps,
    }
}

fn stage(
    concurrency: usize,
    upload_mbps: f64,
    download_mbps: f64,
    sustainable: bool,
) -> ThroughputStageResult {
    ThroughputStageResult {
        concurrency,
        duration_secs: 5,
        payload_size: 65_536,
        successful_chunks: 1_000,
        failed_chunks: usize::from(!sustainable),
        failure_rate_percent: if sustainable { 0.0 } else { 2.0 },
        chunks_per_second: 200.0,
        throughput: throughput(upload_mbps, download_mbps),
        p95_rtt_ms: 2.0,
        upload_bytes: 64 * 1024 * 1024,
        download_bytes: 64 * 1024 * 1024,
        sustainable,
    }
}
