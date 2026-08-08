use super::*;
use crate::performance_tests::max_throughput::{
    DirectionalThroughput, InterfaceTestStatus, InterfaceThroughputResult, MaxThroughputConfig,
    ThroughputInterface, ThroughputStageResult, failed_interface, select_peak_stage,
};

pub(super) async fn run_tcp_sweep(
    interface: ThroughputInterface,
    mode: TcpPerformanceMode,
    config: &MaxThroughputConfig,
    levels: &[usize],
    route_interface: Option<String>,
) -> InterfaceThroughputResult {
    let result = run_tcp_stages(mode, config, levels).await;
    finish_interface(interface, result, route_interface)
}

pub(super) async fn run_udp_sweep(
    interface: ThroughputInterface,
    mode: UdpPerformanceMode,
    config: &MaxThroughputConfig,
    levels: &[usize],
) -> InterfaceThroughputResult {
    let result = run_udp_stages(mode, config, levels).await;
    finish_interface(interface, result, None)
}

async fn run_tcp_stages(
    mode: TcpPerformanceMode,
    config: &MaxThroughputConfig,
    levels: &[usize],
) -> Result<Vec<ThroughputStageResult>> {
    if config.warmup_duration_secs > 0 {
        let warmup = run_tcp_mode_performance_tests(
            mode,
            &config.agent_addr,
            &config.tcp_target_host,
            config.tcp_target_port,
            config.start_concurrency,
            config.warmup_duration_secs,
            config.tcp_payload_size,
        )
        .await?;
        anyhow::ensure!(warmup.successful_chunks > 0, "预热阶段没有有效 TCP 数据");
    }

    let mut stages = Vec::with_capacity(levels.len());
    for (index, concurrency) in levels.iter().copied().enumerate() {
        settle(index, config.settle_duration_secs).await;
        let result = run_tcp_mode_performance_tests(
            mode,
            &config.agent_addr,
            &config.tcp_target_host,
            config.tcp_target_port,
            concurrency,
            config.stage_duration_secs,
            config.tcp_payload_size,
        )
        .await?;
        stages.push(stage_from_tcp(&result, config.max_failure_rate_percent));
    }
    Ok(stages)
}

async fn run_udp_stages(
    mode: UdpPerformanceMode,
    config: &MaxThroughputConfig,
    levels: &[usize],
) -> Result<Vec<ThroughputStageResult>> {
    if config.warmup_duration_secs > 0 {
        let warmup = run_udp_mode_performance_tests(
            mode,
            &config.agent_addr,
            &config.udp_target_host,
            config.udp_target_port,
            config.start_concurrency,
            config.warmup_duration_secs,
            config.udp_payload_size,
        )
        .await?;
        anyhow::ensure!(warmup.successful_datagrams > 0, "预热阶段没有有效 UDP 数据");
    }

    let mut stages = Vec::with_capacity(levels.len());
    for (index, concurrency) in levels.iter().copied().enumerate() {
        settle(index, config.settle_duration_secs).await;
        let result = run_udp_mode_performance_tests(
            mode,
            &config.agent_addr,
            &config.udp_target_host,
            config.udp_target_port,
            concurrency,
            config.stage_duration_secs,
            config.udp_payload_size,
        )
        .await?;
        stages.push(stage_from_udp(&result, config.max_failure_rate_percent));
    }
    Ok(stages)
}

async fn settle(index: usize, duration_secs: u64) {
    if index > 0 && duration_secs > 0 {
        tokio::time::sleep(Duration::from_secs(duration_secs)).await;
    }
}

fn finish_interface(
    interface: ThroughputInterface,
    result: Result<Vec<ThroughputStageResult>>,
    route_interface: Option<String>,
) -> InterfaceThroughputResult {
    let stages = match result {
        Ok(stages) => stages,
        Err(error) => return failed_interface(interface, error.to_string()),
    };
    let Some(peak) = select_peak_stage(&stages) else {
        let mut failed = failed_interface(interface, "没有并发阶段满足失败率门槛".to_string());
        failed.route_interface = route_interface;
        failed.stages = stages;
        return failed;
    };
    let best_concurrency = peak.concurrency;
    let peak_throughput = peak.throughput;
    let peak_index = stages
        .iter()
        .position(|stage| stage.concurrency == best_concurrency)
        .unwrap_or_default();
    let peak_confirmed = stages.len().saturating_sub(peak_index + 1) >= 2;
    info!(
        "{} 峰值：上行 {:.2}，下行 {:.2}，合计 {:.2} Mbps，并发 {}",
        interface.name_zh(),
        peak_throughput.upload_mbps,
        peak_throughput.download_mbps,
        peak_throughput.aggregate_mbps,
        best_concurrency
    );
    InterfaceThroughputResult {
        interface,
        interface_name: interface.name_zh().to_string(),
        status: InterfaceTestStatus::Completed,
        error: None,
        route_interface,
        best_concurrency: Some(best_concurrency),
        peak_confirmed,
        peak: peak_throughput,
        upstream_interface: interface.upstream(),
        loss_from_upstream: None,
        same_concurrency_comparison: None,
        stages,
    }
}

fn stage_from_tcp(
    result: &TcpPerformanceTestResults,
    max_failure_rate_percent: f64,
) -> ThroughputStageResult {
    ThroughputStageResult {
        concurrency: result.concurrency,
        duration_secs: result.test_duration_secs,
        payload_size: result.payload_size,
        successful_chunks: result.successful_chunks,
        failed_chunks: result.failed_chunks,
        failure_rate_percent: result.failure_rate_percent,
        chunks_per_second: result.chunks_per_second,
        throughput: DirectionalThroughput {
            upload_mbps: result.upload_throughput_mbps,
            download_mbps: result.download_throughput_mbps,
            aggregate_mbps: result.throughput_mbps,
        },
        p95_rtt_ms: result.tcp_metrics.p95_rtt_ms,
        upload_bytes: result.upload_bytes,
        download_bytes: result.download_bytes,
        sustainable: is_sustainable(
            result.successful_chunks,
            result.failure_rate_percent,
            max_failure_rate_percent,
        ),
        upstream_throughput: None,
        loss_from_upstream: None,
    }
}

fn stage_from_udp(
    result: &UdpPerformanceTestResults,
    max_failure_rate_percent: f64,
) -> ThroughputStageResult {
    ThroughputStageResult {
        concurrency: result.concurrency,
        duration_secs: result.test_duration_secs,
        payload_size: result.payload_size,
        successful_chunks: result.successful_datagrams,
        failed_chunks: result.failed_datagrams,
        failure_rate_percent: result.packet_loss_percent,
        chunks_per_second: result.datagrams_per_second,
        throughput: DirectionalThroughput {
            upload_mbps: result.upload_throughput_mbps,
            download_mbps: result.download_throughput_mbps,
            aggregate_mbps: result.throughput_mbps,
        },
        p95_rtt_ms: result.udp_metrics.p95_rtt_ms,
        upload_bytes: result.upload_bytes,
        download_bytes: result.download_bytes,
        sustainable: is_sustainable(
            result.successful_datagrams,
            result.packet_loss_percent,
            max_failure_rate_percent,
        ),
        upstream_throughput: None,
        loss_from_upstream: None,
    }
}

fn is_sustainable(success: usize, failure_rate: f64, maximum: f64) -> bool {
    success > 0 && failure_rate <= maximum
}
