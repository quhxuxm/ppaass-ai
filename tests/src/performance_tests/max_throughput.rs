use super::*;
use crate::performance_tests::throughput_sweep::{run_tcp_sweep, run_udp_sweep};
use crate::performance_tests::tun_route::verify_tun_route;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ThroughputInterface {
    UpstreamTcp,
    UpstreamUdp,
    Tun,
    HttpProxy,
    SocksProxy,
    UdpRelay,
}

impl ThroughputInterface {
    pub fn name_zh(self) -> &'static str {
        match self {
            Self::UpstreamTcp => "TCP 直连基线",
            Self::UpstreamUdp => "UDP 直连基线",
            Self::Tun => "TUN 端到端",
            Self::HttpProxy => "HTTP CONNECT 端到端",
            Self::SocksProxy => "SOCKS5 TCP 端到端",
            Self::UdpRelay => "SOCKS5 UDP Relay 端到端",
        }
    }

    pub fn upstream(self) -> Option<Self> {
        match self {
            Self::Tun | Self::HttpProxy | Self::SocksProxy => Some(Self::UpstreamTcp),
            Self::UdpRelay => Some(Self::UpstreamUdp),
            Self::UpstreamTcp | Self::UpstreamUdp => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceTestStatus {
    Completed,
    Failed,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct DirectionalThroughput {
    pub upload_mbps: f64,
    pub download_mbps: f64,
    pub aggregate_mbps: f64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DirectionalLoss {
    pub upload_mbps: f64,
    pub upload_percent: f64,
    pub download_mbps: f64,
    pub download_percent: f64,
    pub aggregate_mbps: f64,
    pub aggregate_percent: f64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SameConcurrencyComparison {
    pub concurrency: usize,
    pub upstream: DirectionalThroughput,
    pub current: DirectionalThroughput,
    pub loss: DirectionalLoss,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThroughputStageResult {
    pub concurrency: usize,
    pub duration_secs: u64,
    pub payload_size: usize,
    pub successful_chunks: usize,
    pub failed_chunks: usize,
    pub failure_rate_percent: f64,
    pub chunks_per_second: f64,
    pub throughput: DirectionalThroughput,
    pub p95_rtt_ms: f64,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub sustainable: bool,
    #[serde(default)]
    pub upstream_throughput: Option<DirectionalThroughput>,
    #[serde(default)]
    pub loss_from_upstream: Option<DirectionalLoss>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceThroughputResult {
    pub interface: ThroughputInterface,
    pub interface_name: String,
    pub status: InterfaceTestStatus,
    pub error: Option<String>,
    pub route_interface: Option<String>,
    pub best_concurrency: Option<usize>,
    pub peak_confirmed: bool,
    pub peak: DirectionalThroughput,
    pub upstream_interface: Option<ThroughputInterface>,
    pub loss_from_upstream: Option<DirectionalLoss>,
    #[serde(default)]
    pub same_concurrency_comparison: Option<SameConcurrencyComparison>,
    pub stages: Vec<ThroughputStageResult>,
}

#[derive(Debug, Clone)]
pub struct MaxThroughputConfig {
    pub agent_addr: String,
    pub tcp_target_host: String,
    pub tcp_target_port: u16,
    pub udp_target_host: String,
    pub udp_target_port: u16,
    pub start_concurrency: usize,
    pub max_concurrency: usize,
    pub stage_duration_secs: u64,
    pub warmup_duration_secs: u64,
    pub settle_duration_secs: u64,
    pub tcp_payload_size: usize,
    pub udp_payload_size: usize,
    pub max_failure_rate_percent: f64,
    pub tun_interface: Option<String>,
    pub selected_interfaces: Vec<ThroughputInterface>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaxThroughputTestResults {
    pub test_duration_secs: u64,
    pub agent_addr: String,
    pub tcp_target: String,
    pub udp_target: String,
    pub tcp_payload_size: usize,
    pub udp_payload_size: usize,
    pub stage_duration_secs: u64,
    pub max_failure_rate_percent: f64,
    pub tested_concurrency_levels: Vec<usize>,
    pub interfaces: Vec<InterfaceThroughputResult>,
}

pub fn build_concurrency_levels(start: usize, maximum: usize) -> Result<Vec<usize>> {
    anyhow::ensure!(start > 0, "start concurrency must be greater than zero");
    anyhow::ensure!(maximum >= start, "max concurrency must be at least start");
    let mut levels = Vec::new();
    let mut current = start;
    while current < maximum {
        levels.push(current);
        current = current.saturating_mul(2);
        if current <= *levels.last().unwrap() {
            break;
        }
    }
    if levels.last().copied() != Some(maximum) {
        levels.push(maximum);
    }
    Ok(levels)
}

pub fn select_peak_stage(stages: &[ThroughputStageResult]) -> Option<&ThroughputStageResult> {
    stages
        .iter()
        .filter(|stage| stage.sustainable)
        .max_by(|a, b| {
            a.throughput
                .aggregate_mbps
                .total_cmp(&b.throughput.aggregate_mbps)
        })
}

pub fn calculate_directional_loss(
    upstream: DirectionalThroughput,
    current: DirectionalThroughput,
) -> DirectionalLoss {
    let (upload_mbps, upload_percent) = loss(upstream.upload_mbps, current.upload_mbps);
    let (download_mbps, download_percent) = loss(upstream.download_mbps, current.download_mbps);
    let (aggregate_mbps, aggregate_percent) = loss(upstream.aggregate_mbps, current.aggregate_mbps);
    DirectionalLoss {
        upload_mbps,
        upload_percent,
        download_mbps,
        download_percent,
        aggregate_mbps,
        aggregate_percent,
    }
}

fn loss(upstream: f64, current: f64) -> (f64, f64) {
    let absolute = upstream - current;
    let percent = if upstream > 0.0 {
        absolute / upstream * 100.0
    } else {
        0.0
    };
    (absolute, percent)
}

pub async fn run_max_throughput_tests(
    config: MaxThroughputConfig,
) -> Result<MaxThroughputTestResults> {
    validate_config(&config)?;
    let started = Instant::now();
    let levels = build_concurrency_levels(config.start_concurrency, config.max_concurrency)?;
    info!("=== 开始各接口最高吞吐与出口损失测试 ===");

    let mut interfaces = Vec::with_capacity(6);
    if selected(&config, ThroughputInterface::UpstreamTcp) {
        interfaces.push(
            run_tcp_sweep(
                ThroughputInterface::UpstreamTcp,
                TcpPerformanceMode::Direct,
                &config,
                &levels,
                None,
            )
            .await,
        );
    }
    if selected(&config, ThroughputInterface::UpstreamUdp) {
        interfaces.push(
            run_udp_sweep(
                ThroughputInterface::UpstreamUdp,
                UdpPerformanceMode::Direct,
                &config,
                &levels,
            )
            .await,
        );
    }

    if selected(&config, ThroughputInterface::Tun) {
        let tun_route = verify_tun_route(
            &config.tcp_target_host,
            config.tcp_target_port,
            config.tun_interface.as_deref(),
        )
        .await;
        interfaces.push(match tun_route {
            Ok(route) => {
                run_tcp_sweep(
                    ThroughputInterface::Tun,
                    TcpPerformanceMode::Tun,
                    &config,
                    &levels,
                    Some(route),
                )
                .await
            }
            Err(error) => failed_interface(ThroughputInterface::Tun, error.to_string()),
        });
    }
    if selected(&config, ThroughputInterface::HttpProxy) {
        interfaces.push(
            run_tcp_sweep(
                ThroughputInterface::HttpProxy,
                TcpPerformanceMode::HttpConnect,
                &config,
                &levels,
                None,
            )
            .await,
        );
    }
    if selected(&config, ThroughputInterface::SocksProxy) {
        interfaces.push(
            run_tcp_sweep(
                ThroughputInterface::SocksProxy,
                TcpPerformanceMode::Socks5,
                &config,
                &levels,
                None,
            )
            .await,
        );
    }
    if selected(&config, ThroughputInterface::UdpRelay) {
        interfaces.push(
            run_udp_sweep(
                ThroughputInterface::UdpRelay,
                UdpPerformanceMode::Socks5Relay,
                &config,
                &levels,
            )
            .await,
        );
    }
    apply_upstream_losses(&mut interfaces);

    Ok(MaxThroughputTestResults {
        test_duration_secs: started.elapsed().as_secs(),
        agent_addr: config.agent_addr,
        tcp_target: format!("{}:{}", config.tcp_target_host, config.tcp_target_port),
        udp_target: format!("{}:{}", config.udp_target_host, config.udp_target_port),
        tcp_payload_size: config.tcp_payload_size,
        udp_payload_size: config.udp_payload_size,
        stage_duration_secs: config.stage_duration_secs,
        max_failure_rate_percent: config.max_failure_rate_percent,
        tested_concurrency_levels: levels,
        interfaces,
    })
}

fn selected(config: &MaxThroughputConfig, interface: ThroughputInterface) -> bool {
    config.selected_interfaces.is_empty() || config.selected_interfaces.contains(&interface)
}

fn validate_config(config: &MaxThroughputConfig) -> Result<()> {
    anyhow::ensure!(
        config.stage_duration_secs > 0,
        "stage duration must be positive"
    );
    anyhow::ensure!(
        config.max_failure_rate_percent.is_finite()
            && (0.0..=100.0).contains(&config.max_failure_rate_percent),
        "max failure rate must be between 0 and 100"
    );
    Ok(())
}

pub(super) fn failed_interface(
    interface: ThroughputInterface,
    error: String,
) -> InterfaceThroughputResult {
    warn!("{} 未完成：{}", interface.name_zh(), error);
    InterfaceThroughputResult {
        interface,
        interface_name: interface.name_zh().to_string(),
        status: InterfaceTestStatus::Failed,
        error: Some(error),
        route_interface: None,
        best_concurrency: None,
        peak_confirmed: false,
        peak: DirectionalThroughput::default(),
        upstream_interface: interface.upstream(),
        loss_from_upstream: None,
        same_concurrency_comparison: None,
        stages: Vec::new(),
    }
}

pub(crate) fn apply_upstream_losses(results: &mut [InterfaceThroughputResult]) {
    let tcp = completed_interface(results, ThroughputInterface::UpstreamTcp).cloned();
    let udp = completed_interface(results, ThroughputInterface::UpstreamUdp).cloned();
    for result in results {
        result.loss_from_upstream = None;
        result.same_concurrency_comparison = None;
        for stage in &mut result.stages {
            stage.upstream_throughput = None;
            stage.loss_from_upstream = None;
        }
        let upstream = match result.upstream_interface {
            Some(ThroughputInterface::UpstreamTcp) => tcp.as_ref(),
            Some(ThroughputInterface::UpstreamUdp) => udp.as_ref(),
            _ => None,
        };
        if result.status == InterfaceTestStatus::Completed
            && let Some(upstream) = upstream
        {
            result.loss_from_upstream =
                Some(calculate_directional_loss(upstream.peak, result.peak));
            result.same_concurrency_comparison = result.best_concurrency.and_then(|concurrency| {
                upstream
                    .stages
                    .iter()
                    .find(|stage| stage.concurrency == concurrency)
                    .map(|stage| SameConcurrencyComparison {
                        concurrency,
                        upstream: stage.throughput,
                        current: result.peak,
                        loss: calculate_directional_loss(stage.throughput, result.peak),
                    })
            });
            for stage in &mut result.stages {
                stage.upstream_throughput = upstream
                    .stages
                    .iter()
                    .find(|candidate| candidate.concurrency == stage.concurrency)
                    .map(|candidate| candidate.throughput);
                stage.loss_from_upstream = stage
                    .upstream_throughput
                    .map(|throughput| calculate_directional_loss(throughput, stage.throughput));
            }
        }
    }
}

fn completed_interface(
    results: &[InterfaceThroughputResult],
    interface: ThroughputInterface,
) -> Option<&InterfaceThroughputResult> {
    results
        .iter()
        .find(|result| result.interface == interface)
        .filter(|result| result.status == InterfaceTestStatus::Completed)
}
