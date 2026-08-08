use super::*;
use crate::performance_tests::max_throughput::{
    InterfaceTestStatus, MaxThroughputTestResults, apply_upstream_losses, select_peak_stage,
};

pub fn merge_max_throughput_results(
    base: &mut MaxThroughputTestResults,
    continuation: MaxThroughputTestResults,
) -> Result<()> {
    anyhow::ensure!(
        base.agent_addr == continuation.agent_addr,
        "不能合并 Agent 地址不同的报告"
    );
    anyhow::ensure!(
        base.tcp_target == continuation.tcp_target && base.udp_target == continuation.udp_target,
        "不能合并目标地址不同的报告"
    );
    anyhow::ensure!(
        base.tcp_payload_size == continuation.tcp_payload_size
            && base.udp_payload_size == continuation.udp_payload_size,
        "不能合并 payload 大小不同的报告"
    );
    anyhow::ensure!(
        (base.max_failure_rate_percent - continuation.max_failure_rate_percent).abs()
            < f64::EPSILON,
        "不能合并失败率门槛不同的报告"
    );

    base.test_duration_secs = base
        .test_duration_secs
        .saturating_add(continuation.test_duration_secs);
    base.tested_concurrency_levels
        .extend(continuation.tested_concurrency_levels);
    base.tested_concurrency_levels.sort_unstable();
    base.tested_concurrency_levels.dedup();

    for addition in continuation.interfaces {
        let Some(current) = base
            .interfaces
            .iter_mut()
            .find(|result| result.interface == addition.interface)
        else {
            base.interfaces.push(addition);
            continue;
        };
        if addition.stages.is_empty() {
            continue;
        }
        for stage in addition.stages {
            if let Some(existing) = current
                .stages
                .iter_mut()
                .find(|existing| existing.concurrency == stage.concurrency)
            {
                *existing = stage;
            } else {
                current.stages.push(stage);
            }
        }
        current.stages.sort_by_key(|stage| stage.concurrency);
        let peak =
            select_peak_stage(&current.stages).map(|stage| (stage.concurrency, stage.throughput));
        if let Some((concurrency, throughput)) = peak {
            current.status = InterfaceTestStatus::Completed;
            current.error = None;
            current.best_concurrency = Some(concurrency);
            current.peak = throughput;
            current.peak_confirmed = current
                .stages
                .iter()
                .filter(|stage| stage.concurrency > concurrency)
                .count()
                >= 2;
        }
        if current.route_interface.is_none() {
            current.route_interface = addition.route_interface;
        }
    }

    for result in &mut base.interfaces {
        result.loss_from_upstream = None;
    }
    apply_upstream_losses(&mut base.interfaces);
    Ok(())
}
