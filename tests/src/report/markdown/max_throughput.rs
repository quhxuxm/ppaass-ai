use super::*;

pub(crate) fn generate_max_throughput_markdown_report(
    results: &MaxThroughputTestResults,
    path: &str,
) -> Result<()> {
    let mut content = format!(
        "# PPAASS 各接口最高网速测试报告\n\n\
         ## 测试配置\n\n\
         - **Agent 地址：** {}\n\
         - **TCP 目标：** {}\n\
         - **UDP 目标：** {}\n\
         - **TCP payload：** {} 字节\n\
         - **UDP payload：** {} 字节\n\
         - **并发级别：** {:?}\n\
         - **每级时长：** {} 秒\n\
         - **可持续失败率上限：** {:.3}%\n\
         - **总测试时长：** {} 秒\n\n",
        results.agent_addr,
        results.tcp_target,
        results.udp_target,
        results.tcp_payload_size,
        results.udp_payload_size,
        results.tested_concurrency_levels,
        results.stage_duration_secs,
        results.max_failure_rate_percent,
        results.test_duration_secs,
    );

    content.push_str(
        "## 如何阅读\n\n\
         - `独立峰值` 表示每个接口在自己最佳并发下的最高可持续速度，用于看各接口的上限。\n\
         - `同并发对照` 把当前端到端模式与直连基线放在相同并发下比较，用于判断真实速度变化。\n\
         - `保留率` 是当前速度除以同并发直连基线速度，越接近 100% 越好。\n\n",
    );

    content.push_str(
        "## 测试对象与统计边界\n\n\
         | 报告项目 | 实际数据路径 | 数值含义 |\n\
         |:--|:--|:--|\n\
         | TCP 直连基线 | 测试客户端 → TCP 目标 | 绕过 Agent 和 Proxy 的 TCP 基线，不是 Proxy → 目标的出口速度 |\n\
         | UDP 直连基线 | 测试客户端 → UDP 目标 | 绕过 Agent 和 Proxy 的 UDP 基线，不是 Proxy → 目标的出口速度 |\n\
         | TUN 端到端 | 客户端 → Agent TUN → Proxy → TCP 目标 | 流量由 TUN 进入 Agent 后经过 Proxy 的整条路径有效速度 |\n\
         | HTTP CONNECT 端到端 | 客户端 → Agent HTTP CONNECT → Proxy → TCP 目标 | 流量从 HTTP 接口进入 Agent，但结果是整条路径的端到端有效速度 |\n\
         | SOCKS5 TCP 端到端 | 客户端 → Agent SOCKS5 → Proxy → TCP 目标 | 流量从 SOCKS5 接口进入 Agent，但结果不是单独的 Agent 入口速度 |\n\
         | SOCKS5 UDP Relay 端到端 | 客户端 → Agent SOCKS5 UDP Relay → Proxy UDP → UDP 目标 | 完整 UDP Relay 路径的端到端有效速度 |\n\n\
         ### 字节统计位置\n\n\
         - 上行在测试客户端侧统计，表示客户端成功写入或发送的有效 payload。\n\
         - 下行在测试客户端侧统计，表示客户端从回显目标成功收到的有效 payload。\n\
         - 吞吐数值不包含 TCP/IP、SOCKS5、加密和 Agent↔Proxy 协议头开销。\n\
         - 当前报告没有分别测量客户端→Agent、Agent→Proxy、Proxy→目标的物理网卡速度；如需分段数据，必须在 Agent 和 Proxy 内增加独立字节计数。\n\n",
    );

    content.push_str("## 各接口独立峰值\n\n");
    content.push_str("| 接口 | 状态 | 上行峰值 | 下行峰值 | 合计峰值 | 最佳并发 | 峰值确认 |\n");
    content.push_str("|:--|:--:|--:|--:|--:|--:|:--:|\n");
    for result in &results.interfaces {
        content.push_str(&format!(
            "| {} | {} | {:.2} Mbps | {:.2} Mbps | {:.2} Mbps | {} | {} |\n",
            result.interface_name,
            status_zh(result.status),
            result.peak.upload_mbps,
            result.peak.download_mbps,
            result.peak.aggregate_mbps,
            result
                .best_concurrency
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
            if result.peak_confirmed { "是" } else { "否" },
        ));
    }

    content.push_str("\n## 同并发接口速度变化总览\n\n");
    content.push_str(
        "| 当前模式 | 对照并发 | 方向 | 直连基线速度 | 端到端速度 | 速度变化 | 损失率 | 保留率 |\n\
         |:--|--:|:--:|--:|--:|--:|--:|--:|\n",
    );
    for result in &results.interfaces {
        if let Some(comparison) = result.same_concurrency_comparison {
            for direction in Direction::ALL {
                let loss = loss_values(comparison.loss, direction);
                content.push_str(&format!(
                    "| {} | {} | {} | {:.2} Mbps | {:.2} Mbps | {} | {:.2}% | {:.2}% |\n",
                    result.interface_name,
                    comparison.concurrency,
                    direction.name_zh(),
                    throughput_value(comparison.upstream, direction),
                    throughput_value(comparison.current, direction),
                    format_change(loss.0),
                    loss.1,
                    100.0 - loss.1,
                ));
            }
        }
    }

    content.push_str("\n## 各接口同并发明细\n");
    for result in &results.interfaces {
        content.push_str(&format!("\n### {}\n\n", result.interface_name));
        content.push_str(&format!("- **数据路径：** {}\n", path_zh(result.interface)));
        if let Some(route) = &result.route_interface {
            content.push_str(&format!("- **实际路由网卡：** {route}\n"));
        }
        if let Some(error) = &result.error {
            content.push_str(&format!("- **未完成原因：** {error}\n"));
            continue;
        }
        content.push('\n');
        content.push_str("| 并发 | 基线上行 | 当前上行 | 上行变化 | 基线下行 | 当前下行 | 下行变化 | 基线合计 | 当前合计 | 合计变化 | 失败率 | P95 RTT | 可持续 |\n");
        content.push_str("|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|:--:|\n");
        for stage in &result.stages {
            content.push_str(&format!(
                "| {} | {} | {:.2} | {} | {} | {:.2} | {} | {} | {:.2} | {} | {:.3}% | {:.3} ms | {} |\n",
                stage.concurrency,
                format_upstream(stage.upstream_throughput, Direction::Upload),
                stage.throughput.upload_mbps,
                format_loss(stage.loss_from_upstream, Direction::Upload),
                format_upstream(stage.upstream_throughput, Direction::Download),
                stage.throughput.download_mbps,
                format_loss(stage.loss_from_upstream, Direction::Download),
                format_upstream(stage.upstream_throughput, Direction::Aggregate),
                stage.throughput.aggregate_mbps,
                format_loss(stage.loss_from_upstream, Direction::Aggregate),
                stage.failure_rate_percent,
                stage.p95_rtt_ms,
                if stage.sustainable { "是" } else { "否" },
            ));
        }
    }

    content.push_str(
        "\n## 统计口径\n\n\
         上行按测试客户端成功发送的有效 payload 字节统计，下行按测试客户端成功收到的有效 payload 字节统计。\
         TCP 端到端模式相对 TCP 直连基线计算损失，UDP Relay 相对 UDP 直连基线计算损失。\
         并发明细中的损失使用相同并发档位的直连结果作为基线；峰值汇总使用各模式自己的最高可持续值。\
         损失为负数表示当前接口测得速度高于基线，通常属于调度或采样波动。\n",
    );

    let mut file = File::create(path)?;
    file.write_all(content.as_bytes())?;
    Ok(())
}

#[derive(Clone, Copy)]
enum Direction {
    Upload,
    Download,
    Aggregate,
}

impl Direction {
    const ALL: [Self; 3] = [Self::Upload, Self::Download, Self::Aggregate];

    fn name_zh(self) -> &'static str {
        match self {
            Self::Upload => "上行",
            Self::Download => "下行",
            Self::Aggregate => "合计",
        }
    }
}

fn status_zh(status: InterfaceTestStatus) -> &'static str {
    match status {
        InterfaceTestStatus::Completed => "完成",
        InterfaceTestStatus::Failed => "未完成",
    }
}

fn format_loss(loss: Option<DirectionalLoss>, direction: Direction) -> String {
    let Some(loss) = loss else {
        return "-".to_string();
    };
    let (mbps, percent) = loss_values(loss, direction);
    format!("{} ({percent:.2}%)", format_change(mbps))
}

fn loss_values(loss: DirectionalLoss, direction: Direction) -> (f64, f64) {
    match direction {
        Direction::Upload => (loss.upload_mbps, loss.upload_percent),
        Direction::Download => (loss.download_mbps, loss.download_percent),
        Direction::Aggregate => (loss.aggregate_mbps, loss.aggregate_percent),
    }
}

fn throughput_value(throughput: DirectionalThroughput, direction: Direction) -> f64 {
    match direction {
        Direction::Upload => throughput.upload_mbps,
        Direction::Download => throughput.download_mbps,
        Direction::Aggregate => throughput.aggregate_mbps,
    }
}

fn format_upstream(throughput: Option<DirectionalThroughput>, direction: Direction) -> String {
    throughput
        .map(|value| format!("{:.2}", throughput_value(value, direction)))
        .unwrap_or_else(|| "-".to_string())
}

fn format_change(loss_mbps: f64) -> String {
    if loss_mbps >= 0.0 {
        format!("减少 {loss_mbps:.2} Mbps")
    } else {
        format!("增加 {:.2} Mbps", -loss_mbps)
    }
}

fn path_zh(interface: ThroughputInterface) -> &'static str {
    match interface {
        ThroughputInterface::UpstreamTcp => "客户端 → TCP 目标（直连基线）",
        ThroughputInterface::UpstreamUdp => "客户端 → UDP 目标（直连基线）",
        ThroughputInterface::Tun => "客户端 → Agent TUN → Proxy → TCP 目标",
        ThroughputInterface::HttpProxy => "客户端 → Agent HTTP CONNECT → Proxy → TCP 目标",
        ThroughputInterface::SocksProxy => "客户端 → Agent SOCKS5 → Proxy → TCP 目标",
        ThroughputInterface::UdpRelay => "客户端 → Agent SOCKS5 UDP Relay → Proxy UDP → UDP 目标",
    }
}
