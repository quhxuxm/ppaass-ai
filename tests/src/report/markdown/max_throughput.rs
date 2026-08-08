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

    content.push_str("## 接口峰值与出口损失\n\n");
    content.push_str(
        "| 接口 | 状态 | 上行峰值 | 下行峰值 | 合计峰值 | 上行损失 | 下行损失 | 合计损失 | 最佳并发 | 峰值确认 |\n",
    );
    content.push_str("|:--|:--:|--:|--:|--:|--:|--:|--:|--:|:--:|\n");
    for result in &results.interfaces {
        content.push_str(&format!(
            "| {} | {} | {:.2} Mbps | {:.2} Mbps | {:.2} Mbps | {} | {} | {} | {} | {} |\n",
            result.interface_name,
            status_zh(result.status),
            result.peak.upload_mbps,
            result.peak.download_mbps,
            result.peak.aggregate_mbps,
            format_loss(result.loss_from_upstream, Direction::Upload),
            format_loss(result.loss_from_upstream, Direction::Download),
            format_loss(result.loss_from_upstream, Direction::Aggregate),
            result
                .best_concurrency
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
            if result.peak_confirmed { "是" } else { "否" },
        ));
    }

    content.push_str("\n## 各接口并发明细\n");
    for result in &results.interfaces {
        content.push_str(&format!("\n### {}\n\n", result.interface_name));
        if let Some(route) = &result.route_interface {
            content.push_str(&format!("- **实际路由网卡：** {route}\n"));
        }
        if let Some(error) = &result.error {
            content.push_str(&format!("- **未完成原因：** {error}\n"));
            continue;
        }
        content
            .push_str("| 并发 | 上行 Mbps | 下行 Mbps | 合计 Mbps | 失败率 | P95 RTT | 可持续 |\n");
        content.push_str("|--:|--:|--:|--:|--:|--:|:--:|\n");
        for stage in &result.stages {
            content.push_str(&format!(
                "| {} | {:.2} | {:.2} | {:.2} | {:.3}% | {:.3} ms | {} |\n",
                stage.concurrency,
                stage.throughput.upload_mbps,
                stage.throughput.download_mbps,
                stage.throughput.aggregate_mbps,
                stage.failure_rate_percent,
                stage.p95_rtt_ms,
                if stage.sustainable { "是" } else { "否" },
            ));
        }
    }

    content.push_str(
        "\n## 统计口径\n\n\
         上行按客户端发往目标的有效 payload 字节统计，下行按目标返回客户端的有效 payload 字节统计。\
         TCP 模式相对上一级 TCP 直连出口计算损失，UDP relay 相对上一级 UDP 直连出口计算损失。\
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
    let (mbps, percent) = match direction {
        Direction::Upload => (loss.upload_mbps, loss.upload_percent),
        Direction::Download => (loss.download_mbps, loss.download_percent),
        Direction::Aggregate => (loss.aggregate_mbps, loss.aggregate_percent),
    };
    format!("{mbps:.2} Mbps ({percent:.2}%)")
}
