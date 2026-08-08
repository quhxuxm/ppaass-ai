use super::*;

pub(crate) fn generate_max_throughput_html_report(
    results: &MaxThroughputTestResults,
    path: &str,
) -> Result<()> {
    let summary_rows = results
        .interfaces
        .iter()
        .map(summary_row)
        .collect::<String>();
    let detail_sections = results
        .interfaces
        .iter()
        .map(detail_section)
        .collect::<String>();
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PPAASS 各接口最高网速测试报告</title>
<style>
body{{margin:0;padding:24px;color:#202124;background:#f4f6f8;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}
main{{max-width:1280px;margin:auto;padding:28px;background:#fff;border:1px solid #dfe3e8;border-radius:8px}}
h1{{margin:0 0 8px;font-size:28px}}h2{{margin-top:30px;font-size:21px}}h3{{margin-top:26px;font-size:17px}}
.meta{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px 20px;padding:16px 0;color:#4f5b67}}
.table-wrap{{overflow-x:auto}}table{{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}}
th,td{{padding:10px 12px;border-bottom:1px solid #e4e8ed;text-align:right;white-space:nowrap}}
th{{background:#eef2f5;color:#34404c}}th:first-child,td:first-child{{text-align:left}}
.ok{{color:#137333;font-weight:600}}.bad{{color:#b3261e;font-weight:600}}
.error{{padding:12px;border-left:3px solid #b3261e;background:#fff5f4;color:#7d211b;overflow-wrap:anywhere}}
.route,.note{{color:#56616d;line-height:1.65}}.note{{margin-top:24px;padding-top:16px;border-top:1px solid #e4e8ed}}
@media(max-width:640px){{body{{padding:0}}main{{padding:18px;border:0;border-radius:0}}h1{{font-size:23px}}}}
</style>
</head>
<body><main>
<h1>PPAASS 各接口最高网速测试报告</h1>
<div class="meta">
<span><strong>Agent：</strong>{}</span><span><strong>TCP 目标：</strong>{}</span>
<span><strong>UDP 目标：</strong>{}</span><span><strong>并发级别：</strong>{:?}</span>
<span><strong>TCP payload：</strong>{} 字节</span><span><strong>UDP payload：</strong>{} 字节</span>
<span><strong>每级时长：</strong>{} 秒</span><span><strong>失败率上限：</strong>{:.3}%</span>
<span><strong>总测试时长：</strong>{} 秒</span>
</div>
<h2>接口峰值与出口损失</h2>
<div class="table-wrap"><table><thead><tr><th>接口</th><th>状态</th><th>上行峰值</th><th>下行峰值</th><th>合计峰值</th><th>上行损失</th><th>下行损失</th><th>合计损失</th><th>最佳并发</th><th>峰值确认</th></tr></thead><tbody>{}</tbody></table></div>
<h2>各接口并发明细</h2>{}
<p class="note"><strong>统计口径：</strong>上行按客户端发往目标的有效 payload 字节统计，下行按目标返回客户端的有效 payload 字节统计。TCP 模式与上一级 TCP 直连出口比较，UDP relay 与上一级 UDP 直连出口比较。损失为负数表示当前接口测得速度高于基线，通常属于调度或采样波动。</p>
</main></body></html>"#,
        escape_html(&results.agent_addr),
        escape_html(&results.tcp_target),
        escape_html(&results.udp_target),
        results.tested_concurrency_levels,
        results.tcp_payload_size,
        results.udp_payload_size,
        results.stage_duration_secs,
        results.max_failure_rate_percent,
        results.test_duration_secs,
        summary_rows,
        detail_sections,
    );
    let mut file = File::create(path)?;
    file.write_all(html.as_bytes())?;
    Ok(())
}

fn summary_row(result: &InterfaceThroughputResult) -> String {
    let (status, class) = match result.status {
        InterfaceTestStatus::Completed => ("完成", "ok"),
        InterfaceTestStatus::Failed => ("未完成", "bad"),
    };
    format!(
        "<tr><td>{}</td><td class=\"{}\">{}</td><td>{:.2} Mbps</td><td>{:.2} Mbps</td><td>{:.2} Mbps</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
        escape_html(&result.interface_name),
        class,
        status,
        result.peak.upload_mbps,
        result.peak.download_mbps,
        result.peak.aggregate_mbps,
        format_loss(result.loss_from_upstream, 0),
        format_loss(result.loss_from_upstream, 1),
        format_loss(result.loss_from_upstream, 2),
        result
            .best_concurrency
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".into()),
        if result.peak_confirmed { "是" } else { "否" },
    )
}

fn detail_section(result: &InterfaceThroughputResult) -> String {
    let route = result
        .route_interface
        .as_ref()
        .map(|value| {
            format!(
                "<p class=\"route\"><strong>实际路由网卡：</strong>{}</p>",
                escape_html(value)
            )
        })
        .unwrap_or_default();
    if let Some(error) = &result.error {
        return format!(
            "<section><h3>{}</h3>{}<p class=\"error\"><strong>未完成原因：</strong>{}</p></section>",
            escape_html(&result.interface_name),
            route,
            escape_html(error)
        );
    }
    let rows = result.stages.iter().map(|stage| format!(
        "<tr><td>{}</td><td>{:.2}</td><td>{:.2}</td><td>{:.2}</td><td>{:.3}%</td><td>{:.3} ms</td><td class=\"{}\">{}</td></tr>",
        stage.concurrency, stage.throughput.upload_mbps, stage.throughput.download_mbps,
        stage.throughput.aggregate_mbps, stage.failure_rate_percent, stage.p95_rtt_ms,
        if stage.sustainable { "ok" } else { "bad" }, if stage.sustainable { "是" } else { "否" }
    )).collect::<String>();
    format!(
        "<section><h3>{}</h3>{}<div class=\"table-wrap\"><table><thead><tr><th>并发</th><th>上行 Mbps</th><th>下行 Mbps</th><th>合计 Mbps</th><th>失败率</th><th>P95 RTT</th><th>可持续</th></tr></thead><tbody>{}</tbody></table></div></section>",
        escape_html(&result.interface_name),
        route,
        rows
    )
}

fn format_loss(loss: Option<DirectionalLoss>, direction: usize) -> String {
    let Some(loss) = loss else {
        return "-".to_string();
    };
    let (mbps, percent) = match direction {
        0 => (loss.upload_mbps, loss.upload_percent),
        1 => (loss.download_mbps, loss.download_percent),
        _ => (loss.aggregate_mbps, loss.aggregate_percent),
    };
    format!("{mbps:.2} Mbps ({percent:.2}%)")
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
