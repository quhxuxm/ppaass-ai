use super::max_throughput_charts::generate_charts;
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
    let comparison_rows = results
        .interfaces
        .iter()
        .flat_map(comparison_rows)
        .collect::<String>();
    let charts = generate_charts(results);
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
.guide{{line-height:1.7;color:#46515c;padding-left:22px}}.explain{{color:#56616d;line-height:1.65}}
.scope{{padding:14px 16px;border-left:3px solid #1565c0;background:#f5f9ff;color:#3f4b57;line-height:1.7}}.scope p{{margin:4px 0}}
.table-wrap{{overflow-x:auto}}table{{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}}
th,td{{padding:10px 12px;border-bottom:1px solid #e4e8ed;text-align:right;white-space:nowrap}}
th{{background:#eef2f5;color:#34404c}}th:first-child,td:first-child{{text-align:left}}
.ok{{color:#137333;font-weight:600}}.warn{{color:#9a5b00;font-weight:600}}.bad{{color:#b3261e;font-weight:600}}
.error{{padding:12px;border-left:3px solid #b3261e;background:#fff5f4;color:#7d211b;overflow-wrap:anywhere}}
.route,.note{{color:#56616d;line-height:1.65}}.note{{margin-top:24px;padding-top:16px;border-top:1px solid #e4e8ed}}
.chart-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}}
.chart{{border:1px solid #dfe3e8;border-radius:6px;padding:14px;min-width:0}}.chart h4{{margin:0 0 6px;font-size:15px}}
.chart svg{{display:block;width:100%;height:auto}}.grid-line{{stroke:#e5e9ed;stroke-width:1}}
.axis{{fill:#66717c;font-size:11px}}.axis.y{{text-anchor:end}}.axis.x{{text-anchor:middle}}
.legend{{display:flex;gap:8px 16px;flex-wrap:wrap;color:#56616d;font-size:12px}}.legend span{{white-space:nowrap}}
.legend i{{display:inline-block;width:16px;height:3px;margin:0 6px 3px 0;vertical-align:middle}}
@media(max-width:640px){{body{{padding:0}}main{{padding:18px;border:0;border-radius:0}}h1{{font-size:23px}}}}
@media(max-width:860px){{.chart-grid{{grid-template-columns:1fr}}}}
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
<h2>如何阅读</h2><ul class="guide"><li><strong>独立峰值</strong>用于看每个模式的最高可持续速度。</li><li><strong>同并发对照</strong>在相同并发下比较直连基线和端到端模式，可以直接看到速度变化。</li><li><strong>保留率</strong>是端到端速度除以同并发直连基线速度，越接近 100% 越好。</li></ul>
<h2>测试对象与统计边界</h2>
<div class="table-wrap"><table><thead><tr><th>报告项目</th><th>实际数据路径</th><th>数值含义</th></tr></thead><tbody>
<tr><td>TCP 直连基线</td><td>测试客户端 → TCP 目标</td><td>绕过 Agent 和 Proxy 的 TCP 基线，不是 Proxy → 目标的出口速度</td></tr>
<tr><td>UDP 直连基线</td><td>测试客户端 → UDP 目标</td><td>绕过 Agent 和 Proxy 的 UDP 基线，不是 Proxy → 目标的出口速度</td></tr>
<tr><td>TUN 端到端</td><td>客户端 → Agent TUN → Proxy → TCP 目标</td><td>流量由 TUN 进入 Agent 后经过 Proxy 的整条路径有效速度</td></tr>
<tr><td>HTTP CONNECT 端到端</td><td>客户端 → Agent HTTP CONNECT → Proxy → TCP 目标</td><td>流量从 HTTP 接口进入 Agent，但结果是整条路径的端到端有效速度</td></tr>
<tr><td>SOCKS5 TCP 端到端</td><td>客户端 → Agent SOCKS5 → Proxy → TCP 目标</td><td>流量从 SOCKS5 接口进入 Agent，但结果不是单独的 Agent 入口速度</td></tr>
<tr><td>SOCKS5 UDP Relay 端到端</td><td>客户端 → Agent SOCKS5 UDP Relay → Proxy UDP → UDP 目标</td><td>完整 UDP Relay 路径的端到端有效速度</td></tr>
</tbody></table></div>
<h3>字节统计位置</h3><div class="scope"><p><strong>上行：</strong>在测试客户端侧统计成功写入或发送的有效 payload。</p><p><strong>下行：</strong>在测试客户端侧统计从回显目标成功收到的有效 payload。</p><p><strong>不计入：</strong>TCP/IP、SOCKS5、加密和 Agent↔Proxy 协议头开销。</p><p><strong>当前限制：</strong>报告没有分别测量客户端→Agent、Agent→Proxy、Proxy→目标的物理网卡速度；分段数据需要在 Agent 和 Proxy 内增加独立字节计数。</p></div>
<h2>各接口独立峰值</h2>
<div class="table-wrap"><table><thead><tr><th>接口</th><th>状态</th><th>上行峰值</th><th>下行峰值</th><th>合计峰值</th><th>最佳并发</th><th>峰值确认</th></tr></thead><tbody>{}</tbody></table></div>
<h2>同并发接口速度变化总览</h2>
<p class="explain">每个端到端模式取自身最佳并发，再与直连基线的相同并发档位对照。</p>
<div class="table-wrap"><table><thead><tr><th>当前模式</th><th>对照并发</th><th>方向</th><th>直连基线速度</th><th>端到端速度</th><th>速度变化</th><th>损失率</th><th>保留率</th></tr></thead><tbody>{}</tbody></table></div>
{}
<h2>各接口同并发明细</h2>{}
<p class="note"><strong>统计口径：</strong>上行按测试客户端成功发送的有效 payload 字节统计，下行按测试客户端成功收到的有效 payload 字节统计。TCP 端到端模式与 TCP 直连基线比较，UDP Relay 与 UDP 直连基线比较。并发明细使用相同并发档位的直连结果作为基线，峰值汇总使用各模式自己的最高可持续值。损失为负数表示端到端模式测得速度高于基线，通常属于调度或采样波动。</p>
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
        comparison_rows,
        charts,
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
        "<tr><td>{}</td><td class=\"{}\">{}</td><td>{:.2} Mbps</td><td>{:.2} Mbps</td><td>{:.2} Mbps</td><td>{}</td><td>{}</td></tr>",
        escape_html(&result.interface_name),
        class,
        status,
        result.peak.upload_mbps,
        result.peak.download_mbps,
        result.peak.aggregate_mbps,
        result
            .best_concurrency
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".into()),
        if result.peak_confirmed { "是" } else { "否" },
    )
}

fn detail_section(result: &InterfaceThroughputResult) -> String {
    let path = format!(
        "<p class=\"route\"><strong>数据路径：</strong>{}</p>",
        path_zh(result.interface)
    );
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
            "<section><h3>{}</h3>{}{}<p class=\"error\"><strong>未完成原因：</strong>{}</p></section>",
            escape_html(&result.interface_name),
            path,
            route,
            escape_html(error)
        );
    }
    let rows = result.stages.iter().map(|stage| format!(
        "<tr><td>{}</td><td>{}</td><td>{:.2}</td><td>{}</td><td>{}</td><td>{:.2}</td><td>{}</td><td>{}</td><td>{:.2}</td><td>{}</td><td>{:.3}%</td><td>{:.3} ms</td><td class=\"{}\">{}</td></tr>",
        stage.concurrency, format_upstream(stage.upstream_throughput, 0), stage.throughput.upload_mbps,
        format_loss(stage.loss_from_upstream, 0), format_upstream(stage.upstream_throughput, 1),
        stage.throughput.download_mbps, format_loss(stage.loss_from_upstream, 1),
        format_upstream(stage.upstream_throughput, 2), stage.throughput.aggregate_mbps,
        format_loss(stage.loss_from_upstream, 2), stage.failure_rate_percent, stage.p95_rtt_ms,
        if stage.sustainable { "ok" } else { "bad" }, if stage.sustainable { "是" } else { "否" }
    )).collect::<String>();
    format!(
        "<section><h3>{}</h3>{}{}<div class=\"table-wrap\"><table><thead><tr><th>并发</th><th>基线上行</th><th>当前上行</th><th>上行变化</th><th>基线下行</th><th>当前下行</th><th>下行变化</th><th>基线合计</th><th>当前合计</th><th>合计变化</th><th>失败率</th><th>P95 RTT</th><th>可持续</th></tr></thead><tbody>{}</tbody></table></div></section>",
        escape_html(&result.interface_name),
        path,
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
    if mbps >= 0.0 {
        format!("减少 {mbps:.2} Mbps ({percent:.2}%)")
    } else {
        format!("增加 {:.2} Mbps ({:.2}%)", -mbps, -percent)
    }
}

fn comparison_rows(result: &InterfaceThroughputResult) -> Vec<String> {
    let Some(comparison) = result.same_concurrency_comparison else {
        return Vec::new();
    };
    (0..3)
        .map(|direction| {
            let upstream = throughput_value(comparison.upstream, direction);
            let current = throughput_value(comparison.current, direction);
            let (mbps, percent) = loss_value(comparison.loss, direction);
            let retention = 100.0 - percent;
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{upstream:.2} Mbps</td><td>{current:.2} Mbps</td><td class=\"{}\">{}</td><td class=\"{}\">{percent:.2}%</td><td class=\"{}\">{retention:.2}%</td></tr>",
                escape_html(&result.interface_name), comparison.concurrency,
                ["上行", "下行", "合计"][direction],
                loss_class(percent), format_change(mbps), loss_class(percent),
                retention_class(retention),
            )
        })
        .collect()
}

fn throughput_value(throughput: DirectionalThroughput, direction: usize) -> f64 {
    [
        throughput.upload_mbps,
        throughput.download_mbps,
        throughput.aggregate_mbps,
    ][direction]
}

fn loss_value(loss: DirectionalLoss, direction: usize) -> (f64, f64) {
    [
        (loss.upload_mbps, loss.upload_percent),
        (loss.download_mbps, loss.download_percent),
        (loss.aggregate_mbps, loss.aggregate_percent),
    ][direction]
}

fn format_upstream(throughput: Option<DirectionalThroughput>, direction: usize) -> String {
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

fn loss_class(percent: f64) -> &'static str {
    if percent <= 20.0 {
        "ok"
    } else if percent <= 50.0 {
        "warn"
    } else {
        "bad"
    }
}

fn retention_class(percent: f64) -> &'static str {
    if percent >= 80.0 {
        "ok"
    } else if percent >= 50.0 {
        "warn"
    } else {
        "bad"
    }
}

fn path_zh(interface: ThroughputInterface) -> &'static str {
    match interface {
        ThroughputInterface::UpstreamTcp => "测试客户端 → TCP 目标（直连基线）",
        ThroughputInterface::UpstreamUdp => "测试客户端 → UDP 目标（直连基线）",
        ThroughputInterface::Tun => "客户端 → Agent TUN → Proxy → TCP 目标",
        ThroughputInterface::HttpProxy => "客户端 → Agent HTTP CONNECT → Proxy → TCP 目标",
        ThroughputInterface::SocksProxy => "客户端 → Agent SOCKS5 → Proxy → TCP 目标",
        ThroughputInterface::UdpRelay => "客户端 → Agent SOCKS5 UDP Relay → Proxy UDP → UDP 目标",
    }
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
