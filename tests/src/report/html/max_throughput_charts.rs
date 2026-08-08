use super::*;

#[derive(Clone, Copy)]
enum Direction {
    Upload,
    Download,
    Aggregate,
}

#[derive(Clone, Copy)]
enum ChartValue {
    Throughput(Direction),
    Retention,
}

#[derive(Clone, Copy)]
struct Series {
    interface: ThroughputInterface,
    label: &'static str,
    color: &'static str,
}

const TCP: [Series; 4] = [
    Series {
        interface: ThroughputInterface::UpstreamTcp,
        label: "TCP 直连出口",
        color: "#1565c0",
    },
    Series {
        interface: ThroughputInterface::Tun,
        label: "TUN",
        color: "#b06000",
    },
    Series {
        interface: ThroughputInterface::HttpProxy,
        label: "HTTP CONNECT 端到端",
        color: "#188038",
    },
    Series {
        interface: ThroughputInterface::SocksProxy,
        label: "SOCKS5 TCP 端到端",
        color: "#d93025",
    },
];

const TCP_RETENTION: [Series; 3] = [TCP[1], TCP[2], TCP[3]];

const UDP: [Series; 2] = [
    Series {
        interface: ThroughputInterface::UpstreamUdp,
        label: "UDP 直连出口",
        color: "#1565c0",
    },
    Series {
        interface: ThroughputInterface::UdpRelay,
        label: "SOCKS5 UDP Relay 端到端",
        color: "#d93025",
    },
];

const UDP_RETENTION: [Series; 1] = [UDP[1]];

pub(super) fn generate_charts(results: &MaxThroughputTestResults) -> String {
    format!(
        "<section><h2>同并发速度变化曲线</h2>\
         <p class=\"explain\">每个点代表一个并发档位。吞吐曲线越高越好，保留率越接近 100% 越好。</p>\
         <h3>TCP 接口组</h3><div class=\"chart-grid\">{}{}{}{}</div>\
         <h3>UDP 接口组</h3><div class=\"chart-grid\">{}{}{}{}</div></section>",
        chart(
            results,
            "TCP 上行速度",
            &TCP,
            ChartValue::Throughput(Direction::Upload)
        ),
        chart(
            results,
            "TCP 下行速度",
            &TCP,
            ChartValue::Throughput(Direction::Download)
        ),
        chart(
            results,
            "TCP 上下行合计",
            &TCP,
            ChartValue::Throughput(Direction::Aggregate)
        ),
        chart(
            results,
            "TCP 合计速度保留率",
            &TCP_RETENTION,
            ChartValue::Retention
        ),
        chart(
            results,
            "UDP 上行速度",
            &UDP,
            ChartValue::Throughput(Direction::Upload)
        ),
        chart(
            results,
            "UDP 下行速度",
            &UDP,
            ChartValue::Throughput(Direction::Download)
        ),
        chart(
            results,
            "UDP 上下行合计",
            &UDP,
            ChartValue::Throughput(Direction::Aggregate)
        ),
        chart(
            results,
            "UDP 合计速度保留率",
            &UDP_RETENTION,
            ChartValue::Retention
        ),
    )
}

fn chart(
    results: &MaxThroughputTestResults,
    title: &str,
    candidates: &[Series],
    value_kind: ChartValue,
) -> String {
    let series = candidates
        .iter()
        .filter(|candidate| has_values(results, **candidate, value_kind))
        .copied()
        .collect::<Vec<_>>();
    let maximum = chart_maximum(results, &series, value_kind);
    let mut svg = grid(maximum, value_kind);
    for item in &series {
        svg.push_str(&series_path(results, *item, value_kind, maximum));
    }
    svg.push_str(&x_axis(results));
    let legend = series
        .iter()
        .map(|item| {
            format!(
                "<span><i style=\"background:{}\"></i>{}</span>",
                item.color, item.label
            )
        })
        .collect::<String>();
    format!(
        "<article class=\"chart\"><h4>{}</h4><svg viewBox=\"0 0 760 270\" role=\"img\" aria-label=\"{}\">{}</svg><div class=\"legend\">{}</div></article>",
        title, title, svg, legend
    )
}

fn has_values(results: &MaxThroughputTestResults, series: Series, value_kind: ChartValue) -> bool {
    interface_result(results, series.interface).is_some_and(|result| {
        result
            .stages
            .iter()
            .any(|stage| value(stage, value_kind).is_some())
    })
}

fn chart_maximum(
    results: &MaxThroughputTestResults,
    series: &[Series],
    value_kind: ChartValue,
) -> f64 {
    let measured = series
        .iter()
        .filter_map(|item| interface_result(results, item.interface))
        .flat_map(|result| result.stages.iter())
        .filter_map(|stage| value(stage, value_kind))
        .fold(0.0_f64, f64::max);
    match value_kind {
        ChartValue::Retention => measured.max(100.0),
        ChartValue::Throughput(_) => (measured * 1.08).max(1.0),
    }
}

fn grid(maximum: f64, value_kind: ChartValue) -> String {
    let mut output = String::new();
    for step in 0..=4 {
        let ratio = f64::from(step) / 4.0;
        let y = 220.0 - ratio * 190.0;
        let label = axis_label(maximum * ratio, value_kind);
        output.push_str(&format!(
            "<line x1=\"64\" y1=\"{y:.1}\" x2=\"738\" y2=\"{y:.1}\" class=\"grid-line\"/><text x=\"56\" y=\"{:.1}\" class=\"axis y\">{label}</text>",
            y + 4.0
        ));
    }
    output
}

fn series_path(
    results: &MaxThroughputTestResults,
    series: Series,
    value_kind: ChartValue,
    maximum: f64,
) -> String {
    let Some(result) = interface_result(results, series.interface) else {
        return String::new();
    };
    let points = results
        .tested_concurrency_levels
        .iter()
        .enumerate()
        .filter_map(|(index, concurrency)| {
            let stage = result
                .stages
                .iter()
                .find(|stage| stage.concurrency == *concurrency)?;
            let measured = value(stage, value_kind)?;
            Some((
                x_position(index, results.tested_concurrency_levels.len()),
                measured,
            ))
        })
        .collect::<Vec<_>>();
    if points.is_empty() {
        return String::new();
    }
    let path = points
        .iter()
        .enumerate()
        .map(|(index, (x, measured))| {
            let command = if index == 0 { "M" } else { "L" };
            format!("{command}{x:.1},{:.1}", y_position(*measured, maximum))
        })
        .collect::<Vec<_>>()
        .join(" ");
    let dots = points
        .iter()
        .map(|(x, measured)| {
            let y = y_position(*measured, maximum);
            format!(
                "<circle cx=\"{x:.1}\" cy=\"{y:.1}\" r=\"4\" fill=\"{}\"><title>{}: {}</title></circle>",
                series.color,
                series.label,
                axis_label(*measured, value_kind)
            )
        })
        .collect::<String>();
    format!(
        "<path d=\"{path}\" fill=\"none\" stroke=\"{}\" stroke-width=\"2.5\"/>{dots}",
        series.color
    )
}

fn x_axis(results: &MaxThroughputTestResults) -> String {
    let labels = results
        .tested_concurrency_levels
        .iter()
        .enumerate()
        .map(|(index, concurrency)| {
            let x = x_position(index, results.tested_concurrency_levels.len());
            format!("<text x=\"{x:.1}\" y=\"242\" class=\"axis x\">{concurrency}</text>")
        })
        .collect::<String>();
    format!("{labels}<text x=\"401\" y=\"262\" class=\"axis x\">并发数</text>")
}

fn x_position(index: usize, count: usize) -> f64 {
    if count <= 1 {
        return 401.0;
    }
    64.0 + index as f64 * 674.0 / (count - 1) as f64
}

fn y_position(value: f64, maximum: f64) -> f64 {
    220.0 - value / maximum * 190.0
}

fn value(stage: &ThroughputStageResult, value_kind: ChartValue) -> Option<f64> {
    match value_kind {
        ChartValue::Throughput(Direction::Upload) => Some(stage.throughput.upload_mbps),
        ChartValue::Throughput(Direction::Download) => Some(stage.throughput.download_mbps),
        ChartValue::Throughput(Direction::Aggregate) => Some(stage.throughput.aggregate_mbps),
        ChartValue::Retention => stage
            .loss_from_upstream
            .map(|loss| 100.0 - loss.aggregate_percent),
    }
}

fn axis_label(value: f64, value_kind: ChartValue) -> String {
    match value_kind {
        ChartValue::Retention => format!("{value:.0}%"),
        ChartValue::Throughput(_) if value >= 1_000.0 => format!("{:.1}G", value / 1_000.0),
        ChartValue::Throughput(_) => format!("{value:.0}M"),
    }
}

fn interface_result(
    results: &MaxThroughputTestResults,
    interface: ThroughputInterface,
) -> Option<&InterfaceThroughputResult> {
    results
        .interfaces
        .iter()
        .find(|result| result.interface == interface && !result.stages.is_empty())
}
