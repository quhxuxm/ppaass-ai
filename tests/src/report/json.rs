use super::*;

pub(super) fn generate_json_report(results: &PerformanceTestResults, path: &str) -> Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

pub(super) fn generate_udp_json_report(
    results: &UdpPerformanceTestResults,
    path: &str,
) -> Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

pub(super) fn generate_tcp_json_report(
    results: &TcpPerformanceTestResults,
    path: &str,
) -> Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

pub(super) fn generate_max_throughput_json_report(
    results: &MaxThroughputTestResults,
    path: &str,
) -> Result<()> {
    let report = MaxThroughputJsonReport {
        measurement_definition: measurement_definition(),
        results,
    };
    let json = serde_json::to_string_pretty(&report)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

#[derive(serde::Serialize)]
struct MaxThroughputJsonReport<'a> {
    measurement_definition: MeasurementDefinition,
    #[serde(flatten)]
    results: &'a MaxThroughputTestResults,
}

#[derive(serde::Serialize)]
struct MeasurementDefinition {
    throughput_scope: &'static str,
    upload_definition: &'static str,
    download_definition: &'static str,
    excluded_overhead: [&'static str; 4],
    comparison_definition: &'static str,
    segment_limitation: &'static str,
    interfaces: [InterfaceDefinition; 6],
}

#[derive(serde::Serialize)]
struct InterfaceDefinition {
    id: &'static str,
    report_name: &'static str,
    path: &'static str,
    meaning: &'static str,
}

fn measurement_definition() -> MeasurementDefinition {
    MeasurementDefinition {
        throughput_scope: "在测试客户端侧统计的端到端有效 payload 吞吐，不是物理网卡线速",
        upload_definition: "测试客户端成功写入或发送的有效 payload 字节",
        download_definition: "测试客户端从回显目标成功收到的有效 payload 字节",
        excluded_overhead: ["TCP/IP 头", "SOCKS5 头", "加密开销", "Agent↔Proxy 协议头"],
        comparison_definition: "TCP 端到端模式与同并发 TCP 直连基线比较，UDP Relay 与同并发 UDP 直连基线比较",
        segment_limitation: "未分别测量客户端→Agent、Agent→Proxy、Proxy→目标的物理网卡速度；分段数据需要 Agent 和 Proxy 内的独立字节计数",
        interfaces: interface_definitions(),
    }
}

fn interface_definitions() -> [InterfaceDefinition; 6] {
    [
        InterfaceDefinition {
            id: "upstream_tcp",
            report_name: "TCP 直连基线",
            path: "测试客户端 → TCP 目标",
            meaning: "绕过 Agent 和 Proxy 的 TCP 基线，不是 Proxy 出口速度",
        },
        InterfaceDefinition {
            id: "upstream_udp",
            report_name: "UDP 直连基线",
            path: "测试客户端 → UDP 目标",
            meaning: "绕过 Agent 和 Proxy 的 UDP 基线，不是 Proxy 出口速度",
        },
        InterfaceDefinition {
            id: "tun",
            report_name: "TUN 端到端",
            path: "客户端 → Agent TUN → Proxy → TCP 目标",
            meaning: "由 TUN 进入 Agent 后经过 Proxy 的整条路径有效速度",
        },
        InterfaceDefinition {
            id: "http_proxy",
            report_name: "HTTP CONNECT 端到端",
            path: "客户端 → Agent HTTP CONNECT → Proxy → TCP 目标",
            meaning: "由 HTTP 接口进入 Agent，但结果是整条路径速度",
        },
        InterfaceDefinition {
            id: "socks_proxy",
            report_name: "SOCKS5 TCP 端到端",
            path: "客户端 → Agent SOCKS5 → Proxy → TCP 目标",
            meaning: "由 SOCKS5 接口进入 Agent，但不是单独的 Agent 入口速度",
        },
        InterfaceDefinition {
            id: "udp_relay",
            report_name: "SOCKS5 UDP Relay 端到端",
            path: "客户端 → Agent SOCKS5 UDP Relay → Proxy UDP → UDP 目标",
            meaning: "完整 UDP Relay 路径的端到端有效速度",
        },
    ]
}

pub(super) fn generate_quic_json_report(results: &QuicProbeTestResults, path: &str) -> Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

pub(super) fn generate_large_download_json_report(
    results: &LargeDownloadTestResults,
    path: &str,
) -> Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}
