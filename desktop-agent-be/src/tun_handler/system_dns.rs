use crate::telemetry::{self, DnsResolutionRecord};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

/// 通过 Agent 本机系统解析器解析域名，并向遥测上报一条 `resolver = "system"` 的记录，
/// 便于 UI 标识哪些请求绕过了 Agent 内部 DNS。
pub(super) async fn resolve_via_system(
    transport: &str,
    client: SocketAddr,
    domain: &str,
    port: u16,
    prefer_ip_family: IpAddr,
) -> io::Result<SocketAddr> {
    let started_at = Instant::now();
    let record_type = if prefer_ip_family.is_ipv4() {
        "A"
    } else {
        "AAAA"
    };

    let lookup = tokio::net::lookup_host((domain, port)).await;
    let duration_ms = started_at.elapsed().as_millis();

    match lookup {
        Ok(iter) => {
            let prefer_v4 = prefer_ip_family.is_ipv4();
            let addrs: Vec<SocketAddr> = iter.collect();
            let answers: Vec<String> = addrs.iter().map(|addr| addr.ip().to_string()).collect();
            let status = if addrs.is_empty() {
                "NXDOMAIN"
            } else {
                "NOERROR"
            }
            .to_string();

            telemetry::emit_dns_resolution(DnsResolutionRecord {
                timestamp_ms: telemetry::current_time_millis(),
                resolver: "system".to_string(),
                client: format!("TUN {transport} {client}"),
                upstream: "system".to_string(),
                query: domain.to_string(),
                record_type: record_type.to_string(),
                status,
                answers,
                duration_ms,
            });

            let mut first = None;
            for addr in addrs {
                if first.is_none() {
                    first = Some(addr);
                }
                if addr.is_ipv4() == prefer_v4 {
                    return Ok(addr);
                }
            }

            first.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    format!("域名 {domain} 无可用解析结果"),
                )
            })
        }
        Err(err) => {
            telemetry::emit_dns_resolution(DnsResolutionRecord {
                timestamp_ms: telemetry::current_time_millis(),
                resolver: "system".to_string(),
                client: format!("TUN {transport} {client}"),
                upstream: "system".to_string(),
                query: domain.to_string(),
                record_type: record_type.to_string(),
                status: format!("ERROR: {err}"),
                answers: Vec::new(),
                duration_ms,
            });
            Err(err)
        }
    }
}
