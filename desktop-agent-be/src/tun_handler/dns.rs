#[cfg(not(any(target_os = "macos", windows)))]
use common::BindInterface;
#[cfg(not(any(target_os = "macos", windows)))]
use std::fs;
use std::net::IpAddr;
#[cfg(not(any(target_os = "macos", windows)))]
use std::net::Ipv4Addr;
#[cfg(not(any(target_os = "macos", windows)))]
use tracing::debug;

#[cfg(target_os = "macos")]
mod macos;
mod state;
#[cfg(test)]
mod tests;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "macos")]
pub(super) use macos::DnsGuard;
#[cfg(windows)]
pub(super) use windows::DnsGuard;

#[cfg(not(any(target_os = "macos", windows)))]
pub(super) struct DnsGuard;

#[cfg(not(any(target_os = "macos", windows)))]
impl DnsGuard {
    pub(super) fn install(
        proxy_dns: bool,
        _bind_interface: Option<&BindInterface>,
        _tun_interface_index: u32,
        _tun_dns: Ipv4Addr,
        _dns_state_file: Option<&str>,
    ) -> Option<Self> {
        if proxy_dns {
            debug!("当前平台未实现系统 DNS 临时切换；DNS 请求需由系统路由进入 TUN");
        }
        None
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct SystemDnsServer {
    pub(super) ip: IpAddr,
    pub(super) interface_name: Option<String>,
}

#[cfg(target_os = "macos")]
pub(super) fn system_dns_servers() -> Vec<SystemDnsServer> {
    macos::system_dns_servers()
}

#[cfg(windows)]
pub(super) fn system_dns_servers() -> Vec<SystemDnsServer> {
    let mut servers = windows::system_dns_server_ips()
        .into_iter()
        .map(|ip| SystemDnsServer {
            ip,
            interface_name: None,
        })
        .collect::<Vec<_>>();
    normalize_dns_servers(&mut servers);
    servers
}

#[cfg(all(not(target_os = "macos"), not(windows)))]
pub(super) fn system_dns_servers() -> Vec<SystemDnsServer> {
    let mut servers = fs::read_to_string("/etc/resolv.conf")
        .map(|content| {
            content
                .lines()
                .map(str::trim)
                .filter_map(|line| line.strip_prefix("nameserver"))
                .filter_map(|value| value.split_whitespace().next())
                .filter_map(|value| value.parse::<IpAddr>().ok())
                .map(|ip| SystemDnsServer {
                    ip,
                    interface_name: None,
                })
                .collect()
        })
        .unwrap_or_default();
    normalize_dns_servers(&mut servers);
    servers
}

fn normalize_dns_servers(servers: &mut Vec<SystemDnsServer>) {
    servers.retain(|server| {
        !server.ip.is_unspecified() && !server.ip.is_loopback() && !server.ip.is_multicast()
    });
    servers.sort_by(|left, right| {
        left.ip
            .cmp(&right.ip)
            .then_with(|| left.interface_name.cmp(&right.interface_name))
    });
    servers.dedup();
}

#[cfg(target_os = "macos")]
pub(super) fn flush_system_dns_cache() {
    macos::flush_dns_cache();
}

#[cfg(not(target_os = "macos"))]
pub(super) fn flush_system_dns_cache() {}

fn parse_dns_server_ips(output: &str) -> Vec<IpAddr> {
    output
        .lines()
        .filter_map(|line| parse_dns_server_ip_line(line.trim()))
        .collect()
}

fn parse_dns_server_ip_line(trimmed: &str) -> Option<IpAddr> {
    let value = if trimmed.starts_with("nameserver[") {
        trimmed
            .split_once(':')
            .map(|(_, value)| value.trim())
            .unwrap_or("")
    } else if let Some(value) = trimmed.strip_prefix("nameserver") {
        value.split_whitespace().next().unwrap_or("")
    } else {
        trimmed
    };
    let value = value.trim_matches(|ch: char| ch == '[' || ch == ']');
    value.parse::<IpAddr>().ok()
}
