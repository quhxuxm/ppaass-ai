#[cfg(not(any(target_os = "macos", windows)))]
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use tracing::warn;

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
mod windows;

/// 旧版本可能留下系统 DNS 修改记录，但新版本严格禁止自动写系统 DNS。
/// 保留状态文件并提示人工核对，避免盲目覆盖用户在异常退出后的手工改动。
pub(super) fn warn_legacy_dns_state(dns_state_file: Option<&str>) {
    let path = dns_state_file_path(dns_state_file);
    if path.is_file() {
        warn!(
            "检测到旧版本 DNS 状态文件 {}；为遵守不修改系统 DNS 的约束，Agent 不会自动应用其中的配置，请人工核对系统 DNS 后删除该文件",
            path.display()
        );
    }
}

fn dns_state_file_path(configured_file: Option<&str>) -> PathBuf {
    if let Some(path) = std::env::var_os("PPAASS_TUN_DNS_STATE") {
        return PathBuf::from(path);
    }

    let configured_file = configured_file
        .map(str::trim)
        .filter(|file| !file.is_empty())
        .unwrap_or("tun-dns.json");
    let path = PathBuf::from(configured_file);
    if path.is_absolute() {
        return path;
    }

    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(path)
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SystemDnsServer {
    pub ip: IpAddr,
    pub interface_name: Option<String>,
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

pub fn parse_dns_server_ips(output: &str) -> Vec<IpAddr> {
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
