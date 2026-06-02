use super::state::DnsLease;
use super::*;
use common::BindInterface;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::process::Command;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
enum PreviousDns {
    Empty,
    Servers(Vec<String>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DnsRecord {
    service: String,
    previous: PreviousDns,
}

pub(crate) struct DnsGuard {
    service: String,
    previous: PreviousDns,
    lease: DnsLease<DnsRecord>,
}

impl DnsGuard {
    pub(crate) fn install(
        proxy_dns: bool,
        bind_interface: Option<&BindInterface>,
        _tun_interface_index: u32,
        tun_dns: Ipv4Addr,
        dns_state_file: Option<&str>,
    ) -> Option<Self> {
        let mut lease = DnsLease::new(dns_state_file);
        lease.cleanup_stale_records(restore_dns_record);

        if !proxy_dns {
            return None;
        }

        let interface = bind_interface.and_then(|interface| interface.name.as_deref());
        let Some(interface) = interface else {
            warn!("TUN proxy_dns 已启用，但未检测到物理出口接口；跳过系统 DNS 临时切换");
            return None;
        };

        let service = match service_for_device(interface) {
            Ok(Some(service)) => service,
            Ok(None) => {
                warn!("未找到设备 {interface} 对应的 macOS 网络服务；跳过系统 DNS 临时切换");
                return None;
            }
            Err(e) => {
                warn!("查询 macOS 网络服务失败：{e}");
                return None;
            }
        };

        let previous = match get_dns_servers(&service) {
            Ok(previous) => previous,
            Err(e) => {
                warn!("读取网络服务 {service} 的 DNS 配置失败：{e}");
                return None;
            }
        };
        let previous = normalize_previous_dns(previous, tun_dns);

        let record = DnsRecord {
            service: service.clone(),
            previous: previous.clone(),
        };
        lease.record_active(record.clone());

        if let Err(e) = set_dns_servers(&service, &[tun_dns.to_string()]) {
            warn!("设置网络服务 {service} 的 DNS 到 {tun_dns} 失败：{e}");
            if restore_dns_record(&record) {
                lease.remove_record(&record, same_dns_target);
            }
            return None;
        }
        flush_dns_cache();

        info!("TUN proxy_dns 已接管系统 DNS：服务={service} DNS={tun_dns}");
        Some(Self {
            service,
            previous,
            lease,
        })
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        let record = DnsRecord {
            service: self.service.clone(),
            previous: self.previous.clone(),
        };
        if restore_dns_record(&record) {
            self.lease.remove_record(&record, same_dns_target);
        } else {
            warn!(
                "保留 TUN DNS 状态文件以便下次启动重试：{}",
                self.lease.path.display()
            );
        }
    }
}

fn same_dns_target(left: &DnsRecord, right: &DnsRecord) -> bool {
    left.service == right.service
}

fn normalize_previous_dns(previous: PreviousDns, tun_dns: Ipv4Addr) -> PreviousDns {
    let tun_dns = tun_dns.to_string();
    match previous {
        PreviousDns::Servers(servers) if servers.len() == 1 && servers[0] == tun_dns => {
            warn!("检测到当前 macOS DNS 已经是 TUN DNS {tun_dns}，将按遗留状态处理并在退出时清空");
            PreviousDns::Empty
        }
        previous => previous,
    }
}

fn restore_dns_record(record: &DnsRecord) -> bool {
    let result = match &record.previous {
        PreviousDns::Empty => clear_dns_servers(&record.service),
        PreviousDns::Servers(servers) => set_dns_servers(&record.service, servers),
    };

    match result {
        Ok(()) => {
            flush_dns_cache();
            info!("已恢复网络服务 {} 的 DNS 配置", record.service);
            true
        }
        Err(e) => {
            warn!("恢复网络服务 {} 的 DNS 配置失败：{e}", record.service);
            false
        }
    }
}

fn service_for_device(device: &str) -> std::io::Result<Option<String>> {
    let output = run_networksetup(&["-listnetworkserviceorder"])?;
    let mut current_service = None;

    for line in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if let Some((_, service)) = line.split_once(") ") {
            current_service = Some(service.to_string());
            continue;
        }

        if line.contains(&format!("Device: {device})")) {
            return Ok(current_service);
        }
    }

    Ok(None)
}

fn get_dns_servers(service: &str) -> std::io::Result<PreviousDns> {
    let output = run_networksetup(&["-getdnsservers", service])?;
    let servers: Vec<String> = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();

    if servers.is_empty()
        || servers
            .first()
            .is_some_and(|line| line.starts_with("There aren't any DNS Servers set"))
    {
        return Ok(PreviousDns::Empty);
    }

    Ok(PreviousDns::Servers(servers))
}

fn set_dns_servers(service: &str, servers: &[String]) -> std::io::Result<()> {
    let mut args = Vec::with_capacity(2 + servers.len());
    args.push("-setdnsservers");
    args.push(service);
    args.extend(servers.iter().map(String::as_str));
    run_networksetup(&args).map(|_| ())
}

fn clear_dns_servers(service: &str) -> std::io::Result<()> {
    run_networksetup(&["-setdnsservers", service, "Empty"]).map(|_| ())
}

fn run_networksetup(args: &[&str]) -> std::io::Result<String> {
    debug!("运行 networksetup {:?}", args);
    let output = Command::new("networksetup").args(args).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let message = if stderr.is_empty() {
            format!("networksetup {:?} 退出状态 {}", args, output.status)
        } else {
            stderr
        };
        return Err(std::io::Error::other(message));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub(super) fn system_dns_servers() -> Vec<SystemDnsServer> {
    let mut servers = match Command::new("scutil").arg("--dns").output() {
        Ok(output) if output.status.success() => {
            parse_macos_dns_servers(&String::from_utf8_lossy(&output.stdout))
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if stderr.is_empty() {
                debug!("读取 macOS 系统 DNS 服务器失败：{}", output.status);
            } else {
                debug!("读取 macOS 系统 DNS 服务器失败：{stderr}");
            }
            Vec::new()
        }
        Err(e) => {
            debug!("运行 scutil --dns 失败：{e}");
            Vec::new()
        }
    };
    normalize_dns_servers(&mut servers);
    servers
}

pub(super) fn parse_macos_dns_servers(output: &str) -> Vec<SystemDnsServer> {
    let mut servers = Vec::new();
    let mut block_ips: Vec<IpAddr> = Vec::new();
    let mut block_if_name: Option<String> = None;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("resolver #") || trimmed.starts_with("DNS configuration") {
            flush_macos_dns_block(&mut servers, &mut block_ips, block_if_name.take());
            continue;
        }
        if let Some(ip) = parse_dns_server_ip_line(trimmed) {
            block_ips.push(ip);
            continue;
        }
        if let Some(if_name) = parse_scutil_if_name(trimmed) {
            block_if_name = Some(if_name);
        }
    }
    flush_macos_dns_block(&mut servers, &mut block_ips, block_if_name);

    if servers.is_empty() {
        parse_dns_server_ips(output)
            .into_iter()
            .map(|ip| SystemDnsServer {
                ip,
                interface_name: None,
            })
            .collect()
    } else {
        servers
    }
}

fn flush_macos_dns_block(
    servers: &mut Vec<SystemDnsServer>,
    block_ips: &mut Vec<IpAddr>,
    interface_name: Option<String>,
) {
    for ip in block_ips.drain(..) {
        servers.push(SystemDnsServer {
            ip,
            interface_name: interface_name.clone(),
        });
    }
}

fn parse_scutil_if_name(line: &str) -> Option<String> {
    let value = line.strip_prefix("if_index")?.split_once(':')?.1;
    let start = value.find('(')? + 1;
    let end = value[start..].find(')')? + start;
    let name = value[start..end].trim();
    (!name.is_empty()).then(|| name.to_string())
}

pub(super) fn flush_dns_cache() {
    for (program, args) in [
        ("dscacheutil", &["-flushcache"][..]),
        ("killall", &["-HUP", "mDNSResponder"][..]),
    ] {
        match Command::new(program).args(args).status() {
            Ok(status) if status.success() => {}
            Ok(status) => debug!("{program} {:?} 退出状态 {}", args, status),
            Err(e) => debug!("运行 {program} {:?} 失败：{e}", args),
        }
    }
}
