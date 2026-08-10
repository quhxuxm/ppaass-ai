use super::*;
use std::process::Command;
use tracing::debug;

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

pub fn parse_macos_dns_servers(output: &str) -> Vec<SystemDnsServer> {
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
