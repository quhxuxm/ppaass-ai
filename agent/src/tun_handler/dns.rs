use common::BindInterface;
use std::net::Ipv4Addr;

#[cfg(target_os = "macos")]
use std::process::Command;

#[cfg(target_os = "macos")]
use tracing::{debug, info, warn};

#[cfg(not(target_os = "macos"))]
use tracing::debug;

#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
enum PreviousDns {
    Empty,
    Servers(Vec<String>),
}

#[cfg(target_os = "macos")]
pub(super) struct DnsGuard {
    service: String,
    previous: PreviousDns,
}

#[cfg(not(target_os = "macos"))]
pub(super) struct DnsGuard;

impl DnsGuard {
    #[cfg(target_os = "macos")]
    pub(super) fn install(
        proxy_dns: bool,
        bind_interface: Option<&BindInterface>,
        tun_dns: Ipv4Addr,
    ) -> Option<Self> {
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

        if let Err(e) = set_dns_servers(&service, &[tun_dns.to_string()]) {
            warn!("设置网络服务 {service} 的 DNS 到 {tun_dns} 失败：{e}");
            return None;
        }
        flush_dns_cache();

        info!("TUN proxy_dns 已接管系统 DNS：服务={service} DNS={tun_dns}");
        Some(Self { service, previous })
    }

    #[cfg(not(target_os = "macos"))]
    pub(super) fn install(
        proxy_dns: bool,
        _bind_interface: Option<&BindInterface>,
        _tun_dns: Ipv4Addr,
    ) -> Option<Self> {
        if proxy_dns {
            debug!("当前平台未实现系统 DNS 临时切换；DNS 请求需由系统路由进入 TUN");
        }
        None
    }
}

#[cfg(target_os = "macos")]
impl Drop for DnsGuard {
    fn drop(&mut self) {
        let result = match &self.previous {
            PreviousDns::Empty => clear_dns_servers(&self.service),
            PreviousDns::Servers(servers) => set_dns_servers(&self.service, servers),
        };

        match result {
            Ok(()) => {
                flush_dns_cache();
                info!("已恢复网络服务 {} 的 DNS 配置", self.service);
            }
            Err(e) => {
                warn!("恢复网络服务 {} 的 DNS 配置失败：{e}", self.service);
            }
        }
    }
}

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
fn set_dns_servers(service: &str, servers: &[String]) -> std::io::Result<()> {
    let mut args = Vec::with_capacity(2 + servers.len());
    args.push("-setdnsservers");
    args.push(service);
    args.extend(servers.iter().map(String::as_str));
    run_networksetup(&args).map(|_| ())
}

#[cfg(target_os = "macos")]
fn clear_dns_servers(service: &str) -> std::io::Result<()> {
    run_networksetup(&["-setdnsservers", service, "Empty"]).map(|_| ())
}

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
fn flush_dns_cache() {
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
