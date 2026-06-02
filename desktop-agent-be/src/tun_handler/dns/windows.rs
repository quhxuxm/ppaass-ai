use super::state::DnsLease;
use super::*;
use common::BindInterface;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::process::Command;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
enum PreviousWindowsDns {
    Dhcp,
    Servers(Vec<String>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DnsRecord {
    interface_index: u32,
    previous: PreviousWindowsDns,
}

pub(crate) struct DnsGuard {
    interface_index: u32,
    previous: PreviousWindowsDns,
    lease: DnsLease<DnsRecord>,
}

impl DnsGuard {
    pub(crate) fn install(
        proxy_dns: bool,
        _bind_interface: Option<&BindInterface>,
        tun_interface_index: u32,
        tun_dns: Ipv4Addr,
        dns_state_file: Option<&str>,
    ) -> Option<Self> {
        let mut lease = DnsLease::new(dns_state_file);
        lease.cleanup_stale_records(restore_dns_record);

        if !proxy_dns {
            return None;
        }

        let interface_index = tun_interface_index;
        if interface_index == 0 {
            warn!("TUN proxy_dns 已启用，但 TUN 接口 index 无效；跳过系统 DNS 临时切换");
            return None;
        }

        let previous = match windows_previous_dns(interface_index) {
            Ok(previous) => previous,
            Err(e) => {
                warn!("读取 Windows 接口 {interface_index} 的 DNS 配置失败：{e}");
                return None;
            }
        };
        let previous = normalize_previous_dns(previous, tun_dns);

        let record = DnsRecord {
            interface_index,
            previous: previous.clone(),
        };
        lease.record_active(record.clone());

        if let Err(e) = windows_set_dns_servers(interface_index, &[tun_dns.to_string()]) {
            warn!("设置 Windows 接口 {interface_index} DNS 到 {tun_dns} 失败：{e}");
            if restore_dns_record(&record) {
                lease.remove_record(&record, same_dns_target);
            }
            return None;
        }
        windows_flush_dns_cache();

        info!("TUN proxy_dns 已接管系统 DNS：接口={interface_index} DNS={tun_dns}");
        Some(Self {
            interface_index,
            previous,
            lease,
        })
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        let record = DnsRecord {
            interface_index: self.interface_index,
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
    left.interface_index == right.interface_index
}

fn normalize_previous_dns(previous: PreviousWindowsDns, tun_dns: Ipv4Addr) -> PreviousWindowsDns {
    let tun_dns = tun_dns.to_string();
    match previous {
        PreviousWindowsDns::Servers(servers) if servers.len() == 1 && servers[0] == tun_dns => {
            warn!(
                "检测到当前 Windows DNS 已经是 TUN DNS {tun_dns}，将按遗留状态处理并在退出时重置为 DHCP"
            );
            PreviousWindowsDns::Dhcp
        }
        previous => previous,
    }
}

fn restore_dns_record(record: &DnsRecord) -> bool {
    let result = match &record.previous {
        PreviousWindowsDns::Dhcp => windows_reset_dns_servers(record.interface_index),
        PreviousWindowsDns::Servers(servers) => {
            windows_set_dns_servers(record.interface_index, servers)
        }
    };

    match result {
        Ok(()) => {
            windows_flush_dns_cache();
            info!("已恢复 Windows 接口 {} 的 DNS 配置", record.interface_index);
            true
        }
        Err(e) => {
            warn!(
                "恢复 Windows 接口 {} 的 DNS 配置失败：{e}",
                record.interface_index
            );
            false
        }
    }
}

fn windows_previous_dns(interface_index: u32) -> std::io::Result<PreviousWindowsDns> {
    if windows_interface_has_static_dns(interface_index)? {
        Ok(PreviousWindowsDns::Servers(windows_get_dns_servers(
            interface_index,
        )?))
    } else {
        Ok(PreviousWindowsDns::Dhcp)
    }
}

pub(super) fn system_dns_server_ips() -> Vec<IpAddr> {
    let script = r#"
Get-DnsClientServerAddress |
  ForEach-Object { $_.ServerAddresses } |
  Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
"#;
    match run_powershell(script, &[]) {
        Ok(output) => parse_dns_server_ips(&output),
        Err(e) => {
            debug!("读取 Windows 系统 DNS 服务器失败：{e}");
            Vec::new()
        }
    }
}

fn windows_interface_has_static_dns(interface_index: u32) -> std::io::Result<bool> {
    let script = r#"
$Index = [uint32]$args[0]
$adapter = Get-NetAdapter -InterfaceIndex $Index -ErrorAction Stop
$guid = $adapter.InterfaceGuid.ToString("B").ToLowerInvariant()
$path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid"
$nameServer = (Get-ItemProperty -Path $path -Name NameServer -ErrorAction SilentlyContinue).NameServer
if ([string]::IsNullOrWhiteSpace($nameServer)) {
    "dhcp"
} else {
    "static"
}
"#;
    let output = run_powershell(script, &[&interface_index.to_string()])?;
    Ok(output.lines().any(|line| line.trim() == "static"))
}

fn windows_get_dns_servers(interface_index: u32) -> std::io::Result<Vec<String>> {
    let script = r#"
$Index = [uint32]$args[0]
$servers = (Get-DnsClientServerAddress -InterfaceIndex $Index -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses
foreach ($server in $servers) {
    $server
}
"#;
    let output = run_powershell(script, &[&interface_index.to_string()])?;
    Ok(output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

fn windows_set_dns_servers(interface_index: u32, servers: &[String]) -> std::io::Result<()> {
    if servers.is_empty() {
        return windows_reset_dns_servers(interface_index);
    }

    let script = r#"
$Index = [uint32]$args[0]
$Servers = @($args | Select-Object -Skip 1)
Set-DnsClientServerAddress -InterfaceIndex $Index -ServerAddresses $Servers -ErrorAction Stop
"#;
    let index = interface_index.to_string();
    let mut args = Vec::with_capacity(1 + servers.len());
    args.push(index.as_str());
    args.extend(servers.iter().map(String::as_str));
    run_powershell(script, &args).map(|_| ())
}

fn windows_reset_dns_servers(interface_index: u32) -> std::io::Result<()> {
    let script = r#"
$Index = [uint32]$args[0]
Set-DnsClientServerAddress -InterfaceIndex $Index -ResetServerAddresses -ErrorAction Stop
"#;
    run_powershell(script, &[&interface_index.to_string()]).map(|_| ())
}

fn windows_flush_dns_cache() {
    if let Err(e) = run_powershell("Clear-DnsClientCache", &[]) {
        debug!("刷新 Windows DNS 缓存失败：{e}");
    }
}

fn run_powershell(script: &str, args: &[&str]) -> std::io::Result<String> {
    debug!("运行 PowerShell DNS 脚本");
    let command = format!("& {{\n{script}\n}}");
    let output = Command::new("powershell.exe")
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-Command")
        .arg(command)
        .args(args)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let message = if stderr.is_empty() {
            format!("PowerShell DNS 脚本退出状态 {}", output.status)
        } else {
            stderr
        };
        return Err(std::io::Error::other(message));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
