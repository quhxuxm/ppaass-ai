use common::BindInterface;
use std::net::Ipv4Addr;

#[cfg(any(target_os = "macos", windows))]
use std::process::Command;

#[cfg(any(target_os = "macos", windows))]
use tracing::{debug, info, warn};

#[cfg(not(any(target_os = "macos", windows)))]
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

#[cfg(windows)]
#[derive(Debug, Clone)]
enum PreviousWindowsDns {
    Dhcp,
    Servers(Vec<String>),
}

#[cfg(windows)]
pub(super) struct DnsGuard {
    interface_index: u32,
    previous: PreviousWindowsDns,
}

#[cfg(not(any(target_os = "macos", windows)))]
pub(super) struct DnsGuard;

impl DnsGuard {
    #[cfg(target_os = "macos")]
    pub(super) fn install(
        proxy_dns: bool,
        bind_interface: Option<&BindInterface>,
        _tun_interface_index: u32,
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

    #[cfg(windows)]
    pub(super) fn install(
        proxy_dns: bool,
        _bind_interface: Option<&BindInterface>,
        tun_interface_index: u32,
        tun_dns: Ipv4Addr,
    ) -> Option<Self> {
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

        if let Err(e) = windows_set_dns_servers(interface_index, &[tun_dns.to_string()]) {
            warn!("设置 Windows 接口 {interface_index} DNS 到 {tun_dns} 失败：{e}");
            return None;
        }
        windows_flush_dns_cache();

        info!("TUN proxy_dns 已接管系统 DNS：接口={interface_index} DNS={tun_dns}");
        Some(Self {
            interface_index,
            previous,
        })
    }

    #[cfg(not(any(target_os = "macos", windows)))]
    pub(super) fn install(
        proxy_dns: bool,
        _bind_interface: Option<&BindInterface>,
        _tun_interface_index: u32,
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

#[cfg(windows)]
impl Drop for DnsGuard {
    fn drop(&mut self) {
        let result = match &self.previous {
            PreviousWindowsDns::Dhcp => windows_reset_dns_servers(self.interface_index),
            PreviousWindowsDns::Servers(servers) => {
                windows_set_dns_servers(self.interface_index, servers)
            }
        };

        match result {
            Ok(()) => {
                windows_flush_dns_cache();
                info!("已恢复 Windows 接口 {} 的 DNS 配置", self.interface_index);
            }
            Err(e) => warn!(
                "恢复 Windows 接口 {} 的 DNS 配置失败：{e}",
                self.interface_index
            ),
        }
    }
}

#[cfg(windows)]
fn windows_previous_dns(interface_index: u32) -> std::io::Result<PreviousWindowsDns> {
    if windows_interface_has_static_dns(interface_index)? {
        Ok(PreviousWindowsDns::Servers(windows_get_dns_servers(
            interface_index,
        )?))
    } else {
        Ok(PreviousWindowsDns::Dhcp)
    }
}

#[cfg(windows)]
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

#[cfg(windows)]
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

#[cfg(windows)]
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

#[cfg(windows)]
fn windows_reset_dns_servers(interface_index: u32) -> std::io::Result<()> {
    let script = r#"
$Index = [uint32]$args[0]
Set-DnsClientServerAddress -InterfaceIndex $Index -ResetServerAddresses -ErrorAction Stop
"#;
    run_powershell(script, &[&interface_index.to_string()]).map(|_| ())
}

#[cfg(windows)]
fn windows_flush_dns_cache() {
    if let Err(e) = run_powershell("Clear-DnsClientCache", &[]) {
        debug!("刷新 Windows DNS 缓存失败：{e}");
    }
}

#[cfg(windows)]
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
