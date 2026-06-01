use common::BindInterface;
#[cfg(any(target_os = "macos", windows))]
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
#[cfg(any(target_os = "macos", windows))]
use std::path::{Path, PathBuf};

#[cfg(any(target_os = "macos", windows))]
use std::process::Command;
#[cfg(any(target_os = "macos", windows))]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(any(target_os = "macos", windows))]
use tracing::{debug, info, warn};

#[cfg(not(any(target_os = "macos", windows)))]
use tracing::debug;

#[cfg(any(target_os = "macos", windows))]
const DNS_STATE_VERSION: u8 = 1;
#[cfg(any(target_os = "macos", windows))]
const DNS_STATE_FILE_NAME: &str = "tun-dns.json";

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Serialize, Deserialize)]
enum PreviousDns {
    Empty,
    Servers(Vec<String>),
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DnsRecord {
    service: String,
    previous: PreviousDns,
}

#[cfg(target_os = "macos")]
pub(super) struct DnsGuard {
    service: String,
    previous: PreviousDns,
    lease: DnsLease,
}

#[cfg(windows)]
#[derive(Debug, Clone, Serialize, Deserialize)]
enum PreviousWindowsDns {
    Dhcp,
    Servers(Vec<String>),
}

#[cfg(windows)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DnsRecord {
    interface_index: u32,
    previous: PreviousWindowsDns,
}

#[cfg(windows)]
pub(super) struct DnsGuard {
    interface_index: u32,
    previous: PreviousWindowsDns,
    lease: DnsLease,
}

#[cfg(any(target_os = "macos", windows))]
#[derive(Debug, Serialize, Deserialize)]
struct DnsState {
    version: u8,
    pid: u32,
    created_unix_secs: u64,
    records: Vec<DnsRecord>,
}

#[cfg(any(target_os = "macos", windows))]
struct DnsLease {
    path: PathBuf,
    state: DnsState,
    persist_failed: bool,
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
        dns_state_file: Option<&str>,
    ) -> Option<Self> {
        let mut lease = DnsLease::new(dns_state_file);
        lease.cleanup_stale_records();

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
                lease.remove_record(&record);
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

    #[cfg(windows)]
    pub(super) fn install(
        proxy_dns: bool,
        _bind_interface: Option<&BindInterface>,
        tun_interface_index: u32,
        tun_dns: Ipv4Addr,
        dns_state_file: Option<&str>,
    ) -> Option<Self> {
        let mut lease = DnsLease::new(dns_state_file);
        lease.cleanup_stale_records();

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
                lease.remove_record(&record);
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

    #[cfg(not(any(target_os = "macos", windows)))]
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
    macos_system_dns_servers()
}

#[cfg(not(target_os = "macos"))]
pub(super) fn system_dns_servers() -> Vec<SystemDnsServer> {
    let mut servers = platform_system_dns_server_ips()
        .into_iter()
        .map(|ip| SystemDnsServer {
            ip,
            interface_name: None,
        })
        .collect::<Vec<_>>();
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
    flush_dns_cache();
}

#[cfg(not(target_os = "macos"))]
pub(super) fn flush_system_dns_cache() {}

#[cfg(target_os = "macos")]
impl Drop for DnsGuard {
    fn drop(&mut self) {
        let record = DnsRecord {
            service: self.service.clone(),
            previous: self.previous.clone(),
        };
        if restore_dns_record(&record) {
            self.lease.remove_record(&record);
        } else {
            warn!(
                "保留 TUN DNS 状态文件以便下次启动重试：{}",
                self.lease.path.display()
            );
        }
    }
}

#[cfg(windows)]
impl Drop for DnsGuard {
    fn drop(&mut self) {
        let record = DnsRecord {
            interface_index: self.interface_index,
            previous: self.previous.clone(),
        };
        if restore_dns_record(&record) {
            self.lease.remove_record(&record);
        } else {
            warn!(
                "保留 TUN DNS 状态文件以便下次启动重试：{}",
                self.lease.path.display()
            );
        }
    }
}

#[cfg(any(target_os = "macos", windows))]
impl DnsLease {
    fn new(dns_state_file: Option<&str>) -> Self {
        Self {
            path: dns_state_file_path(dns_state_file),
            state: DnsState {
                version: DNS_STATE_VERSION,
                pid: std::process::id(),
                created_unix_secs: now_unix_secs(),
                records: Vec::new(),
            },
            persist_failed: false,
        }
    }

    fn cleanup_stale_records(&mut self) {
        let state = match fs::read_to_string(&self.path) {
            Ok(content) => match serde_json::from_str::<DnsState>(&content) {
                Ok(state) => state,
                Err(e) => {
                    warn!(
                        "TUN DNS 状态文件 {} 解析失败，将移除该文件：{e}",
                        self.path.display()
                    );
                    remove_file_if_exists(&self.path);
                    return;
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                warn!("读取 TUN DNS 状态文件 {} 失败：{e}", self.path.display());
                return;
            }
        };

        if state.records.is_empty() {
            remove_file_if_exists(&self.path);
            return;
        }

        info!(
            "发现上次 TUN 模式遗留的 DNS 状态文件：{}，准备恢复 {} 条 DNS 配置",
            self.path.display(),
            state.records.len()
        );

        self.state.records.clear();
        for record in state.records {
            if !restore_dns_record(&record) {
                self.state.records.push(record);
            }
        }

        if self.state.records.is_empty() {
            remove_file_if_exists(&self.path);
            info!("上次遗留的 TUN DNS 配置已恢复完成");
        } else if let Err(e) = self.persist() {
            warn!("写回 TUN DNS 状态文件 {} 失败：{e}", self.path.display());
        }
    }

    fn record_active(&mut self, record: DnsRecord) {
        self.state
            .records
            .retain(|existing| !same_dns_target(existing, &record));
        self.state.records.push(record);
        if let Err(e) = self.persist() {
            self.persist_failed = true;
            warn!("写入 TUN DNS 状态文件 {} 失败：{e}", self.path.display());
        }
    }

    fn remove_record(&mut self, record: &DnsRecord) {
        self.state
            .records
            .retain(|existing| !same_dns_target(existing, record));
        if self.state.records.is_empty() {
            self.clear();
        } else if let Err(e) = self.persist() {
            warn!("更新 TUN DNS 状态文件 {} 失败：{e}", self.path.display());
        }
    }

    fn persist(&self) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_vec_pretty(&self.state).map_err(std::io::Error::other)?;
        let tmp_path = self
            .path
            .with_extension(format!("json.tmp.{}", std::process::id()));
        fs::write(&tmp_path, data)?;
        #[cfg(windows)]
        if self.path.exists() {
            fs::remove_file(&self.path)?;
        }
        fs::rename(tmp_path, &self.path)
    }

    fn clear(&mut self) {
        if self.persist_failed {
            debug!(
                "TUN DNS 状态文件此前写入失败，无需清理：{}",
                self.path.display()
            );
        }
        remove_file_if_exists(&self.path);
        self.state.records.clear();
    }
}

#[cfg(target_os = "macos")]
fn same_dns_target(left: &DnsRecord, right: &DnsRecord) -> bool {
    left.service == right.service
}

#[cfg(windows)]
fn same_dns_target(left: &DnsRecord, right: &DnsRecord) -> bool {
    left.interface_index == right.interface_index
}

#[cfg(target_os = "macos")]
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

#[cfg(windows)]
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

#[cfg(target_os = "macos")]
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

#[cfg(windows)]
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

#[cfg(any(target_os = "macos", windows))]
fn dns_state_file_path(configured_file: Option<&str>) -> PathBuf {
    if let Some(path) = std::env::var_os("PPAASS_TUN_DNS_STATE") {
        return PathBuf::from(path);
    }

    let configured_file = configured_file
        .map(str::trim)
        .filter(|file| !file.is_empty())
        .unwrap_or(DNS_STATE_FILE_NAME);
    let path = PathBuf::from(configured_file);
    if path.is_absolute() {
        return path;
    }

    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(path)
}

#[cfg(any(target_os = "macos", windows))]
fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(any(target_os = "macos", windows))]
fn remove_file_if_exists(path: &Path) {
    match fs::remove_file(path) {
        Ok(()) => debug!("已删除 TUN DNS 状态文件：{}", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!("删除 TUN DNS 状态文件 {} 失败：{e}", path.display()),
    }
}

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
fn platform_system_dns_server_ips() -> Vec<IpAddr> {
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
pub(super) fn macos_system_dns_servers() -> Vec<SystemDnsServer> {
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

#[cfg(target_os = "macos")]
fn parse_macos_dns_servers(output: &str) -> Vec<SystemDnsServer> {
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
fn parse_scutil_if_name(line: &str) -> Option<String> {
    let value = line.strip_prefix("if_index")?.split_once(':')?.1;
    let start = value.find('(')? + 1;
    let end = value[start..].find(')')? + start;
    let name = value[start..end].trim();
    (!name.is_empty()).then(|| name.to_string())
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

#[cfg(all(not(target_os = "macos"), not(windows)))]
fn platform_system_dns_server_ips() -> Vec<IpAddr> {
    fs::read_to_string("/etc/resolv.conf")
        .map(|content| {
            content
                .lines()
                .map(str::trim)
                .filter_map(|line| line.strip_prefix("nameserver"))
                .filter_map(|value| value.split_whitespace().next())
                .filter_map(|value| value.parse::<IpAddr>().ok())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scutil_and_resolv_dns_addresses() {
        let output = r#"
resolver #1
  nameserver[0] : 192.168.1.1
  nameserver[1] : 8.8.8.8
  if_index : 11 (en0)
resolver #2
nameserver 1.1.1.1
"#;

        assert_eq!(
            parse_dns_server_ips(output),
            vec![
                IpAddr::V4("192.168.1.1".parse().unwrap()),
                IpAddr::V4("8.8.8.8".parse().unwrap()),
                IpAddr::V4("1.1.1.1".parse().unwrap()),
            ]
        );
        #[cfg(target_os = "macos")]
        {
            assert_eq!(
                parse_macos_dns_servers(output),
                vec![
                    SystemDnsServer {
                        ip: IpAddr::V4("192.168.1.1".parse().unwrap()),
                        interface_name: Some("en0".to_string()),
                    },
                    SystemDnsServer {
                        ip: IpAddr::V4("8.8.8.8".parse().unwrap()),
                        interface_name: Some("en0".to_string()),
                    },
                    SystemDnsServer {
                        ip: IpAddr::V4("1.1.1.1".parse().unwrap()),
                        interface_name: None,
                    },
                ]
            );
        }
    }
}
