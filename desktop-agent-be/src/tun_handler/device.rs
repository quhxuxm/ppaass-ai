use super::*;

#[cfg(test)]
mod tests;

pub(super) fn tun_ipv4_peer(
    ipv4: std::net::Ipv4Addr,
    ipv4_prefix: u8,
) -> Option<std::net::Ipv4Addr> {
    // Host stacks treat the TUN adapter address itself as local, so DNS queries sent
    // to that IP can be consumed by the host instead of entering the TUN device.
    // Pick another usable address in the same TUN subnet so packets reach netstack.
    if ipv4_prefix >= 31 {
        return None;
    }

    let mask = if ipv4_prefix == 0 {
        0
    } else {
        u32::MAX << (32 - ipv4_prefix)
    };
    let network = u32::from(ipv4) & mask;
    let broadcast = network | !mask;
    let local = u32::from(ipv4);

    let candidates = [
        network.saturating_add(1),
        network.saturating_add(2),
        network.saturating_add(3),
    ];
    for candidate in candidates {
        if candidate != network && candidate != broadcast && candidate != local {
            return Some(std::net::Ipv4Addr::from(candidate));
        }
    }

    None
}

#[cfg(target_os = "macos")]
pub(super) fn tun_ipv4_destination(
    ipv4: std::net::Ipv4Addr,
    ipv4_prefix: u8,
) -> Option<std::net::Ipv4Addr> {
    tun_ipv4_peer(ipv4, ipv4_prefix)
}

#[cfg(not(target_os = "macos"))]
pub(super) fn tun_ipv4_destination(
    _ipv4: std::net::Ipv4Addr,
    _ipv4_prefix: u8,
) -> Option<std::net::Ipv4Addr> {
    None
}

#[cfg(target_os = "macos")]
pub(super) fn tun_ipv4_interface_prefix(_configured_prefix: u8) -> u8 {
    // macOS utun is point-to-point. Keep the configured CIDR for routing policy
    // and virtual peer selection, but install the interface address as a host
    // route so packets are delivered through the utun control socket.
    32
}

#[cfg(not(target_os = "macos"))]
pub(super) fn tun_ipv4_interface_prefix(configured_prefix: u8) -> u8 {
    configured_prefix
}

pub(super) struct CreatedTunDevice {
    pub(super) device: tun_rs::AsyncDevice,
    pub(super) name: String,
    pub(super) if_index: u32,
    pub(super) system_guard: Option<TunSystemGuard>,
}

pub(super) enum TunSystemGuard {
    #[cfg(target_os = "macos")]
    #[allow(dead_code)]
    Helper(HelperTunLease),
}

pub(super) fn create_tun_device(
    config: &TunConfig,
    ipv4: std::net::Ipv4Addr,
    ipv4_prefix: u8,
    ipv6_config: Option<(std::net::Ipv6Addr, u8)>,
    _proxy_addrs: &[String],
    _proxy_bind_interface: Option<&common::BindInterface>,
) -> Result<CreatedTunDevice> {
    #[cfg(target_os = "macos")]
    if config.macos_helper_enabled {
        match start_tun_via_helper(config, _proxy_addrs, _proxy_bind_interface) {
            Ok(helper_device) => {
                info!(
                    "已通过 TUN helper 创建设备：name={} if_index={}",
                    helper_device.name, helper_device.if_index
                );
                return Ok(CreatedTunDevice {
                    device: helper_device.device,
                    name: helper_device.name,
                    if_index: helper_device.if_index,
                    system_guard: Some(TunSystemGuard::Helper(helper_device.lease)),
                });
            }
            Err(err) if config.macos_helper_fallback_to_privilege => {
                warn!("TUN helper 不可用，将回退到旧的整进程提权路径：{}", err);
            }
            Err(err) => return Err(err),
        }
    }

    create_tun_device_legacy(config, ipv4, ipv4_prefix, ipv6_config)
}

pub(super) fn create_tun_device_legacy(
    config: &TunConfig,
    ipv4: std::net::Ipv4Addr,
    ipv4_prefix: u8,
    ipv6_config: Option<(std::net::Ipv6Addr, u8)>,
) -> Result<CreatedTunDevice> {
    cleanup_stale_routes(config.route_state_file.as_deref());
    ensure_tun_privileges_or_relaunch()?;

    // DeviceBuilder 负责设置地址、MTU 和平台相关参数。
    let mut builder = DeviceBuilder::new()
        .name(&config.name)
        .mtu(config.mtu)
        .ipv4(
            ipv4,
            tun_ipv4_interface_prefix(ipv4_prefix),
            tun_ipv4_destination(ipv4, ipv4_prefix),
        );
    #[cfg(target_os = "macos")]
    {
        // We manage split-default and proxy bypass routes ourselves. tun-rs' macOS
        // associated route points the TUN subnet at the adapter address, which can
        // steal packets for the virtual peer/DNS address before they reach utun.
        builder = builder.associate_route(false);
    }
    if let Some((ipv6, ipv6_prefix)) = ipv6_config {
        builder = builder.ipv6(ipv6, ipv6_prefix);
    }

    let device = build_tun_device(builder, config)?;
    let name = device
        .name()
        .map_err(|e| AgentError::Connection(format!("读取 TUN 设备名失败：{e}")))?;
    let if_index = device
        .if_index()
        .map_err(|e| AgentError::Connection(format!("读取 TUN if_index 失败：{e}")))?;

    Ok(CreatedTunDevice {
        device,
        name,
        if_index,
        system_guard: None,
    })
}

#[cfg(windows)]
fn build_tun_device(builder: DeviceBuilder, config: &TunConfig) -> Result<tun_rs::AsyncDevice> {
    // Windows 必须显式找到 wintun.dll。
    let wintun_file = resolve_wintun_file(config)?;
    info!("使用 Windows TUN 运行库：{}", wintun_file.display());
    builder
        .wintun_file(wintun_file.to_string_lossy().into_owned())
        .build_async()
        .map_err(|e| windows_tun_create_error(e, &wintun_file))
}

#[cfg(not(windows))]
fn build_tun_device(builder: DeviceBuilder, _config: &TunConfig) -> Result<tun_rs::AsyncDevice> {
    // 非 Windows 平台由 tun-rs 直接创建系统 TUN 设备。
    builder
        .build_async()
        .map_err(|e| AgentError::Connection(format!("创建 TUN 设备失败：{e}")))
}

#[cfg(windows)]
fn resolve_wintun_file(config: &TunConfig) -> Result<PathBuf> {
    // 用户显式配置时只接受该路径，避免误用 PATH 中的其他 DLL。
    if let Some(path) = config
        .wintun_file
        .as_deref()
        .map(str::trim)
        .filter(|path| !path.is_empty())
    {
        let path = absolute_wintun_path(Path::new(path));
        if path.is_file() {
            return Ok(path);
        }
        return Err(missing_wintun_error(&[path], true));
    }

    // 未配置时按 desktop-agent.exe 目录、当前目录、PATH 顺序搜索。
    let candidates = default_wintun_candidates();
    if let Some(path) = candidates.iter().find(|path| path.is_file()) {
        return Ok(path.clone());
    }

    Err(missing_wintun_error(&candidates, false))
}

#[cfg(windows)]
fn absolute_wintun_path(path: &Path) -> PathBuf {
    // 相对路径按当前工作目录解析，便于配置文件本地部署。
    if path.is_absolute() {
        return path.to_path_buf();
    }

    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(path)
}

#[cfg(windows)]
fn default_wintun_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    // desktop-agent.exe 同目录优先，最符合随二进制打包的部署方式。
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        push_wintun_candidate(&mut candidates, dir.join("wintun.dll"));
    }

    if let Ok(cwd) = std::env::current_dir() {
        push_wintun_candidate(&mut candidates, cwd.join("wintun.dll"));
    }

    // 最后才遍历 PATH，避免意外加载其他软件携带的 wintun.dll。
    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            push_wintun_candidate(&mut candidates, dir.join("wintun.dll"));
        }
    }

    candidates
}

#[cfg(windows)]
fn push_wintun_candidate(candidates: &mut Vec<PathBuf>, path: PathBuf) {
    // 搜索路径可能重复，去重后错误信息更清楚。
    if !candidates.iter().any(|candidate| candidate == &path) {
        candidates.push(path);
    }
}

#[cfg(windows)]
fn missing_wintun_error(candidates: &[PathBuf], explicit: bool) -> AgentError {
    // 错误信息保留已检查路径和进程架构，方便用户定位 DLL 放置/架构问题。
    let checked = format_wintun_candidates(candidates);
    let reason = if explicit {
        "配置的 wintun_file 不存在"
    } else {
        "未找到 Windows TUN 运行库 wintun.dll"
    };

    AgentError::Connection(format!(
        "创建 TUN 设备失败：{reason}。TUN 模式需要与 desktop-agent.exe 同架构的 wintun.dll（当前进程架构：{}）。\
         请从 https://www.wintun.net/ 下载对应架构的 DLL，放到 desktop-agent.exe 同目录，或在 [tun] 中设置 wintun_file。\
         已检查：{}",
        windows_arch_label(),
        checked
    ))
}

#[cfg(windows)]
fn windows_tun_create_error(error: std::io::Error, wintun_file: &Path) -> AgentError {
    // os error 5 单独提示管理员权限和适配器占用，这是 Windows 下最常见失败。
    let hint = if error.raw_os_error() == Some(5) {
        "Windows 返回拒绝访问。请确认当前进程是 elevated 管理员令牌；如果已经提权，检查是否有同名 Wintun 适配器被其他进程占用，或安全策略拦截驱动安装/打开。"
    } else {
        "如果 DLL 存在但仍加载失败，请确认它与 desktop-agent.exe 架构一致，并以管理员身份运行。"
    };

    AgentError::Connection(format!(
        "创建 TUN 设备失败：{error}。已使用 wintun.dll：{}。\
         {hint}（当前进程架构：{}）",
        wintun_file.display(),
        windows_arch_label()
    ))
}

#[cfg(windows)]
fn format_wintun_candidates(candidates: &[PathBuf]) -> String {
    // PATH 可能很长，错误信息只展示前几个候选并汇总剩余数量。
    let mut checked: Vec<String> = candidates
        .iter()
        .take(8)
        .map(|path| path.display().to_string())
        .collect();

    if candidates.len() > checked.len() {
        checked.push(format!(
            "另有 {} 个 PATH 位置",
            candidates.len() - checked.len()
        ));
    }

    if checked.is_empty() {
        "<无可用搜索路径>".to_string()
    } else {
        checked.join("; ")
    }
}

#[cfg(windows)]
fn windows_arch_label() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x64/amd64",
        "x86" => "x86",
        "aarch64" => "ARM64",
        "arm" => "ARM",
        other => other,
    }
}
