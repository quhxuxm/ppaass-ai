use super::*;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use std::process::Stdio;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use std::thread;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use std::time::{Duration, Instant};

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
const ROUTE_CLEANUP_COMMAND_TIMEOUT: Duration = Duration::from_secs(3);
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
const ROUTE_CLEANUP_COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(50);

pub(super) fn delete_recorded_route(mgr: &mut RouteManager, record: &RouteRecord) -> bool {
    if !should_delete_recorded_route(record) {
        debug!(
            "保留 macOS scoped default bypass，不在 TUN 关闭时删除：destination={}/{} gateway={:?} if_name={:?}",
            record.destination, record.prefix, record.gateway, record.if_name
        );
        return true;
    }

    let route = record.to_route();
    if let Some(matches) = matching_routes(mgr, record)
        && matches.is_empty()
    {
        debug!("TUN 路由已不存在：{}", route);
        return true;
    }

    #[cfg(target_os = "macos")]
    if delete_route_with_platform_tool(record) && !recorded_route_exists(mgr, record) {
        return true;
    }

    match mgr.delete(&route) {
        Ok(()) => {
            if !recorded_route_exists(mgr, record) {
                debug!("已清理 TUN 路由：{}", route);
                return true;
            }
            debug!("删除 TUN 路由 {} 返回成功，但路由表中仍存在匹配条目", route);
        }
        Err(e) => {
            debug!(
                "按状态文件直接删除路由 {} 失败，将检查当前路由表：{e}",
                route
            );
        }
    }

    if delete_matching_routes(mgr, record) && !recorded_route_exists(mgr, record) {
        return true;
    }

    #[cfg(not(target_os = "macos"))]
    if delete_route_with_platform_tool(record) && !recorded_route_exists(mgr, record) {
        return true;
    }

    warn!("删除 TUN 路由失败，路由表中仍存在匹配条目：{}", route);
    false
}

pub(super) fn should_delete_recorded_route(record: &RouteRecord) -> bool {
    #[cfg(target_os = "macos")]
    if matches!(record.kind, RouteKind::MacosScopedDefaultBypass) {
        return false;
    }
    #[cfg(not(target_os = "macos"))]
    let _ = record;

    true
}

fn recorded_route_exists(mgr: &mut RouteManager, record: &RouteRecord) -> bool {
    match matching_routes(mgr, record) {
        Some(routes) => !routes.is_empty(),
        None => true,
    }
}

fn matching_routes(mgr: &mut RouteManager, record: &RouteRecord) -> Option<Vec<Route>> {
    match mgr.list() {
        Ok(routes) => Some(
            routes
                .into_iter()
                .filter(|candidate| record.matches_route(candidate))
                .collect(),
        ),
        Err(e) => {
            warn!("无法列出当前路由以确认 TUN 路由是否已删除：{e}");
            None
        }
    }
}

fn delete_matching_routes(mgr: &mut RouteManager, record: &RouteRecord) -> bool {
    let route = record.to_route();
    let matches = match matching_routes(mgr, record) {
        Some(matches) => matches,
        None => return false,
    };

    if matches.is_empty() {
        debug!("TUN 路由已不存在：{}", route);
        return true;
    }

    let mut deleted_all = true;
    for candidate in matches {
        match mgr.delete(&candidate) {
            Ok(()) => debug!("已按当前路由表条目清理 TUN 路由：{}", candidate),
            Err(e) => {
                deleted_all = false;
                warn!("删除当前路由表中的 TUN 路由 {} 失败：{e}", candidate);
            }
        }
    }
    deleted_all
}

pub(super) fn cleanup_existing_tun_split_routes(mgr: &mut RouteManager, tun_if_index: u32) {
    let routes = [
        split_route_record(
            RouteKind::Ipv4SplitDefault,
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            1,
            tun_if_index,
        ),
        split_route_record(
            RouteKind::Ipv4SplitDefault,
            IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)),
            1,
            tun_if_index,
        ),
        split_route_record(
            RouteKind::Ipv6SplitDefault,
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            1,
            tun_if_index,
        ),
        split_route_record(
            RouteKind::Ipv6SplitDefault,
            IpAddr::V6(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)),
            1,
            tun_if_index,
        ),
    ];

    for record in routes {
        let _ = delete_recorded_route(mgr, &record);
    }
}

fn split_route_record(
    kind: RouteKind,
    destination: IpAddr,
    prefix: u8,
    tun_if_index: u32,
) -> RouteRecord {
    let if_name = None;
    #[cfg(target_os = "macos")]
    let if_name = if_name.or_else(|| interface_name_for_index(Some(tun_if_index)));

    RouteRecord {
        kind,
        destination,
        prefix,
        gateway: None,
        if_name,
        if_index: Some(tun_if_index),
    }
}

#[cfg(target_os = "macos")]
fn delete_route_with_platform_tool(record: &RouteRecord) -> bool {
    let if_name = record
        .if_name
        .clone()
        .or_else(|| interface_name_for_index(record.if_index));

    if matches!(record.kind, RouteKind::DnsCapture) {
        if let Some(if_name) = if_name.as_deref()
            && record.gateway.is_some()
            && run_route_cleanup_command(macos_route_delete_command(record, Some(if_name), true))
        {
            return true;
        }
        if let Some(if_name) = if_name.as_deref()
            && run_route_cleanup_command(macos_route_delete_command(record, Some(if_name), false))
        {
            return true;
        }
    }

    if record.gateway.is_some()
        && run_route_cleanup_command(macos_route_delete_command(record, None, true))
    {
        return true;
    }
    if run_route_cleanup_command(macos_route_delete_command(record, None, false)) {
        return true;
    }
    if let Some(if_name) = if_name.as_deref()
        && record.gateway.is_some()
        && run_route_cleanup_command(macos_route_delete_command(record, Some(if_name), true))
    {
        return true;
    }
    if let Some(if_name) = if_name.as_deref()
        && run_route_cleanup_command(macos_route_delete_command(record, Some(if_name), false))
    {
        return true;
    }

    false
}

#[cfg(target_os = "macos")]
pub(super) fn macos_route_delete_command(
    record: &RouteRecord,
    if_scope: Option<&str>,
    include_gateway: bool,
) -> Command {
    let mut command = Command::new("route");
    command.arg("-n").arg("delete");
    if record.destination.is_ipv4() {
        command.arg("-inet");
    } else {
        command.arg("-inet6");
    }
    command.arg(if route_record_is_host(record) {
        "-host"
    } else {
        "-net"
    });
    if let Some(if_scope) = if_scope {
        command.arg("-ifscope").arg(if_scope);
    }
    append_macos_route_destination_args(&mut command, record);
    if include_gateway
        && let Some(gateway) = record.gateway
        && !is_unspecified_gateway(gateway, record.destination)
    {
        command.arg(gateway.to_string());
    }
    command
}

#[cfg(target_os = "linux")]
fn delete_route_with_platform_tool(record: &RouteRecord) -> bool {
    let mut command = Command::new("ip");
    if record.destination.is_ipv6() {
        command.arg("-6");
    }
    command
        .arg("route")
        .arg("del")
        .arg(format!("{}/{}", record.destination, record.prefix));

    run_route_cleanup_command(command)
}

#[cfg(target_os = "macos")]
fn route_record_is_host(record: &RouteRecord) -> bool {
    (record.destination.is_ipv4() && record.prefix == 32)
        || (record.destination.is_ipv6() && record.prefix == 128)
}

#[cfg(target_os = "macos")]
fn append_macos_route_destination_args(command: &mut Command, record: &RouteRecord) {
    if route_record_is_host(record) {
        command.arg(record.destination.to_string());
        return;
    }

    if record.prefix == 0 {
        command.arg("default");
        return;
    }

    command.arg(record.destination.to_string());
    match record.destination {
        IpAddr::V4(_) => {
            command.arg("-netmask").arg(record_mask_arg(record));
        }
        IpAddr::V6(_) => {
            command.arg("-prefixlen").arg(record.prefix.to_string());
        }
    }
}

#[cfg(target_os = "macos")]
fn record_mask_arg(record: &RouteRecord) -> String {
    match record.to_route().mask() {
        IpAddr::V4(mask) => mask.to_string(),
        IpAddr::V6(mask) => mask.to_string(),
    }
}

#[cfg(windows)]
fn delete_route_with_platform_tool(record: &RouteRecord) -> bool {
    let mut command = Command::new("powershell.exe");
    let destination_prefix = format!("{}/{}", record.destination, record.prefix);
    let interface_index = record
        .if_index
        .map(|if_index| if_index.to_string())
        .unwrap_or_default();
    let next_hop = record
        .gateway
        .filter(|gateway| !is_unspecified_gateway(*gateway, record.destination))
        .map(|gateway| gateway.to_string())
        .unwrap_or_default();
    let script = r#"
$DestinationPrefix = $args[0]
$InterfaceIndex = $args[1]
$NextHop = $args[2]
$filter = @{
    DestinationPrefix = $DestinationPrefix
    ErrorAction = 'SilentlyContinue'
}
if (-not [string]::IsNullOrWhiteSpace($InterfaceIndex)) {
    $filter.InterfaceIndex = [uint32]$InterfaceIndex
}
if (-not [string]::IsNullOrWhiteSpace($NextHop)) {
    $filter.NextHop = $NextHop
}
$routes = @(Get-NetRoute @filter)
foreach ($route in $routes) {
    $route | Remove-NetRoute -Confirm:$false -ErrorAction Stop
}
"#;
    let command_script = format!("& {{\n{script}\n}}");
    command
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-Command")
        .arg(command_script)
        .arg(destination_prefix)
        .arg(interface_index)
        .arg(next_hop);

    run_route_cleanup_command(command)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn delete_route_with_platform_tool(_record: &RouteRecord) -> bool {
    false
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn run_route_cleanup_command(mut command: Command) -> bool {
    debug!("运行路由清理命令：{:?}", command);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            debug!("运行路由清理命令失败：{e}");
            return false;
        }
    };
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return true,
            Ok(Some(status)) => {
                debug!("路由清理命令退出状态：{status}");
                return false;
            }
            Ok(None) if started.elapsed() >= ROUTE_CLEANUP_COMMAND_TIMEOUT => {
                warn!(
                    "路由清理命令超时（超过 {} 秒），正在终止子进程",
                    ROUTE_CLEANUP_COMMAND_TIMEOUT.as_secs()
                );
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
            Ok(None) => thread::sleep(ROUTE_CLEANUP_COMMAND_POLL_INTERVAL),
            Err(e) => {
                debug!("等待路由清理命令失败：{e}");
                return false;
            }
        }
    }
}
