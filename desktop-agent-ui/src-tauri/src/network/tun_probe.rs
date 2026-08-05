use std::process::Command;
#[cfg(any(windows, target_os = "linux"))]
use std::process::Stdio;
#[cfg(target_os = "windows")]
use std::thread;
#[cfg(target_os = "windows")]
use std::time::{Duration, Instant};

#[cfg(target_os = "windows")]
use crate::process_util::hide_child_console;

#[cfg(target_os = "windows")]
const WINDOWS_TUN_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(target_os = "windows")]
pub(super) fn tun_interface_ready(tun_name: &str) -> bool {
    powershell_status(
        "$adapter = Get-NetAdapter -Name $env:PPAASS_TUN_NAME -ErrorAction SilentlyContinue; if ($adapter -and $adapter.Status -eq 'Up') { exit 0 }; exit 1",
        tun_name,
    )
}

#[cfg(target_os = "windows")]
pub(super) fn tun_routes_ready(tun_name: &str) -> bool {
    powershell_status(
        "$routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/1','128.0.0.0/1' -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -eq $env:PPAASS_TUN_NAME }); if ($routes.Count -ge 2) { exit 0 }; exit 1",
        tun_name,
    )
}

#[cfg(target_os = "windows")]
fn powershell_status(script: &str, tun_name: &str) -> bool {
    let mut command = Command::new("powershell.exe");
    command
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .env("PPAASS_TUN_NAME", tun_name)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    hide_child_console(&mut command);
    command_status_with_timeout(&mut command, WINDOWS_TUN_PROBE_TIMEOUT)
}

#[cfg(target_os = "windows")]
fn command_status_with_timeout(command: &mut Command, timeout: Duration) -> bool {
    let Ok(mut child) = command.spawn() else {
        return false;
    };
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

#[cfg(target_os = "macos")]
pub(super) fn tun_interface_ready(tun_name: &str) -> bool {
    macos_ifconfig_up(tun_name)
        || macos_active_tun_route_interface().is_some_and(|name| macos_ifconfig_up(&name))
}

#[cfg(target_os = "macos")]
pub(super) fn tun_routes_ready(tun_name: &str) -> bool {
    (route_get_uses_tun("1.1.1.1", tun_name) && route_get_uses_tun("200.0.0.1", tun_name))
        || macos_active_tun_route_interface().is_some()
}

#[cfg(target_os = "macos")]
fn route_get_uses_tun(target: &str, tun_name: &str) -> bool {
    route_get_interface(target).is_some_and(|name| name == tun_name)
}

#[cfg(target_os = "macos")]
pub(super) fn resolved_tun_name(tun_name: &str) -> Option<String> {
    if macos_ifconfig_up(tun_name) {
        return Some(tun_name.to_string());
    }
    macos_active_tun_route_interface()
}

#[cfg(not(target_os = "macos"))]
pub(super) fn resolved_tun_name(tun_name: &str) -> Option<String> {
    Some(tun_name.to_string())
}

#[cfg(target_os = "macos")]
fn macos_ifconfig_up(tun_name: &str) -> bool {
    Command::new("ifconfig")
        .arg(tun_name)
        .output()
        .ok()
        .is_some_and(|output| {
            output.status.success()
                && String::from_utf8_lossy(&output.stdout)
                    .to_ascii_uppercase()
                    .contains("UP")
        })
}

#[cfg(target_os = "macos")]
fn macos_active_tun_route_interface() -> Option<String> {
    let first = route_get_interface("1.1.1.1")?;
    let second = route_get_interface("200.0.0.1")?;
    (first == second && first.starts_with("utun")).then_some(first)
}

#[cfg(target_os = "macos")]
fn route_get_interface(target: &str) -> Option<String> {
    let output = Command::new("route")
        .args(["-n", "get", target])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("interface:")
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(ToOwned::to_owned)
        })
}

#[cfg(target_os = "linux")]
pub(super) fn tun_interface_ready(tun_name: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", "dev", tun_name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(target_os = "linux")]
pub(super) fn tun_routes_ready(tun_name: &str) -> bool {
    ip_route_uses_tun("1.1.1.1", tun_name) && ip_route_uses_tun("200.0.0.1", tun_name)
}

#[cfg(target_os = "linux")]
fn ip_route_uses_tun(target: &str, tun_name: &str) -> bool {
    Command::new("ip")
        .args(["route", "get", target])
        .output()
        .ok()
        .is_some_and(|output| {
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains(&format!(" dev {tun_name} "))
        })
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
pub(super) fn tun_interface_ready(_tun_name: &str) -> bool {
    false
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
pub(super) fn tun_routes_ready(_tun_name: &str) -> bool {
    false
}
