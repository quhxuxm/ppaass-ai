#![cfg(target_os = "macos")]

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use common::tun_control::{
    tun_helper_dns_state_path, tun_helper_route_state_path, TunHelperRequest, TunHelperResponse,
    TUN_HELPER_PROTOCOL_VERSION,
};

use crate::config::locate_config_path;
use crate::logging::{normalize_log_level, UiLogBuffer};
use crate::network::probe_tun_ready;
use crate::process_util::current_time_millis;

pub(crate) const TUN_HELPER_SERVICE_ARG: &str = "--tun-helper-service";
const TUN_HELPER_SOCKET_ARG: &str = "--tun-helper-socket";
const TUN_HELPER_ALLOWED_UID_ARG: &str = "--tun-helper-allowed-uid";
const TUN_HELPER_LOG_LEVEL_ARG: &str = "--log-level";
const TUN_HELPER_INSTALL_PATH: &str = "/usr/local/libexec/ppaass-desktop-agent";
const TUN_HELPER_LEGACY_INSTALL_PATH: &str = "/usr/local/libexec/ppaass-tun-helper";
const TUN_HELPER_SOCKET_PATH: &str = "/var/run/ppaass-ai/tun-helper.sock";
const TUN_HELPER_PLIST_ID: &str = "com.ppaass.ai.desktop-agent.tun-helper";
const TUN_HELPER_LEGACY_PLIST_ID: &str = "com.ppaass.ai.tun-helper";
const TUN_HELPER_PLIST_PATH: &str =
    "/Library/LaunchDaemons/com.ppaass.ai.desktop-agent.tun-helper.plist";
const TUN_HELPER_LEGACY_PLIST_PATH: &str = "/Library/LaunchDaemons/com.ppaass.ai.tun-helper.plist";
const TUN_HELPER_LEASE_STATE_SUFFIX: &str = ".leases.json";
const TUN_HELPER_CONTROL_TIMEOUT: Duration = Duration::from_secs(4);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum MacosTunHelperStatus {
    Current,
    Missing,
    Outdated,
    NeedsRestart,
}

#[derive(Debug, Clone)]
struct MacosTunHelperStatePaths {
    route: PathBuf,
    dns: PathBuf,
    lease: PathBuf,
}

pub(crate) fn check_macos_tun_helper_on_startup(logs: &UiLogBuffer) {
    let Some(config_path) = locate_config_path() else {
        return;
    };

    let config = match desktop_agent_be::config::AgentConfig::load(&config_path) {
        Ok(config) => config,
        Err(err) => {
            logs.push(format!("跳过 TUN helper 自动检查：读取配置失败：{err}"));
            return;
        }
    };
    if !config_needs_macos_tun_helper(&config) {
        return;
    }

    let (tun_ready, tun_status) = probe_tun_ready(&config.tun.name);
    if tun_ready {
        logs.push(format!(
            "TUN 已在运行，暂不自动检查或更新 helper：{tun_status}。停止后点击启动会再次检查协议版本。"
        ));
        return;
    }

    if let Err(err) = ensure_macos_tun_helper(&config_path, &config, logs) {
        logs.push(format!("TUN helper 自动检查失败：{err}"));
    }
}

pub(crate) fn ensure_macos_tun_helper_for_config(
    config_path: &Path,
    logs: &UiLogBuffer,
) -> Result<(), String> {
    let config = desktop_agent_be::config::AgentConfig::load(config_path)
        .map_err(|err| format!("加载 Agent 配置失败：{err}"))?;
    if !config_needs_macos_tun_helper(&config) {
        return Ok(());
    }

    ensure_macos_tun_helper(config_path, &config, logs)
}

fn config_needs_macos_tun_helper(config: &desktop_agent_be::config::AgentConfig) -> bool {
    config.tun.enabled && config.tun.macos_helper_enabled
}

fn ensure_macos_tun_helper(
    config_path: &Path,
    config: &desktop_agent_be::config::AgentConfig,
    logs: &UiLogBuffer,
) -> Result<(), String> {
    let source = std::env::current_exe().map_err(|err| format!("定位当前 App 程序失败：{err}"))?;
    ensure_macos_tun_helper_from_source(&source, config_path, config, logs)
}

fn ensure_macos_tun_helper_from_source(
    source: &Path,
    config_path: &Path,
    config: &desktop_agent_be::config::AgentConfig,
    logs: &UiLogBuffer,
) -> Result<(), String> {
    let socket_path = macos_tun_helper_socket(config);
    match macos_tun_helper_status(config) {
        MacosTunHelperStatus::Current => {
            logs.push(format!(
                "TUN helper 协议版本已是当前版本：{}",
                TUN_HELPER_PROTOCOL_VERSION
            ));
            return Ok(());
        }
        MacosTunHelperStatus::Missing => logs.push("TUN helper 未安装，正在请求管理员授权安装"),
        MacosTunHelperStatus::Outdated => logs.push(format!(
            "TUN helper 协议版本不匹配，正在请求管理员授权更新到版本 {}",
            TUN_HELPER_PROTOCOL_VERSION
        )),
        MacosTunHelperStatus::NeedsRestart => {
            logs.push("TUN helper 已安装但未就绪，正在请求管理员授权重启")
        }
    }

    let state_paths = macos_tun_helper_state_paths(config_path, config)?;
    prepare_macos_tun_helper_replacement(config, &state_paths, logs)?;
    install_macos_tun_helper(source, config, &state_paths, logs)?;
    if wait_for_macos_tun_helper_socket(socket_path, Duration::from_secs(6)) {
        request_macos_tun_helper_cleanup(socket_path, &state_paths)
            .map_err(|err| format!("TUN helper 已更新，但启动后的遗留网络状态清理失败：{err}"))?;
        logs.push("TUN helper 已就绪");
        Ok(())
    } else {
        Err(format!("TUN helper socket 未就绪：{socket_path}"))
    }
}

fn macos_tun_helper_socket(config: &desktop_agent_be::config::AgentConfig) -> &str {
    let socket_path = config.tun.macos_helper_socket.trim();
    if socket_path.is_empty() {
        TUN_HELPER_SOCKET_PATH
    } else {
        socket_path
    }
}

fn macos_tun_helper_state_paths(
    _config_path: &Path,
    config: &desktop_agent_be::config::AgentConfig,
) -> Result<MacosTunHelperStatePaths, String> {
    let socket_path = Path::new(macos_tun_helper_socket(config));
    if !socket_path.is_absolute() {
        return Err(format!(
            "TUN helper socket 必须使用绝对路径：{}",
            socket_path.display()
        ));
    }
    Ok(MacosTunHelperStatePaths {
        route: tun_helper_route_state_path(socket_path),
        dns: tun_helper_dns_state_path(socket_path),
        lease: macos_tun_helper_lease_state_path(socket_path),
    })
}

fn macos_tun_helper_lease_state_path(socket_path: &Path) -> PathBuf {
    let mut file_name = socket_path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("tun-helper.sock"))
        .to_os_string();
    file_name.push(TUN_HELPER_LEASE_STATE_SUFFIX);
    socket_path.with_file_name(file_name)
}

fn prepare_macos_tun_helper_replacement(
    config: &desktop_agent_be::config::AgentConfig,
    state_paths: &MacosTunHelperStatePaths,
    logs: &UiLogBuffer,
) -> Result<(), String> {
    let active_reasons = active_macos_tun_replacement_reasons(config, state_paths)?;
    if !active_reasons.is_empty() {
        return Err(format!(
            "检测到活动 TUN，拒绝覆盖或重启 helper：{}。请先停止当前 Agent/TUN，确认网络恢复后再重试",
            active_reasons.join("；")
        ));
    }

    let socket_path = macos_tun_helper_socket(config);
    match macos_tun_helper_ping(socket_path) {
        Ok(()) => {
            logs.push(format!(
                "更新 TUN helper 前先清理现有 lease/路由状态：route={} dns={} lease={}",
                state_paths.route.display(),
                state_paths.dns.display(),
                state_paths.lease.display()
            ));
            request_macos_tun_helper_cleanup(socket_path, state_paths)?;
            verify_macos_tun_helper_routes_clean(config, state_paths)?;
            logs.push("现有 TUN helper 已确认完成更新前网络状态清理");
            Ok(())
        }
        Err(probe_error) => {
            if macos_tun_helper_process_running() {
                return Err(format!(
                    "拒绝覆盖或重启 TUN helper：旧 helper 进程仍在运行，但控制接口不可用，无法确认其 lease 已安全清理（{probe_error}）"
                ));
            }
            let stale_state = existing_macos_tun_helper_state_files(state_paths)?;
            if !stale_state.is_empty() {
                return Err(format!(
                    "旧 TUN helper 不可连接且仍有恢复状态，拒绝直接删除：{}（{probe_error}）",
                    stale_state.join("；")
                ));
            }
            logs.push(format!(
                "旧 TUN helper 不可连接，但未发现活动 lease/路由，可安全安装：{probe_error}"
            ));
            Ok(())
        }
    }
}

fn active_macos_tun_replacement_reasons(
    config: &desktop_agent_be::config::AgentConfig,
    _state_paths: &MacosTunHelperStatePaths,
) -> Result<Vec<String>, String> {
    let mut reasons = Vec::new();
    let (tun_ready, tun_status) = probe_tun_ready(&config.tun.name);
    if tun_ready {
        reasons.push(tun_status);
    } else if macos_managed_tun_route_active(&config.tun.name) {
        reasons.push("至少一条系统分流路由仍由 TUN 接管".to_string());
    }
    Ok(reasons)
}

fn existing_macos_tun_helper_state_files(
    state_paths: &MacosTunHelperStatePaths,
) -> Result<Vec<String>, String> {
    let mut existing = Vec::new();
    for (label, path) in [
        ("路由状态", &state_paths.route),
        ("DNS 状态", &state_paths.dns),
        ("helper lease 状态", &state_paths.lease),
    ] {
        if state_file_exists(path)? {
            existing.push(format!("{label}文件仍存在：{}", path.display()));
        }
    }
    Ok(existing)
}

fn verify_macos_tun_helper_routes_clean(
    config: &desktop_agent_be::config::AgentConfig,
    state_paths: &MacosTunHelperStatePaths,
) -> Result<(), String> {
    let remaining_state = existing_macos_tun_helper_state_files(state_paths)?;
    if !remaining_state.is_empty() {
        return Err(format!(
            "旧 helper 返回清理成功，但仍有恢复状态，拒绝重启：{}",
            remaining_state.join("；")
        ));
    }
    if macos_managed_tun_route_active(&config.tun.name) {
        return Err("旧 helper 返回清理成功，但系统流量仍由 TUN 路由接管，拒绝重启".to_string());
    }
    Ok(())
}

fn state_file_exists(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(format!(
            "检查 TUN helper 状态文件失败：{}：{err}",
            path.display()
        )),
    }
}

fn macos_tun_helper_process_running() -> bool {
    launchd_job_has_pid(TUN_HELPER_PLIST_ID) || launchd_job_has_pid(TUN_HELPER_LEGACY_PLIST_ID)
}

fn launchd_job_has_pid(label: &str) -> bool {
    let output = match Command::new("launchctl")
        .args(["print", &format!("system/{label}")])
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return false,
    };
    launchd_print_has_pid(&String::from_utf8_lossy(&output.stdout))
}

fn launchd_print_has_pid(output: &str) -> bool {
    output.lines().any(|line| {
        line.trim()
            .strip_prefix("pid = ")
            .is_some_and(|pid| pid.trim().parse::<u32>().is_ok_and(|pid| pid > 0))
    })
}

fn macos_managed_tun_route_active(configured_tun_name: &str) -> bool {
    ["1.1.1.1", "200.0.0.1"].iter().any(|target| {
        macos_route_interface(target)
            .as_deref()
            .is_some_and(|interface| tun_interface_matches(interface, configured_tun_name))
    })
}

fn macos_route_interface(target: &str) -> Option<String> {
    let output = Command::new("route")
        .args(["-n", "get", target])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_macos_route_interface(&String::from_utf8_lossy(&output.stdout))
}

fn parse_macos_route_interface(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        line.trim()
            .strip_prefix("interface:")
            .map(str::trim)
            .filter(|interface| !interface.is_empty())
            .map(ToOwned::to_owned)
    })
}

fn tun_interface_matches(interface: &str, configured_tun_name: &str) -> bool {
    interface == configured_tun_name
        || (interface.starts_with("utun") && configured_tun_name.starts_with("utun"))
}

fn macos_tun_helper_status(config: &desktop_agent_be::config::AgentConfig) -> MacosTunHelperStatus {
    let socket_path = macos_tun_helper_socket(config);
    let install_path = Path::new(TUN_HELPER_INSTALL_PATH);
    let plist_path = Path::new(TUN_HELPER_PLIST_PATH);
    if !install_path.is_file() || !plist_path.is_file() {
        return MacosTunHelperStatus::Missing;
    }

    if !macos_tun_helper_plist_matches(config).unwrap_or(false) {
        return MacosTunHelperStatus::Outdated;
    }

    match macos_tun_helper_protocol_version(socket_path) {
        Ok(version) if version == TUN_HELPER_PROTOCOL_VERSION => MacosTunHelperStatus::Current,
        Ok(_) => MacosTunHelperStatus::Outdated,
        Err(_) if macos_tun_helper_ping(socket_path).is_ok() => {
            // Ping is supported by legacy helpers. If ping works but the
            // version handshake does not, this is an old protocol.
            MacosTunHelperStatus::Outdated
        }
        Err(_) => MacosTunHelperStatus::NeedsRestart,
    }
}

fn macos_tun_helper_socket_ready(socket_path: &str) -> bool {
    macos_tun_helper_ping(socket_path).is_ok()
}

fn macos_tun_helper_ping(socket_path: &str) -> Result<(), String> {
    match send_macos_tun_helper_request(
        socket_path,
        &TunHelperRequest::Ping,
        Duration::from_millis(700),
    )? {
        TunHelperResponse::Pong => Ok(()),
        TunHelperResponse::Error { message } => {
            Err(format!("TUN helper probe 返回错误：{message}"))
        }
        TunHelperResponse::Ok => Err("TUN helper probe 返回了意外响应：ok".to_string()),
        TunHelperResponse::HelperInfo { .. } => {
            Err("TUN helper probe 返回了意外响应：helper_info".to_string())
        }
        TunHelperResponse::TunStarted(_) => {
            Err("TUN helper probe 返回了意外响应：tun_started".to_string())
        }
    }
}

fn macos_tun_helper_protocol_version(socket_path: &str) -> Result<u32, String> {
    match send_macos_tun_helper_request(
        socket_path,
        &TunHelperRequest::GetHelperInfo,
        Duration::from_millis(700),
    )? {
        TunHelperResponse::HelperInfo { protocol_version } => Ok(protocol_version),
        TunHelperResponse::Error { message } => {
            Err(format!("TUN helper 版本握手返回错误：{message}"))
        }
        TunHelperResponse::Pong => Err("TUN helper 版本握手返回了意外响应：pong".to_string()),
        TunHelperResponse::Ok => Err("TUN helper 版本握手返回了意外响应：ok".to_string()),
        TunHelperResponse::TunStarted(_) => {
            Err("TUN helper 版本握手返回了意外响应：tun_started".to_string())
        }
    }
}

fn request_macos_tun_helper_cleanup(
    socket_path: &str,
    state_paths: &MacosTunHelperStatePaths,
) -> Result<(), String> {
    let request = TunHelperRequest::CleanupStale {
        route_state_file: Some(state_paths.route.to_string_lossy().into_owned()),
        dns_state_file: Some(state_paths.dns.to_string_lossy().into_owned()),
    };
    validate_macos_tun_helper_cleanup_response(send_macos_tun_helper_request(
        socket_path,
        &request,
        TUN_HELPER_CONTROL_TIMEOUT,
    )?)
}

fn validate_macos_tun_helper_cleanup_response(response: TunHelperResponse) -> Result<(), String> {
    match response {
        TunHelperResponse::Ok => Ok(()),
        TunHelperResponse::Error { message } => {
            Err(format!("TUN helper 安全清理返回错误：{message}"))
        }
        TunHelperResponse::Pong => Err("TUN helper 安全清理返回了意外响应：pong".to_string()),
        TunHelperResponse::HelperInfo { .. } => {
            Err("TUN helper 安全清理返回了意外响应：helper_info".to_string())
        }
        TunHelperResponse::TunStarted(_) => {
            Err("TUN helper 安全清理返回了意外响应：tun_started".to_string())
        }
    }
}

fn send_macos_tun_helper_request(
    socket_path: &str,
    request: &TunHelperRequest,
    timeout: Duration,
) -> Result<TunHelperResponse, String> {
    if !Path::new(socket_path).exists() {
        return Err(format!("helper socket 不存在：{socket_path}"));
    }

    let mut stream = UnixStream::connect(socket_path)
        .map_err(|err| format!("连接 TUN helper 失败：socket={socket_path} error={err}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| format!("设置 helper probe 读超时失败：{err}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| format!("设置 helper probe 写超时失败：{err}"))?;

    exchange_macos_tun_helper_request(&mut stream, request)
}

fn exchange_macos_tun_helper_request(
    stream: &mut UnixStream,
    request: &TunHelperRequest,
) -> Result<TunHelperResponse, String> {
    let payload =
        serde_json::to_vec(request).map_err(|err| format!("序列化 TUN helper 请求失败：{err}"))?;
    let len = (payload.len() as u32).to_be_bytes();
    stream
        .write_all(&len)
        .map_err(|err| format!("发送 TUN helper probe 失败：{err}"))?;
    stream
        .write_all(&payload)
        .map_err(|err| format!("发送 TUN helper probe 失败：{err}"))?;

    let mut marker = [0u8; 1];
    stream
        .read_exact(&mut marker)
        .map_err(|err| format!("读取 TUN helper probe marker 失败：{err}"))?;
    if marker != [1] {
        return Err(format!(
            "TUN helper probe marker 无效：{}",
            marker.first().copied().unwrap_or_default()
        ));
    }

    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|err| format!("读取 TUN helper probe 响应长度失败：{err}"))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 1024 * 1024 {
        return Err(format!("TUN helper probe 响应过大：{len} bytes"));
    }

    let mut response = vec![0u8; len];
    stream
        .read_exact(&mut response)
        .map_err(|err| format!("读取 TUN helper probe 响应失败：{err}"))?;

    serde_json::from_slice::<TunHelperResponse>(&response)
        .map_err(|err| format!("解析 TUN helper probe 响应失败：{err}"))
}

fn macos_tun_helper_plist_matches(
    config: &desktop_agent_be::config::AgentConfig,
) -> Result<bool, String> {
    let socket_path = macos_tun_helper_socket(config);
    let allowed_uid = current_uid()?;
    let actual = fs::read_to_string(TUN_HELPER_PLIST_PATH)
        .map_err(|err| format!("读取 TUN helper plist 失败：{err}"))?;
    Ok(macos_tun_helper_plist_has_core_config(
        &actual,
        socket_path,
        allowed_uid,
    ))
}

fn macos_tun_helper_plist_has_core_config(
    plist: &str,
    socket_path: &str,
    allowed_uid: u32,
) -> bool {
    let allowed_uid = allowed_uid.to_string();
    [
        TUN_HELPER_PLIST_ID,
        TUN_HELPER_INSTALL_PATH,
        TUN_HELPER_SERVICE_ARG,
        TUN_HELPER_SOCKET_ARG,
        socket_path,
        TUN_HELPER_ALLOWED_UID_ARG,
        allowed_uid.as_str(),
    ]
    .iter()
    .all(|value| plist.contains(&format!("<string>{}</string>", xml_escape(value))))
}

fn install_macos_tun_helper(
    source: &Path,
    config: &desktop_agent_be::config::AgentConfig,
    state_paths: &MacosTunHelperStatePaths,
    logs: &UiLogBuffer,
) -> Result<(), String> {
    let allowed_uid = current_uid()?;
    let socket_path = macos_tun_helper_socket(config);
    let script = macos_tun_helper_install_script(
        source,
        socket_path,
        allowed_uid,
        &config.log_level,
        &state_paths.route,
        &state_paths.dns,
        &state_paths.lease,
    );
    let script_path = std::env::temp_dir().join(format!(
        "ppaass-install-tun-helper-{}-{}.sh",
        std::process::id(),
        current_time_millis()
    ));
    fs::write(&script_path, script).map_err(|err| {
        format!(
            "写入 TUN helper 安装脚本失败：{}：{err}",
            script_path.display()
        )
    })?;

    let result = run_macos_admin_shell_script(&script_path);
    let _ = fs::remove_file(&script_path);
    result?;

    logs.push(format!(
        "TUN helper 已安装到：{}，socket={}",
        TUN_HELPER_INSTALL_PATH, socket_path
    ));
    Ok(())
}

fn macos_tun_helper_install_script(
    source: &Path,
    socket_path: &str,
    allowed_uid: u32,
    log_level: &str,
    route_state_path: &Path,
    dns_state_path: &Path,
    lease_state_path: &Path,
) -> String {
    let plist = macos_tun_helper_plist(socket_path, allowed_uid, log_level);
    format!(
        r#"#!/bin/sh
set -eu
source_path={source_path}
install_path={install_path}
socket_path={socket_path}
route_state_path={route_state_path}
dns_state_path={dns_state_path}
lease_state_path={lease_state_path}
plist_id={plist_id}
plist_path={plist_path}
legacy_plist_path={legacy_plist_path}
legacy_install_path={legacy_install_path}

/bin/mkdir -p "$(dirname "$install_path")"
/bin/mkdir -p "$(dirname "$socket_path")"
if [ -e "$route_state_path" ] || [ -e "$dns_state_path" ] || [ -e "$lease_state_path" ]; then
  echo "检测到活动 TUN 路由、DNS 或 lease 状态，拒绝重启 helper：route=$route_state_path dns=$dns_state_path lease=$lease_state_path" >&2
  exit 73
fi
/bin/launchctl bootout system "$plist_path" >/dev/null 2>&1 || true
/bin/launchctl bootout system "$legacy_plist_path" >/dev/null 2>&1 || true
/usr/bin/install -m 0755 "$source_path" "$install_path"
/usr/sbin/chown root:wheel "$install_path"
/bin/rm -f "$legacy_install_path"
/bin/rm -f "$legacy_plist_path"
/bin/cat > "$plist_path" <<'PPAASS_TUN_HELPER_PLIST'
{plist}
PPAASS_TUN_HELPER_PLIST
/usr/sbin/chown root:wheel "$plist_path"
/bin/chmod 0644 "$plist_path"
/bin/launchctl bootstrap system "$plist_path"
/bin/launchctl enable "system/$plist_id"
/bin/launchctl kickstart -k "system/$plist_id"
"#,
        source_path = shell_quote(&source.to_string_lossy()),
        install_path = shell_quote(TUN_HELPER_INSTALL_PATH),
        socket_path = shell_quote(socket_path),
        route_state_path = shell_quote(&route_state_path.to_string_lossy()),
        dns_state_path = shell_quote(&dns_state_path.to_string_lossy()),
        lease_state_path = shell_quote(&lease_state_path.to_string_lossy()),
        plist_id = shell_quote(TUN_HELPER_PLIST_ID),
        plist_path = shell_quote(TUN_HELPER_PLIST_PATH),
        legacy_plist_path = shell_quote(TUN_HELPER_LEGACY_PLIST_PATH),
        legacy_install_path = shell_quote(TUN_HELPER_LEGACY_INSTALL_PATH),
    )
}

fn macos_tun_helper_plist(socket_path: &str, allowed_uid: u32, log_level: &str) -> String {
    let log_level = normalize_log_level(log_level);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{plist_id}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{install_path}</string>
    <string>{service_arg}</string>
    <string>{socket_arg}</string>
    <string>{socket_path}</string>
    <string>{allowed_uid_arg}</string>
    <string>{allowed_uid}</string>
    <string>{log_level_arg}</string>
    <string>{log_level}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/var/log/ppaass-desktop-agent-tun-helper.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/ppaass-desktop-agent-tun-helper.err.log</string>
</dict>
</plist>"#,
        plist_id = xml_escape(TUN_HELPER_PLIST_ID),
        install_path = xml_escape(TUN_HELPER_INSTALL_PATH),
        service_arg = xml_escape(TUN_HELPER_SERVICE_ARG),
        socket_arg = xml_escape(TUN_HELPER_SOCKET_ARG),
        socket_path = xml_escape(socket_path),
        allowed_uid_arg = xml_escape(TUN_HELPER_ALLOWED_UID_ARG),
        log_level_arg = xml_escape(TUN_HELPER_LOG_LEVEL_ARG),
        log_level = xml_escape(log_level),
    )
}

fn run_macos_admin_shell_script(script_path: &Path) -> Result<(), String> {
    let shell_command = format!("/bin/sh {}", shell_quote(&script_path.to_string_lossy()));
    let apple_script = format!(
        "do shell script {} with administrator privileges",
        apple_script_string(&shell_command)
    );
    let output = Command::new("osascript")
        .args(["-e", &apple_script])
        .output()
        .map_err(|err| format!("请求管理员授权失败：{err}"))?;

    if output.status.success() {
        return Ok(());
    }

    Err(command_failure_message("TUN helper 安装失败", &output))
}

fn command_failure_message(context: &str, output: &std::process::Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let detail = if stderr.is_empty() { stdout } else { stderr };
    if detail.is_empty() {
        format!("{context}：{}", output.status)
    } else {
        format!("{context}：{detail}")
    }
}

fn wait_for_macos_tun_helper_socket(socket_path: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if macos_tun_helper_socket_ready(socket_path) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

fn current_uid() -> Result<u32, String> {
    let output = Command::new("id")
        .arg("-u")
        .output()
        .map_err(|err| format!("读取当前用户 UID 失败：{err}"))?;
    if !output.status.success() {
        return Err(command_failure_message("读取当前用户 UID 失败", &output));
    }
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u32>()
        .map_err(|err| format!("解析当前用户 UID 失败：{err}"))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn apple_script_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub(crate) fn run_macos_tun_helper_service_from_args() -> Result<(), String> {
    let args = std::env::args().collect::<Vec<_>>();
    let socket = arg_value(&args, TUN_HELPER_SOCKET_ARG);
    let allowed_uid = match arg_value(&args, TUN_HELPER_ALLOWED_UID_ARG) {
        Some(value) => Some(
            value
                .parse::<u32>()
                .map_err(|err| format!("解析 TUN helper allowed uid 失败：{err}"))?,
        ),
        None => None,
    };
    let log_level = arg_value(&args, TUN_HELPER_LOG_LEVEL_ARG);

    desktop_agent_be::run_tun_helper_service(socket.as_deref(), allowed_uid, log_level.as_deref())
        .map_err(|err| err.to_string())
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find_map(|pair| {
        if pair[0] == flag {
            Some(pair[1].clone())
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn helper_response_server(
        mut stream: UnixStream,
        response: serde_json::Value,
    ) -> thread::JoinHandle<serde_json::Value> {
        thread::spawn(move || {
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).unwrap();
            let mut payload = vec![0u8; u32::from_be_bytes(len_buf) as usize];
            stream.read_exact(&mut payload).unwrap();

            let response = serde_json::to_vec(&response).unwrap();
            stream.write_all(&[1]).unwrap();
            stream
                .write_all(&(response.len() as u32).to_be_bytes())
                .unwrap();
            stream.write_all(&response).unwrap();
            serde_json::from_slice(&payload).unwrap()
        })
    }

    #[test]
    fn cleanup_request_sends_known_route_and_dns_state_before_restart() {
        let directory = tempfile::tempdir().unwrap();
        let route_path = directory.path().join("route state.json");
        let dns_path = directory.path().join("dns state.json");
        let (mut client, server_stream) = UnixStream::pair().unwrap();
        let server = helper_response_server(server_stream, serde_json::json!({ "type": "ok" }));

        let response = exchange_macos_tun_helper_request(
            &mut client,
            &TunHelperRequest::CleanupStale {
                route_state_file: Some(route_path.to_string_lossy().into_owned()),
                dns_state_file: Some(dns_path.to_string_lossy().into_owned()),
            },
        )
        .unwrap();
        assert!(matches!(response, TunHelperResponse::Ok));

        let request = server.join().unwrap();
        assert_eq!(request["type"], "cleanup_stale");
        assert_eq!(
            request["route_state_file"],
            route_path.to_string_lossy().as_ref()
        );
        assert_eq!(
            request["dns_state_file"],
            dns_path.to_string_lossy().as_ref()
        );
    }

    #[test]
    fn helper_version_handshake_uses_explicit_protocol_version() {
        let (mut client, server_stream) = UnixStream::pair().unwrap();
        let server = helper_response_server(
            server_stream,
            serde_json::json!({
                "type": "helper_info",
                "protocol_version": TUN_HELPER_PROTOCOL_VERSION
            }),
        );

        let response =
            exchange_macos_tun_helper_request(&mut client, &TunHelperRequest::GetHelperInfo)
                .unwrap();
        assert!(matches!(
            response,
            TunHelperResponse::HelperInfo { protocol_version }
                if protocol_version == TUN_HELPER_PROTOCOL_VERSION
        ));
        assert_eq!(server.join().unwrap()["type"], "get_helper_info");
    }

    #[test]
    fn cleanup_request_fails_closed_when_old_helper_rejects_it() {
        let directory = tempfile::tempdir().unwrap();
        let (mut client, server_stream) = UnixStream::pair().unwrap();
        let server = helper_response_server(
            server_stream,
            serde_json::json!({ "type": "error", "message": "lease is busy" }),
        );

        let response = exchange_macos_tun_helper_request(
            &mut client,
            &TunHelperRequest::CleanupStale {
                route_state_file: Some(
                    directory
                        .path()
                        .join("routes.json")
                        .to_string_lossy()
                        .into_owned(),
                ),
                dns_state_file: Some(
                    directory
                        .path()
                        .join("dns.json")
                        .to_string_lossy()
                        .into_owned(),
                ),
            },
        )
        .unwrap();

        let error = validate_macos_tun_helper_cleanup_response(response).unwrap_err();
        assert!(error.contains("lease is busy"));
        let _ = server.join().unwrap();
    }

    #[test]
    fn existing_state_files_cover_route_dns_and_lease_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let route_path = directory.path().join("tun-routes.json");
        let dns_path = directory.path().join("tun-dns.json");
        let lease_path = directory.path().join("helper.sock.leases.json");
        fs::write(&route_path, br#"{"routes":[{"destination":"0.0.0.0"}]}"#).unwrap();
        fs::write(&dns_path, b"{}").unwrap();
        fs::write(&lease_path, b"{}").unwrap();
        let state_paths = MacosTunHelperStatePaths {
            route: route_path,
            dns: dns_path,
            lease: lease_path,
        };

        let existing = existing_macos_tun_helper_state_files(&state_paths).unwrap();

        assert_eq!(existing.len(), 3);
        assert!(existing.iter().any(|item| item.contains("路由状态")));
        assert!(existing.iter().any(|item| item.contains("DNS 状态")));
        assert!(existing
            .iter()
            .any(|item| item.contains("helper lease 状态")));
    }

    #[test]
    fn install_script_guards_route_state_and_boots_out_before_replacing_binary() {
        let script = macos_tun_helper_install_script(
            Path::new("/Applications/PPAASS Agent.app/Contents/MacOS/ppaass"),
            "/var/run/ppaass-ai/tun-helper.sock",
            501,
            "info",
            Path::new("/Users/test/Library/Application Support/PPAASS/tun-routes.json"),
            Path::new("/Users/test/Library/Application Support/PPAASS/tun-dns.json"),
            Path::new("/var/run/ppaass-ai/tun-helper.sock.leases.json"),
        );

        let guard = script
            .find(
                "if [ -e \"$route_state_path\" ] || [ -e \"$dns_state_path\" ] || [ -e \"$lease_state_path\" ]",
            )
            .expect("route state guard");
        let bootout = script
            .find("/bin/launchctl bootout system \"$plist_path\"")
            .expect("launchd bootout");
        let install = script
            .find("/usr/bin/install -m 0755 \"$source_path\" \"$install_path\"")
            .expect("binary install");

        assert!(guard < bootout);
        assert!(bootout < install);
        assert!(script.contains("exit 73"));
    }

    #[test]
    fn detects_launchd_pid_without_accepting_zero_or_unrelated_fields() {
        assert!(launchd_print_has_pid(
            "state = running\n\tpid = 1234\n\tlast exit code = 0\n"
        ));
        assert!(!launchd_print_has_pid(
            "state = waiting\n\tpid = 0\n\tlast exit code = 1234\n"
        ));
    }

    #[test]
    fn parses_macos_route_interface_and_matches_dynamic_utun_names() {
        assert_eq!(
            parse_macos_route_interface(
                "   route to: 1.1.1.1\ninterface: utun12\nflags: <UP,DONE>\n"
            )
            .as_deref(),
            Some("utun12")
        );
        assert!(tun_interface_matches("utun12", "utun8"));
        assert!(tun_interface_matches("ppaass-tun", "ppaass-tun"));
        assert!(!tun_interface_matches("en0", "utun8"));
    }

    #[test]
    fn helper_state_paths_are_confined_to_the_socket_directory() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../agent.toml");
        let mut config =
            desktop_agent_be::config::AgentConfig::load(&config_path).expect("local config");
        config.tun.macos_helper_socket = directory
            .path()
            .join("helper.sock")
            .to_string_lossy()
            .into_owned();
        config.tun.route_state_file = Some("/tmp/caller-controlled-routes.json".to_string());
        config.tun.dns_state_file = Some("/tmp/caller-controlled-dns.json".to_string());

        let paths = macos_tun_helper_state_paths(&config_path, &config).unwrap();

        assert_eq!(paths.route, directory.path().join("tun-routes.json"));
        assert_eq!(paths.dns, directory.path().join("tun-dns.json"));

        config.tun.macos_helper_socket = "relative/helper.sock".to_string();
        assert!(macos_tun_helper_state_paths(&config_path, &config)
            .unwrap_err()
            .contains("必须使用绝对路径"));
    }

    #[test]
    fn helper_lease_state_path_matches_service_registry_path() {
        assert_eq!(
            macos_tun_helper_lease_state_path(Path::new("/var/run/ppaass-ai/tun-helper.sock")),
            Path::new("/var/run/ppaass-ai/tun-helper.sock.leases.json")
        );
    }
}
