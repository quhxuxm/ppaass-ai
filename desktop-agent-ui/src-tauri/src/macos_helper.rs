#![cfg(target_os = "macos")]

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use crate::config::{deployed_agent_data_file, locate_config_path};
use crate::logging::{normalize_log_level, UiLogBuffer};
use crate::models::MacosTunHelperProbeResponse;
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
const TUN_HELPER_PLIST_PATH: &str =
    "/Library/LaunchDaemons/com.ppaass.ai.desktop-agent.tun-helper.plist";
const TUN_HELPER_LEGACY_PLIST_PATH: &str = "/Library/LaunchDaemons/com.ppaass.ai.tun-helper.plist";
const TUN_HELPER_CURRENT_APP_MARKER: &str = "tun-helper-current-app.txt";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum MacosTunHelperStatus {
    Current,
    Missing,
    Outdated,
    NeedsRestart,
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

    let source = match std::env::current_exe() {
        Ok(source) => source,
        Err(err) => {
            logs.push(format!(
                "跳过 TUN helper 自动检查：定位当前 App 程序失败：{err}"
            ));
            return;
        }
    };
    let force_refresh = macos_tun_helper_current_app_update_pending(&source, logs);
    let (tun_ready, tun_status) = probe_tun_ready(&config.tun.name);
    if tun_ready {
        if force_refresh {
            logs.push(format!(
                "检测到当前 App 首次运行或已更新，但 TUN 已在运行，暂不热更新 helper：{tun_status}。停止后点击启动会强制更新。"
            ));
        } else {
            logs.push(format!(
                "TUN 已在运行，暂不自动更新 helper：{tun_status}。停止后点击启动会再次检查。"
            ));
        }
        return;
    }

    if let Err(err) = ensure_macos_tun_helper_from_source(&source, &config, logs, force_refresh) {
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

    ensure_macos_tun_helper(&config, logs)
}

fn config_needs_macos_tun_helper(config: &desktop_agent_be::config::AgentConfig) -> bool {
    config.tun.enabled && config.tun.macos_helper_enabled
}

fn ensure_macos_tun_helper(
    config: &desktop_agent_be::config::AgentConfig,
    logs: &UiLogBuffer,
) -> Result<(), String> {
    let source = std::env::current_exe().map_err(|err| format!("定位当前 App 程序失败：{err}"))?;
    let force_refresh = macos_tun_helper_current_app_update_pending(&source, logs);
    ensure_macos_tun_helper_from_source(&source, config, logs, force_refresh)
}

fn ensure_macos_tun_helper_from_source(
    source: &Path,
    config: &desktop_agent_be::config::AgentConfig,
    logs: &UiLogBuffer,
    force_refresh: bool,
) -> Result<(), String> {
    let socket_path = macos_tun_helper_socket(config);
    let status = macos_tun_helper_status(source, config);
    match (status, force_refresh) {
        (MacosTunHelperStatus::Current, false) => {
            logs.push("TUN helper 已是当前 App 版本");
            record_macos_tun_helper_current_app(source, logs);
            return Ok(());
        }
        (MacosTunHelperStatus::Current, true) => {
            logs.push("当前 App 首次运行或已更新，正在强制刷新 TUN helper")
        }
        (MacosTunHelperStatus::Missing, _) => {
            logs.push("TUN helper 未安装，正在请求管理员授权安装")
        }
        (MacosTunHelperStatus::Outdated, _) => {
            logs.push("TUN helper 不是当前 App 版本，正在请求管理员授权更新")
        }
        (MacosTunHelperStatus::NeedsRestart, _) => {
            logs.push("TUN helper 已安装但未就绪，正在请求管理员授权重启")
        }
    }

    install_macos_tun_helper(source, config, logs)?;
    if wait_for_macos_tun_helper_socket(socket_path, Duration::from_secs(6)) {
        logs.push("TUN helper 已就绪");
        record_macos_tun_helper_current_app(source, logs);
        Ok(())
    } else {
        Err(format!("TUN helper socket 未就绪：{socket_path}"))
    }
}

fn macos_tun_helper_current_app_update_pending(source: &Path, logs: &UiLogBuffer) -> bool {
    let signature = match macos_current_app_signature(source) {
        Ok(signature) => signature,
        Err(err) => {
            logs.push(format!("跳过 TUN helper 首次运行强制刷新：{err}"));
            return false;
        }
    };
    let marker_path = match macos_tun_helper_current_app_marker_path() {
        Ok(path) => path,
        Err(err) => {
            logs.push(format!("跳过 TUN helper 首次运行强制刷新：{err}"));
            return false;
        }
    };

    match fs::read_to_string(&marker_path) {
        Ok(saved) => saved.trim() != signature,
        Err(err) if err.kind() == io::ErrorKind::NotFound => true,
        Err(err) => {
            logs.push(format!(
                "读取 TUN helper 当前 App 标记失败，将按普通状态检查：{}：{err}",
                marker_path.display()
            ));
            false
        }
    }
}

fn record_macos_tun_helper_current_app(source: &Path, logs: &UiLogBuffer) {
    let signature = match macos_current_app_signature(source) {
        Ok(signature) => signature,
        Err(err) => {
            logs.push(format!("记录 TUN helper 当前 App 标记失败：{err}"));
            return;
        }
    };
    let marker_path = match macos_tun_helper_current_app_marker_path() {
        Ok(path) => path,
        Err(err) => {
            logs.push(format!("记录 TUN helper 当前 App 标记失败：{err}"));
            return;
        }
    };

    if let Some(parent) = marker_path.parent() {
        if let Err(err) = fs::create_dir_all(parent) {
            logs.push(format!(
                "创建 TUN helper 当前 App 标记目录失败：{}：{err}",
                parent.display()
            ));
            return;
        }
    }
    if let Err(err) = fs::write(&marker_path, format!("{signature}\n")) {
        logs.push(format!(
            "写入 TUN helper 当前 App 标记失败：{}：{err}",
            marker_path.display()
        ));
    }
}

fn macos_tun_helper_current_app_marker_path() -> Result<PathBuf, String> {
    deployed_agent_data_file(TUN_HELPER_CURRENT_APP_MARKER)
        .ok_or_else(|| "Agent 数据目录尚未初始化".to_string())
}

fn macos_current_app_signature(source: &Path) -> Result<String, String> {
    let canonical = source
        .canonicalize()
        .unwrap_or_else(|_| source.to_path_buf());
    let mut file = fs::File::open(source).map_err(|err| format!("打开当前 App 程序失败：{err}"))?;
    let metadata = file
        .metadata()
        .map_err(|err| format!("读取当前 App 程序元数据失败：{err}"))?;
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    let mut buffer = [0u8; 64 * 1024];

    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|err| format!("读取当前 App 程序失败：{err}"))?;
        if read == 0 {
            break;
        }
        for byte in &buffer[..read] {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }

    Ok(format!(
        "path={}\nlen={}\nhash={hash:016x}",
        canonical.display(),
        metadata.len()
    ))
}

fn macos_tun_helper_socket(config: &desktop_agent_be::config::AgentConfig) -> &str {
    let socket_path = config.tun.macos_helper_socket.trim();
    if socket_path.is_empty() {
        TUN_HELPER_SOCKET_PATH
    } else {
        socket_path
    }
}

fn macos_tun_helper_status(
    source: &Path,
    config: &desktop_agent_be::config::AgentConfig,
) -> MacosTunHelperStatus {
    let socket_path = macos_tun_helper_socket(config);
    let install_path = Path::new(TUN_HELPER_INSTALL_PATH);
    let plist_path = Path::new(TUN_HELPER_PLIST_PATH);
    if !install_path.is_file() || !plist_path.is_file() {
        return MacosTunHelperStatus::Missing;
    }

    if !files_identical(source, install_path).unwrap_or(false) {
        return MacosTunHelperStatus::Outdated;
    }

    if !macos_tun_helper_plist_matches(config).unwrap_or(false) {
        return MacosTunHelperStatus::Outdated;
    }

    if !macos_tun_helper_socket_ready(socket_path) {
        return MacosTunHelperStatus::NeedsRestart;
    }

    MacosTunHelperStatus::Current
}

fn macos_tun_helper_socket_ready(socket_path: &str) -> bool {
    macos_tun_helper_ping(socket_path).is_ok()
}

fn macos_tun_helper_ping(socket_path: &str) -> Result<(), String> {
    if !Path::new(socket_path).exists() {
        return Err(format!("helper socket 不存在：{socket_path}"));
    }

    let mut stream = UnixStream::connect(socket_path)
        .map_err(|err| format!("连接 TUN helper 失败：socket={socket_path} error={err}"))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(700)))
        .map_err(|err| format!("设置 helper probe 读超时失败：{err}"))?;
    stream
        .set_write_timeout(Some(Duration::from_millis(700)))
        .map_err(|err| format!("设置 helper probe 写超时失败：{err}"))?;

    let payload = br#"{"type":"ping"}"#;
    let len = (payload.len() as u32).to_be_bytes();
    stream
        .write_all(&len)
        .and_then(|_| stream.write_all(payload))
        .map_err(|err| format!("发送 TUN helper probe 失败：{err}"))?;

    let mut marker = [0u8; 1];
    stream
        .read_exact(&mut marker)
        .map_err(|err| format!("读取 TUN helper probe marker 失败：{err}"))?;

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

    match serde_json::from_slice::<MacosTunHelperProbeResponse>(&response)
        .map_err(|err| format!("解析 TUN helper probe 响应失败：{err}"))?
    {
        MacosTunHelperProbeResponse::Pong => Ok(()),
        MacosTunHelperProbeResponse::Error { message } => {
            Err(format!("TUN helper probe 返回错误：{message}"))
        }
    }
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

fn files_identical(left: &Path, right: &Path) -> io::Result<bool> {
    let left_metadata = fs::metadata(left)?;
    let right_metadata = fs::metadata(right)?;
    if left_metadata.len() != right_metadata.len() {
        return Ok(false);
    }

    Ok(fs::read(left)? == fs::read(right)?)
}

fn install_macos_tun_helper(
    source: &Path,
    config: &desktop_agent_be::config::AgentConfig,
    logs: &UiLogBuffer,
) -> Result<(), String> {
    let allowed_uid = current_uid()?;
    let socket_path = macos_tun_helper_socket(config);
    let script =
        macos_tun_helper_install_script(source, socket_path, allowed_uid, &config.log_level);
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
) -> String {
    let plist = macos_tun_helper_plist(socket_path, allowed_uid, log_level);
    format!(
        r#"#!/bin/sh
set -eu
source_path={source_path}
install_path={install_path}
socket_path={socket_path}
plist_id={plist_id}
plist_path={plist_path}
legacy_plist_path={legacy_plist_path}
legacy_install_path={legacy_install_path}

/bin/mkdir -p "$(dirname "$install_path")"
/bin/mkdir -p "$(dirname "$socket_path")"
/usr/bin/install -m 0755 "$source_path" "$install_path"
/usr/sbin/chown root:wheel "$install_path"
/bin/rm -f "$legacy_install_path"
/bin/launchctl bootout system "$plist_path" >/dev/null 2>&1 || true
/bin/launchctl bootout system "$legacy_plist_path" >/dev/null 2>&1 || true
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
