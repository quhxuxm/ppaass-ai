use super::*;

pub(crate) fn macos_tun_helper_plist_matches(
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

pub(crate) fn macos_tun_helper_plist_has_core_config(
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

pub(crate) fn install_macos_tun_helper(
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

pub fn macos_tun_helper_install_script(
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

pub(crate) fn macos_tun_helper_plist(
    socket_path: &str,
    allowed_uid: u32,
    log_level: &str,
) -> String {
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

pub(crate) fn run_macos_admin_shell_script(script_path: &Path) -> Result<(), String> {
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

pub(crate) fn command_failure_message(context: &str, output: &std::process::Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let detail = if stderr.is_empty() { stdout } else { stderr };
    if detail.is_empty() {
        format!("{context}：{}", output.status)
    } else {
        format!("{context}：{detail}")
    }
}

pub(crate) fn wait_for_macos_tun_helper_socket(socket_path: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if macos_tun_helper_socket_ready(socket_path) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

pub(crate) fn current_uid() -> Result<u32, String> {
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

pub(crate) fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub(crate) fn apple_script_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

pub(crate) fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
