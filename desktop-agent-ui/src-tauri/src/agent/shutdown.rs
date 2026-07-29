use super::*;

pub(crate) fn wait_for_agent_start(runtime: &AgentRuntime) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        let (running, _) = process_status(runtime)?;
        if !running {
            return Err(last_agent_error(runtime)
                .unwrap_or_else(|| "Agent 启动后立即退出，请查看日志页".to_string()));
        }
        if last_agent_error(runtime).is_some() {
            return Err(last_agent_error(runtime).unwrap());
        }
        std::thread::sleep(Duration::from_millis(120));
    }
    Ok(())
}

pub(crate) fn last_agent_error(runtime: &AgentRuntime) -> Option<String> {
    let last_error = runtime.last_error.lock().ok()?;
    last_error.clone()
}

pub(crate) fn ensure_start_privileges(config_path: &Path) -> Result<(), String> {
    let raw = fs::read_to_string(config_path).map_err(|err| format!("读取配置失败：{err}"))?;
    let summary = summarize_config(&raw)?;
    if !summary.tun_enabled || is_elevated_for_tun() {
        return Ok(());
    }

    Err(
        "TUN 模式需要管理员权限。Windows 不能把当前窗口原地提权；请以管理员身份启动 PPAASS Agent UI 后再点击启动。"
            .to_string(),
    )
}

#[cfg(windows)]
pub(crate) fn is_elevated_for_tun() -> bool {
    unsafe { IsUserAnAdmin() != 0 }
}

#[cfg(not(windows))]
pub(crate) fn is_elevated_for_tun() -> bool {
    true
}

pub(crate) fn stop_external_agent(config_path: &Path) -> Result<(), String> {
    let raw = fs::read_to_string(config_path).map_err(|err| format!("读取配置失败：{err}"))?;
    let summary = summarize_config(&raw)?;
    let addr = connect_addr(&summary.listen_addr)
        .ok_or_else(|| format!("无法解析监听地址：{}", summary.listen_addr))?;
    stop_external_agent_on_port(addr.port()).map(|_| ())
}

#[cfg(target_os = "windows")]
pub(crate) fn stop_external_agent_on_port(port: u16) -> Result<bool, String> {
    let script = r#"
$port = [int]$env:PPAASS_AGENT_PORT
$stopped = $false
$connections = @(Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)
foreach ($connection in $connections) {
  $process = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
  if ($process -and $process.ProcessName -eq 'desktop-agent') {
    try {
      Stop-Process -Id $process.Id -Force -ErrorAction Stop
      $stopped = $true
    } catch {}
  }
}
if ($stopped) { exit 0 }
exit 2
"#;

    let mut command = Command::new("powershell.exe");
    command
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .env("PPAASS_AGENT_PORT", port.to_string())
        .stdin(Stdio::null());
    hide_child_console(&mut command);
    let output = command
        .output()
        .map_err(|err| format!("停止外部 Agent 失败：{err}"))?;

    match output.status.code() {
        Some(0) => Ok(true),
        Some(2) => Ok(false),
        _ => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if stderr.is_empty() {
                Err(format!("停止外部 Agent 失败：{}", output.status))
            } else {
                Err(stderr)
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub(crate) fn stop_external_agent_on_port(_port: u16) -> Result<bool, String> {
    Ok(false)
}
