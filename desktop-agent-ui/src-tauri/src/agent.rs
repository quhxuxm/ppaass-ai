use std::fs;
use std::path::{Path, PathBuf};
#[cfg(target_os = "windows")]
use std::process::Command;
#[cfg(target_os = "windows")]
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;

use crate::config::{locate_config_path, make_absolute_path, summarize_config};
use crate::logging::UiLogBuffer;
#[cfg(target_os = "macos")]
use crate::macos_helper::ensure_macos_tun_helper_for_config;
use crate::models::AgentState;
use crate::network::connect_addr;
#[cfg(target_os = "windows")]
use crate::process_util::hide_child_console;
use crate::runtime::{AgentRuntime, EmbeddedAgent};
#[cfg(windows)]
use crate::windows_service::{
    start_agent_via_windows_service, stop_agent_via_windows_service, windows_service_is_running,
    windows_service_matches_current_exe, windows_service_state,
};

#[cfg(windows)]
use windows_sys::Win32::UI::Shell::IsUserAnAdmin;

pub(crate) fn get_agent_state_inner(runtime: &AgentRuntime) -> Result<AgentState, String> {
    #[cfg(windows)]
    if windows_service_matches_current_exe().unwrap_or(false) {
        match windows_service_state() {
            Ok(state) => return Ok(state),
            Err(err) if windows_service_is_running().unwrap_or(false) => return Err(err),
            Err(_) => return agent_state_from_status(runtime, false, None),
        }
    }

    agent_state(runtime)
}

pub(crate) fn start_agent_command(
    runtime: &AgentRuntime,
    config_path: String,
) -> Result<AgentState, String> {
    #[cfg(windows)]
    {
        return start_agent_via_windows_service(config_path, &runtime.logs);
    }

    #[cfg(not(windows))]
    start_agent_inner(runtime, PathBuf::from(config_path), true)
}

pub(crate) fn start_agent_inner(
    runtime: &AgentRuntime,
    config_path: PathBuf,
    allow_elevation: bool,
) -> Result<AgentState, String> {
    apply_log_level_from_config_path(runtime, &config_path)?;

    let (running, _) = process_status(runtime)?;
    if running {
        return agent_state(runtime);
    }

    if allow_elevation {
        ensure_start_privileges(&config_path)?;
    }
    #[cfg(target_os = "macos")]
    if allow_elevation {
        ensure_macos_tun_helper_for_config(&config_path, &runtime.logs)?;
    }
    stop_external_agent(&config_path)?;
    if let Ok(mut last_error) = runtime.last_error.lock() {
        *last_error = None;
    }
    let embedded = spawn_embedded_agent(
        config_path.clone(),
        runtime.logs.clone(),
        runtime.last_error.clone(),
    )?;

    *runtime
        .config_path
        .lock()
        .map_err(|_| "配置路径状态锁已损坏".to_string())? = Some(config_path);
    *runtime
        .agent
        .lock()
        .map_err(|_| "进程状态锁已损坏".to_string())? = Some(embedded);

    wait_for_agent_start(runtime)?;
    agent_state(runtime)
}

pub(crate) fn stop_agent_inner_command(runtime: &AgentRuntime) -> Result<AgentState, String> {
    #[cfg(windows)]
    if let Ok(state) = stop_agent_via_windows_service() {
        return Ok(state);
    }

    stop_embedded_agent(runtime)?;
    agent_state(runtime)
}

pub(crate) fn stop_embedded_agent(runtime: &AgentRuntime) -> Result<(), String> {
    let mut guard = runtime
        .agent
        .lock()
        .map_err(|_| "进程状态锁已损坏".to_string())?;

    if let Some(mut agent) = guard.take() {
        agent.shutdown.cancel();
        if let Some(join) = agent.join.take() {
            let _ = join.join();
        }
    }
    Ok(())
}

pub(crate) fn agent_state(runtime: &AgentRuntime) -> Result<AgentState, String> {
    let (running, pid) = process_status(runtime)?;
    agent_state_from_status(runtime, running, pid)
}

pub(crate) fn agent_state_from_status(
    runtime: &AgentRuntime,
    running: bool,
    pid: Option<u32>,
) -> Result<AgentState, String> {
    let config_path = runtime
        .config_path
        .lock()
        .map_err(|_| "配置路径状态锁已损坏".to_string())?
        .clone()
        .or_else(locate_config_path);

    Ok(AgentState {
        running,
        managed: true,
        pid,
        config_path: config_path.map(|path| path.to_string_lossy().to_string()),
        binary_path: std::env::current_exe()
            .ok()
            .map(|path| path.to_string_lossy().to_string()),
        logs: runtime.logs.snapshot(),
    })
}

pub(crate) fn apply_ui_log_level(runtime: &AgentRuntime, log_level: &str) {
    if let Err(err) = runtime.logs.set_log_level(log_level) {
        runtime.logs.push(err);
    }
}

fn apply_log_level_from_config_path(
    runtime: &AgentRuntime,
    config_path: &Path,
) -> Result<(), String> {
    let config = desktop_agent_be::config::AgentConfig::load(config_path)
        .map_err(|err| format!("加载 Agent 配置失败：{err}"))?;
    apply_ui_log_level(runtime, &config.log_level);
    Ok(())
}

fn process_status(runtime: &AgentRuntime) -> Result<(bool, Option<u32>), String> {
    let mut guard = runtime
        .agent
        .lock()
        .map_err(|_| "进程状态锁已损坏".to_string())?;

    match guard.as_mut() {
        Some(agent) if agent.join.as_ref().is_some_and(JoinHandle::is_finished) => {
            if let Some(join) = agent.join.take() {
                let _ = join.join();
            }
            *guard = None;
            Ok((false, None))
        }
        Some(_) => Ok((true, Some(std::process::id()))),
        None => Ok((false, None)),
    }
}

fn spawn_embedded_agent(
    config_path: PathBuf,
    logs: UiLogBuffer,
    last_error: Arc<Mutex<Option<String>>>,
) -> Result<EmbeddedAgent, String> {
    let agent_base_dir = agent_base_dir(&config_path);
    let mut config = desktop_agent_be::config::AgentConfig::load(&config_path)
        .map_err(|err| format!("加载 Agent 配置失败：{err}"))?;
    normalize_agent_config_paths(&mut config, &agent_base_dir);
    config.log_dir = None;
    #[cfg(target_os = "macos")]
    {
        config.tun.macos_helper_fallback_to_privilege = false;
    }
    let shutdown = CancellationToken::new();
    let shutdown_for_thread = shutdown.clone();
    let thread_logs = logs.clone();
    let thread_error = last_error.clone();
    let stack_size = config.async_runtime_stack_size_mb * 1024 * 1024;
    let runtime_threads = config.runtime_threads;

    logs.push(format!(
        "准备以内嵌模式启动 Agent：{}",
        config_path.to_string_lossy()
    ));
    logs.push(format!("Agent 资源目录：{}", agent_base_dir.display()));
    if config.tun.enabled {
        if let Some(wintun_file) = config.tun.wintun_file.as_deref() {
            logs.push(format!("Windows TUN 运行库：{wintun_file}"));
        }
    }

    let join = thread::Builder::new()
        .name("ppaass-embedded-agent".to_string())
        .spawn(move || {
            let mut builder = tokio::runtime::Builder::new_multi_thread();
            builder.thread_stack_size(stack_size).enable_all();
            if let Some(threads) = runtime_threads {
                builder.worker_threads(threads);
            }

            match builder.build() {
                Ok(runtime) => {
                    let result =
                        runtime.block_on(desktop_agent_be::run_agent(config, shutdown_for_thread));
                    if let Err(err) = result {
                        let message = format!("内嵌 Agent 异常停止：{err}");
                        if let Ok(mut last_error) = thread_error.lock() {
                            *last_error = Some(message.clone());
                        }
                        tracing::error!("{message}");
                    }
                }
                Err(err) => {
                    let message = format!("创建内嵌 Agent Tokio runtime 失败：{err}");
                    if let Ok(mut last_error) = thread_error.lock() {
                        *last_error = Some(message.clone());
                    }
                    thread_logs.push(message);
                }
            }
        })
        .map_err(|err| format!("启动内嵌 Agent 线程失败：{err}"))?;

    Ok(EmbeddedAgent {
        shutdown,
        join: Some(join),
    })
}

fn normalize_agent_config_paths(
    config: &mut desktop_agent_be::config::AgentConfig,
    base_dir: &Path,
) {
    config.private_key_path = resolve_existing_agent_path(base_dir, &config.private_key_path)
        .to_string_lossy()
        .into();

    if let Some(wintun_file) = config.tun.wintun_file.as_mut() {
        let trimmed = wintun_file.trim();
        if !trimmed.is_empty() {
            *wintun_file = resolve_existing_agent_path(base_dir, trimmed)
                .to_string_lossy()
                .into();
        }
    }

    if let Some(route_state_file) = config.tun.route_state_file.as_mut() {
        let trimmed = route_state_file.trim();
        if !trimmed.is_empty() {
            *route_state_file = resolve_agent_path(base_dir, trimmed)
                .to_string_lossy()
                .into();
        }
    }

    if let Some(dns_state_file) = config.tun.dns_state_file.as_mut() {
        let trimmed = dns_state_file.trim();
        if !trimmed.is_empty() {
            *dns_state_file = resolve_agent_path(base_dir, trimmed)
                .to_string_lossy()
                .into();
        }
    }
}

fn resolve_existing_agent_path(base_dir: &Path, value: &str) -> PathBuf {
    let path = Path::new(value);
    if path.is_absolute() {
        return path.to_path_buf();
    }

    agent_asset_candidates(base_dir, path)
        .into_iter()
        .find(|candidate| candidate.exists())
        .unwrap_or_else(|| base_dir.join(path))
}

fn resolve_agent_path(base_dir: &Path, value: &str) -> PathBuf {
    let path = Path::new(value);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    }
}

fn agent_asset_candidates(base_dir: &Path, path: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    push_unique_path(&mut candidates, base_dir.join(path));

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            push_unique_path(&mut candidates, dir.join(path));
        }
    }

    if let Ok(cwd) = std::env::current_dir() {
        push_unique_path(&mut candidates, cwd.join(path));
    }

    candidates
}

fn push_unique_path(candidates: &mut Vec<PathBuf>, path: PathBuf) {
    if !candidates.iter().any(|candidate| candidate == &path) {
        candidates.push(path);
    }
}

fn agent_base_dir(config_path: &Path) -> PathBuf {
    let absolute_config = make_absolute_path(config_path);
    if let Some(base_dir) = find_agent_base_dir(&absolute_config) {
        return base_dir;
    }

    let absolute_config = config_path
        .canonicalize()
        .unwrap_or_else(|_| make_absolute_path(config_path));
    if let Some(base_dir) = find_agent_base_dir(&absolute_config) {
        return base_dir;
    }

    if let Some(parent) = absolute_config.parent() {
        return parent.to_path_buf();
    }

    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn find_agent_base_dir(config_path: &Path) -> Option<PathBuf> {
    let parent = config_path.parent()?;
    parent
        .ancestors()
        .take(8)
        .find(|ancestor| is_agent_base_dir(ancestor))
        .map(Path::to_path_buf)
}

fn is_agent_base_dir(path: &Path) -> bool {
    path.join("wintun.dll").is_file()
        || path.join("desktop-agent-be").is_dir()
        || (path.join("config/local/agent.toml").is_file() && path.join("keys").is_dir())
}

fn wait_for_agent_start(runtime: &AgentRuntime) -> Result<(), String> {
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

fn last_agent_error(runtime: &AgentRuntime) -> Option<String> {
    let last_error = runtime.last_error.lock().ok()?;
    last_error.clone()
}

fn ensure_start_privileges(config_path: &Path) -> Result<(), String> {
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
fn is_elevated_for_tun() -> bool {
    unsafe { IsUserAnAdmin() != 0 }
}

#[cfg(not(windows))]
fn is_elevated_for_tun() -> bool {
    true
}

fn stop_external_agent(config_path: &Path) -> Result<(), String> {
    let raw = fs::read_to_string(config_path).map_err(|err| format!("读取配置失败：{err}"))?;
    let summary = summarize_config(&raw)?;
    let addr = connect_addr(&summary.listen_addr)
        .ok_or_else(|| format!("无法解析监听地址：{}", summary.listen_addr))?;
    stop_external_agent_on_port(addr.port()).map(|_| ())
}

#[cfg(target_os = "windows")]
fn stop_external_agent_on_port(port: u16) -> Result<bool, String> {
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
fn stop_external_agent_on_port(_port: u16) -> Result<bool, String> {
    Ok(false)
}
