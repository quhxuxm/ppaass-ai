#![cfg(windows)]

use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown as TcpShutdown, SocketAddr, TcpStream as StdTcpStream};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::Manager;
use tempfile::Builder as TempFileBuilder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Builder;
use tokio::task;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};
use windows_sys::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteW};
use zeroize::{Zeroize, Zeroizing};

use crate::agent::{
    agent_state, clear_packet_capture_runtime_local, packet_capture_runtime_status_local,
    set_packet_capture_runtime_enabled_local, start_agent_inner, stop_embedded_agent,
};
use crate::auth::{load_persisted_agent_login_from_dir, set_windows_restricted_acl};
use crate::logging::UiLogBuffer;
use crate::models::{
    AgentAuthAccountStatus, AgentState, ServiceRequest, ServiceResponse, VerifiedProxyAuthStatus,
};
use crate::runtime::AgentRuntime;
use crate::telemetry::agent_traffic_snapshot;

pub(crate) const SERVICE_ARG: &str = "--ppaass-agent-service";
pub(crate) const INSTALL_SERVICE_ARG: &str = "--ppaass-install-service";
pub(crate) const SERVICE_CONFIG_ROOT_ARG: &str = "--ppaass-service-config-root";

const SERVICE_NAME: &str = "PPAASSAgentService";
const SERVICE_DISPLAY_NAME: &str = "PPAASS Agent Service";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const SERVICE_IPC_ADDR: &str = "127.0.0.1:17981";
const SERVICE_IPC_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const SERVICE_IPC_IO_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_SERVICE_IPC_REQUEST_BYTES: u64 = 64 * 1024;
const MAX_SERVICE_IPC_RESPONSE_BYTES: u64 = 1024 * 1024;
const SERVICE_SESSION_FILE_NAME: &str = "service-session.json";
const SERVICE_SESSION_FILE_VERSION: u8 = 1;
const SERVICE_SESSION_TOKEN_BYTES: usize = 32;
const SERVICE_SESSION_TOKEN_HEX_LEN: usize = SERVICE_SESSION_TOKEN_BYTES * 2;
const MAX_SERVICE_SESSION_FILE_BYTES: u64 = 4 * 1024;
const SERVICE_DESIRED_STATE_FILE_NAME: &str = "service-runtime-state.json";
const SERVICE_DESIRED_STATE_FILE_VERSION: u8 = 1;
const MAX_SERVICE_DESIRED_STATE_FILE_BYTES: u64 = 1024;
const MANAGED_PROXY_IDENTITY_PUBLIC_KEY_FILE: &str = "proxy-identity-public.pem";

static SERVICE_CONFIG_ROOT: OnceLock<PathBuf> = OnceLock::new();
static UI_SERVICE_SESSION_TOKEN: Mutex<Option<Zeroizing<String>>> = Mutex::new(None);

#[derive(Serialize)]
struct ServiceRequestEnvelopeRef<'a> {
    auth_token: &'a str,
    request: &'a ServiceRequest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceRequestEnvelope {
    auth_token: String,
    request: ServiceRequest,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceSessionAuthorization {
    version: u8,
    token: String,
    #[serde(
        default,
        rename = "ui_process_id",
        skip_serializing_if = "Option::is_none"
    )]
    _legacy_ui_process_id: Option<u32>,
    #[serde(
        default,
        rename = "ui_process_creation_time",
        skip_serializing_if = "Option::is_none"
    )]
    _legacy_ui_process_creation_time: Option<u64>,
    #[serde(
        default,
        rename = "expires_at",
        skip_serializing_if = "Option::is_none"
    )]
    _legacy_expires_at: Option<i64>,
}

impl Drop for ServiceSessionAuthorization {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ServiceLoginBinding {
    username: String,
    key_version: i64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ServiceDesiredState {
    version: u8,
    desired_running: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_version: Option<i64>,
}

define_windows_service!(ffi_service_main, windows_service_main);

pub(crate) fn activate_windows_service_session(app: &tauri::AppHandle) -> Result<(), String> {
    let mut random = [0_u8; SERVICE_SESSION_TOKEN_BYTES];
    getrandom::fill(&mut random)
        .map_err(|error| format!("生成 Windows Service 会话令牌失败：{error}"))?;
    let token = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    random.zeroize();

    let path = ui_service_session_file_path(app)?;
    let parent = path
        .parent()
        .ok_or_else(|| "Windows Service 会话文件缺少父目录".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("创建 Windows Service 会话目录失败：{error}"))?;
    set_windows_restricted_acl(parent, true)?;

    let authorization = ServiceSessionAuthorization {
        version: SERVICE_SESSION_FILE_VERSION,
        token: token.clone(),
        // Older files bound authorization to one UI PID. These fields are
        // decoded below only so an in-place upgrade can keep the already
        // authenticated Service running. The token now belongs to the durable
        // login and is revoked only by explicit logout.
        _legacy_ui_process_id: None,
        _legacy_ui_process_creation_time: None,
        // Kept for backwards-compatible decoding of existing files only.
        // Account/key expiry is decided by Proxy, never by the local clock.
        _legacy_expires_at: None,
    };
    let mut serialized = serde_json::to_vec(&authorization)
        .map_err(|error| format!("编码 Windows Service 会话失败：{error}"))?;
    let mut temporary = TempFileBuilder::new()
        .prefix(".service-session-")
        .tempfile_in(parent)
        .map_err(|error| format!("创建 Windows Service 会话临时文件失败：{error}"))?;
    set_windows_restricted_acl(temporary.path(), false)?;
    temporary
        .write_all(&serialized)
        .map_err(|error| format!("写入 Windows Service 会话失败：{error}"))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| format!("同步 Windows Service 会话失败：{error}"))?;
    serialized.zeroize();

    if path.exists() {
        revoke_service_session_file(&path)?;
    }
    temporary
        .persist(&path)
        .map_err(|error| format!("保存 Windows Service 会话失败：{}", error.error))?;
    set_windows_restricted_acl(&path, false)?;
    if let Ok(directory) = fs::File::open(parent) {
        let _ = directory.sync_all();
    }

    *UI_SERVICE_SESSION_TOKEN
        .lock()
        .map_err(|_| "Windows Service 会话令牌锁已损坏".to_string())? = Some(Zeroizing::new(token));
    Ok(())
}

pub(crate) fn invalidate_windows_service_session(app: &tauri::AppHandle) -> Result<(), String> {
    let desired_result = clear_ui_service_desired_running(app);
    let session_result =
        ui_service_session_file_path(app).and_then(|path| revoke_service_session_file(&path));
    if let Ok(mut token) = UI_SERVICE_SESSION_TOKEN.lock() {
        token.take();
    }
    match (desired_result, session_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(desired_error), Ok(())) => Err(desired_error),
        (Ok(()), Err(session_error)) => Err(session_error),
        (Err(desired_error), Err(session_error)) => Err(format!(
            "{desired_error}；同时吊销 Windows Service 会话失败：{session_error}"
        )),
    }
}

fn ui_service_session_file_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_local_data_dir()
        .map(|path| path.join("credentials").join(SERVICE_SESSION_FILE_NAME))
        .map_err(|error| format!("定位 Windows Service 会话目录失败：{error}"))
}

fn clear_ui_service_desired_running(app: &tauri::AppHandle) -> Result<(), String> {
    let path = app
        .path()
        .app_local_data_dir()
        .map(|path| {
            path.join("credentials")
                .join(SERVICE_DESIRED_STATE_FILE_NAME)
        })
        .map_err(|error| format!("定位 Windows Service 运行状态目录失败：{error}"))?;
    match fs::symlink_metadata(&path) {
        Ok(_) => persist_service_desired_state(&path, None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("读取 Windows Service 运行状态失败：{error}")),
    }
}

fn revoke_service_session_file(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(remove_error) => {
            let revoke_result = fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(path)
                .and_then(|mut file| {
                    file.write_all(b"{\"revoked\":true}")?;
                    file.sync_all()
                });
            match revoke_result {
                Ok(()) => Err(format!(
                    "删除 Windows Service 会话文件失败，已将其吊销：{remove_error}"
                )),
                Err(revoke_error) => Err(format!(
                    "无法吊销 Windows Service 会话：删除失败（{remove_error}），覆盖失败（{revoke_error}）"
                )),
            }
        }
    }
}

pub(crate) fn start_agent_via_windows_service(
    config_path: String,
    logs: &UiLogBuffer,
) -> Result<AgentState, String> {
    verify_interactive_installation_is_protected()?;
    trusted_windows_wintun_path()?;
    let (config_path, config_root) = canonical_managed_config_path(&config_path)?;
    ensure_windows_service_available(logs, &config_root)?;
    let response = send_service_request(&ServiceRequest::Start {
        config_path: config_path.to_string_lossy().to_string(),
    })?;
    service_state_response(response)
}

pub(crate) fn stop_agent_via_windows_service() -> Result<AgentState, String> {
    let response = send_service_request(&ServiceRequest::Stop)?;
    service_state_response(response)
}

pub(crate) fn windows_service_state() -> Result<AgentState, String> {
    let response = send_service_request(&ServiceRequest::State)?;
    service_state_response(response)
}

pub(crate) fn windows_service_auth_status() -> Result<Option<VerifiedProxyAuthStatus>, String> {
    if !windows_service_matches_current_exe().unwrap_or(false)
        || !windows_service_is_running().unwrap_or(false)
    {
        return Ok(None);
    }
    let response = send_service_request(&ServiceRequest::State)?;
    if response.ok {
        Ok(response.auth_status)
    } else {
        Err(response
            .error
            .unwrap_or_else(|| "Agent 服务请求失败".to_string()))
    }
}

pub(crate) fn windows_service_is_running() -> Result<bool, String> {
    let output = match run_sc_capture(["query", SERVICE_NAME]) {
        Ok(output) => output,
        Err(error) if error.contains("1060") => return Ok(false),
        Err(error) => return Err(error),
    };
    Ok(output.lines().any(|line| {
        let line = line.to_ascii_uppercase();
        line.contains("STATE") && line.contains("RUNNING")
    }))
}

pub(crate) fn windows_service_matches_current_exe() -> Result<bool, String> {
    let output = run_sc_capture(["qc", SERVICE_NAME])?;
    let command_line = parse_sc_binary_path(&output)
        .ok_or_else(|| "无法读取 PPAASS Agent Windows Service 路径".to_string())?;
    if !command_line.contains(SERVICE_ARG) {
        return Ok(false);
    }

    let Some(service_exe_path) = extract_service_exe_path(command_line) else {
        return Ok(false);
    };

    let current_exe = std::env::current_exe().map_err(|err| format!("定位 UI 程序失败：{err}"))?;
    let service_exe = PathBuf::from(service_exe_path);
    Ok(normalized_path_for_compare(&current_exe) == normalized_path_for_compare(&service_exe))
}

pub(crate) fn send_service_request(request: &ServiceRequest) -> Result<ServiceResponse, String> {
    let addr = SERVICE_IPC_ADDR
        .parse::<SocketAddr>()
        .map_err(|err| format!("服务 IPC 地址无效：{err}"))?;
    let token = UI_SERVICE_SESSION_TOKEN
        .lock()
        .map_err(|_| "Windows Service 会话令牌锁已损坏".to_string())?
        .as_ref()
        .cloned()
        .ok_or_else(|| "Windows Service 会话未授权，请重新登录".to_string())?;
    send_service_request_to(addr, request, &token)
}

fn send_service_request_to(
    addr: SocketAddr,
    request: &ServiceRequest,
    auth_token: &str,
) -> Result<ServiceResponse, String> {
    let payload = encode_service_request(request, auth_token)?;

    // The UI calls this function from Tauri's blocking worker pool. A standard loopback
    // socket avoids creating and tearing down a Tokio runtime for every telemetry poll and
    // preserves the reliable Windows connect_timeout behavior used by the original IPC path.
    let mut stream =
        StdTcpStream::connect_timeout(&addr, SERVICE_IPC_CONNECT_TIMEOUT).map_err(|err| {
            if err.kind() == std::io::ErrorKind::TimedOut {
                "连接 Agent 服务超时".to_string()
            } else {
                format!("无法连接 Agent 服务：{err}")
            }
        })?;
    stream
        .set_read_timeout(Some(SERVICE_IPC_IO_TIMEOUT))
        .map_err(|err| format!("设置服务 IPC 读超时失败：{err}"))?;
    stream
        .set_write_timeout(Some(SERVICE_IPC_IO_TIMEOUT))
        .map_err(|err| format!("设置服务 IPC 写超时失败：{err}"))?;

    stream
        .write_all(&payload)
        .map_err(|err| format!("发送服务请求失败：{err}"))?;
    let _ = stream.shutdown(TcpShutdown::Write);

    let mut response = Vec::new();
    stream
        .take(MAX_SERVICE_IPC_RESPONSE_BYTES + 1)
        .read_to_end(&mut response)
        .map_err(|err| format!("读取服务响应失败：{err}"))?;
    if response.len() as u64 > MAX_SERVICE_IPC_RESPONSE_BYTES {
        return Err("Agent 服务响应过大，已拒绝处理".to_string());
    }
    serde_json::from_slice(&response).map_err(|err| format!("解析服务响应失败：{err}"))
}

fn encode_service_request(request: &ServiceRequest, auth_token: &str) -> Result<Vec<u8>, String> {
    validate_service_token_format(auth_token)?;
    let payload = serde_json::to_vec(&ServiceRequestEnvelopeRef {
        auth_token,
        request,
    })
    .map_err(|err| format!("编码服务请求失败：{err}"))?;
    if payload.len() as u64 > MAX_SERVICE_IPC_REQUEST_BYTES {
        return Err("服务请求过大，已拒绝发送".to_string());
    }
    Ok(payload)
}

pub(crate) fn install_and_start_windows_service(config_root: PathBuf) -> Result<(), String> {
    trusted_service_executable()?;
    trusted_windows_wintun_path()?;
    let config_root = canonical_managed_config_root_dir(&config_root)?;
    let exe = std::env::current_exe().map_err(|err| format!("定位 UI 程序失败：{err}"))?;
    let bin_path = format!(
        "\"{}\" {SERVICE_ARG} {SERVICE_CONFIG_ROOT_ARG} \"{}\"",
        exe.display(),
        config_root.display()
    );

    if run_sc(["query", SERVICE_NAME]).is_err() {
        run_sc([
            "create",
            SERVICE_NAME,
            "binPath=",
            &bin_path,
            "start=",
            "auto",
            "DisplayName=",
            SERVICE_DISPLAY_NAME,
        ])?;
    } else {
        stop_windows_service_if_running()?;
        run_sc([
            "config",
            SERVICE_NAME,
            "binPath=",
            &bin_path,
            "start=",
            "auto",
        ])?;
    }

    match run_sc(["start", SERVICE_NAME]) {
        Ok(()) => Ok(()),
        Err(err) if err.contains("1056") || err.contains("already running") => Ok(()),
        Err(err) => Err(err),
    }
}

pub(crate) fn run_windows_service(config_root: PathBuf) -> Result<(), String> {
    trusted_service_executable()?;
    trusted_windows_wintun_path()?;
    let config_root = canonical_managed_config_root_dir(&config_root)?;
    SERVICE_CONFIG_ROOT
        .set(config_root)
        .map_err(|_| "Windows Service 受管配置目录被重复初始化".to_string())?;
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|err| format!("启动 Windows Service dispatcher 失败：{err}"))
}

pub(crate) fn service_config_root_from_args() -> Result<PathBuf, String> {
    let mut args = std::env::args_os();
    while let Some(arg) = args.next() {
        if arg == SERVICE_CONFIG_ROOT_ARG {
            return args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| "Windows Service 缺少受管配置目录参数".to_string());
        }
    }
    Err("Windows Service 缺少受管配置目录参数".to_string())
}

fn service_state_response(response: ServiceResponse) -> Result<AgentState, String> {
    if response.ok {
        response
            .state
            .ok_or_else(|| "服务响应缺少 Agent 状态".to_string())
    } else {
        Err(response
            .error
            .unwrap_or_else(|| "Agent 服务请求失败".to_string()))
    }
}

fn ensure_windows_service_available(logs: &UiLogBuffer, config_root: &Path) -> Result<(), String> {
    let service_is_current = windows_service_matches_installation(config_root).unwrap_or(false);
    if service_is_current && send_service_request(&ServiceRequest::State).is_ok() {
        return Ok(());
    }

    if service_is_current {
        logs.push("正在请求启动 PPAASS Agent Windows Service");
    } else if run_sc(["query", SERVICE_NAME]).is_ok() {
        logs.push("PPAASS Agent Windows Service 指向旧程序，正在请求管理员权限更新服务");
    } else {
        logs.push("正在请求安装 PPAASS Agent Windows Service");
    }
    launch_elevated_service_installer(config_root)?;

    let deadline = Instant::now() + Duration::from_secs(35);
    while Instant::now() < deadline {
        let service_is_current = windows_service_matches_installation(config_root).unwrap_or(false);
        if service_is_current && send_service_request(&ServiceRequest::State).is_ok() {
            logs.push("PPAASS Agent Windows Service 已就绪");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    Err("PPAASS Agent Windows Service 启动超时".to_string())
}

fn launch_elevated_service_installer(config_root: &Path) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|err| format!("定位 UI 程序失败：{err}"))?;
    let cwd = std::env::current_dir().map_err(|err| format!("定位工作目录失败：{err}"))?;
    let args = format!(
        "{INSTALL_SERVICE_ARG} {SERVICE_CONFIG_ROOT_ARG} \"{}\"",
        config_root.display()
    );

    let operation = wide_null("runas");
    let exe = wide_null(exe.as_os_str());
    let args = wide_null(args);
    let cwd = wide_null(cwd.as_os_str());

    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            operation.as_ptr(),
            exe.as_ptr(),
            args.as_ptr(),
            cwd.as_ptr(),
            0,
        )
    };

    if result as isize <= 32 {
        return Err(format!(
            "请求管理员权限启动服务失败：ShellExecuteW 返回 {result:?}"
        ));
    }
    Ok(())
}

fn windows_service_matches_installation(config_root: &Path) -> Result<bool, String> {
    if !windows_service_matches_current_exe()? {
        return Ok(false);
    }
    let output = run_sc_capture(["qc", SERVICE_NAME])?;
    let command_line = parse_sc_binary_path(&output)
        .ok_or_else(|| "无法读取 PPAASS Agent Windows Service 路径".to_string())?;
    let Some(service_config_root) =
        extract_command_argument_path(command_line, SERVICE_CONFIG_ROOT_ARG)
    else {
        return Ok(false);
    };
    Ok(normalized_path_for_compare(config_root)
        == normalized_path_for_compare(Path::new(&service_config_root))
        && sc_service_is_auto_start(&output))
}

fn sc_service_is_auto_start(output: &str) -> bool {
    output.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("START_TYPE")
                && (value.trim_start().starts_with('2')
                    || value.to_ascii_uppercase().contains("AUTO_START"))
        })
    })
}

fn wide_null(value: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    value
        .as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn run_sc<const N: usize>(args: [&str; N]) -> Result<(), String> {
    run_sc_capture(args).map(|_| ())
}

fn run_sc_capture<const N: usize>(args: [&str; N]) -> Result<String, String> {
    let output = Command::new("sc.exe")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|err| format!("执行 sc.exe 失败：{err}"))?;

    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).to_string());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(format!(
        "sc.exe 失败：{}{}{}",
        output.status,
        if stdout.trim().is_empty() { "" } else { "\n" },
        if stdout.trim().is_empty() {
            stderr.trim()
        } else {
            stdout.trim()
        }
    ))
}

fn parse_sc_binary_path(output: &str) -> Option<&str> {
    output.lines().find_map(|line| {
        if !line.contains("BINARY_PATH_NAME") {
            return None;
        }
        line.split_once(':').map(|(_, value)| value.trim())
    })
}

fn extract_service_exe_path(command_line: &str) -> Option<String> {
    let command_line = command_line.trim();
    if command_line.is_empty() {
        return None;
    }

    if let Some(rest) = command_line.strip_prefix('"') {
        let (path, _) = rest.split_once('"')?;
        return Some(path.to_string());
    }

    command_line
        .split_whitespace()
        .next()
        .map(|path| path.to_string())
}

fn extract_command_argument_path(command_line: &str, argument: &str) -> Option<String> {
    let (_, remaining) = command_line.split_once(argument)?;
    let remaining = remaining.trim_start();
    if let Some(quoted) = remaining.strip_prefix('"') {
        return quoted
            .split_once('"')
            .map(|(value, _)| value.to_string())
            .filter(|value| !value.is_empty());
    }
    remaining
        .split_whitespace()
        .next()
        .map(str::to_string)
        .filter(|value| !value.is_empty())
}

fn normalized_path_for_compare(path: &Path) -> String {
    fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .replace('/', "\\")
        .to_lowercase()
}

fn trusted_service_executable() -> Result<PathBuf, String> {
    let executable = fs::canonicalize(
        std::env::current_exe().map_err(|err| format!("定位 UI 程序失败：{err}"))?,
    )
    .map_err(|err| format!("解析 UI 程序路径失败：{err}"))?;
    let install_dir = executable
        .parent()
        .ok_or_else(|| "UI 程序缺少安装目录".to_string())?;
    let trusted = program_files_roots()
        .iter()
        .any(|root| normalized_path_is_within(install_dir, root));
    if !trusted {
        return Err(
            "拒绝将用户可写目录中的程序注册为 SYSTEM 服务；请使用正式安装包安装到 Program Files"
                .to_string(),
        );
    }
    Ok(executable)
}

pub(crate) fn trusted_windows_wintun_path() -> Result<PathBuf, String> {
    let executable = trusted_service_executable()?;
    let install_dir = executable
        .parent()
        .ok_or_else(|| "UI 程序缺少安装目录".to_string())?;
    let wintun = fs::canonicalize(install_dir.join("wintun.dll"))
        .map_err(|err| format!("可信安装目录缺少 wintun.dll：{err}"))?;
    if wintun.parent() != Some(install_dir) || !wintun.is_file() {
        return Err("wintun.dll 必须是可信安装目录中的普通文件".to_string());
    }
    Ok(wintun)
}

fn program_files_roots() -> Vec<PathBuf> {
    ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"]
        .into_iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .filter_map(|path| fs::canonicalize(path).ok())
        .fold(Vec::new(), |mut roots, path| {
            if !roots.iter().any(|existing| {
                normalized_path_for_compare(existing) == normalized_path_for_compare(&path)
            }) {
                roots.push(path);
            }
            roots
        })
}

fn verify_interactive_installation_is_protected() -> Result<(), String> {
    let executable = trusted_service_executable()?;
    let install_dir = executable
        .parent()
        .ok_or_else(|| "UI 程序缺少安装目录".to_string())?;
    let wintun = trusted_windows_wintun_path()?;
    if unsafe { IsUserAnAdmin() } != 0 {
        return Ok(());
    }

    match TempFileBuilder::new()
        .prefix(".ppaass-write-probe-")
        .tempfile_in(install_dir)
    {
        Ok(_) => return Err("Agent 安装目录可被当前普通用户写入，拒绝启动 SYSTEM 服务".to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
        Err(error) => return Err(format!("无法验证 Agent 安装目录写保护：{error}")),
    }

    match fs::OpenOptions::new().write(true).open(&wintun) {
        Ok(_) => Err("wintun.dll 可被当前普通用户替换，拒绝启动 SYSTEM 服务".to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Ok(()),
        Err(error) => Err(format!("无法验证 wintun.dll 写保护：{error}")),
    }
}

fn stop_windows_service_if_running() -> Result<(), String> {
    match run_sc(["stop", SERVICE_NAME]) {
        Ok(()) => wait_windows_service_stopped(),
        Err(err) if err.contains("1062") || err.contains("has not been started") => Ok(()),
        Err(err) => Err(err),
    }
}

fn wait_windows_service_stopped() -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        let query = run_sc_capture(["query", SERVICE_NAME])?;
        if query.contains("STOPPED") {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(300));
    }

    Err("等待 PPAASS Agent Windows Service 停止超时".to_string())
}

fn windows_service_main(_arguments: Vec<std::ffi::OsString>) {
    if let Err(err) = run_windows_service_inner() {
        eprintln!("PPAASS Agent Service failed: {err}");
    }
}

fn run_windows_service_inner() -> Result<(), String> {
    let runtime = Arc::new(AgentRuntime::new());
    runtime.logs.install_tracing();
    runtime.logs.push("PPAASS Agent Windows Service 启动");
    let shutdown = CancellationToken::new();
    let shutdown_for_handler = shutdown.clone();

    let status_handle =
        service_control_handler::register(SERVICE_NAME, move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                shutdown_for_handler.cancel();
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        })
        .map_err(|err| format!("注册 Windows Service 控制处理器失败：{err}"))?;

    set_service_status(&status_handle, ServiceState::Running)?;

    let auth_failure_thread =
        spawn_service_auth_failure_listener(runtime.clone(), shutdown.clone())
            .map_err(|err| format!("启动 Proxy 账号状态监听失败：{err}"))?;
    restore_desired_agent_on_service_start(&runtime);

    let ipc_runtime = runtime.clone();
    let ipc_shutdown = shutdown.clone();
    let ipc_thread = thread::Builder::new()
        .name("ppaass-agent-service-ipc".to_string())
        .spawn(move || run_service_ipc(ipc_runtime, ipc_shutdown))
        .map_err(|err| format!("启动服务 IPC 失败：{err}"))?;

    while !shutdown.is_cancelled() {
        std::thread::sleep(Duration::from_millis(300));
    }

    let _ = stop_embedded_agent(&runtime);
    let _ = ipc_thread.join();
    let _ = auth_failure_thread.join();
    set_service_status(&status_handle, ServiceState::Stopped)?;
    Ok(())
}

fn restore_desired_agent_on_service_start(runtime: &AgentRuntime) {
    let desired_login = match service_desired_running() {
        Ok(desired_login) => desired_login,
        Err(error) => {
            runtime.logs.push(format!(
                "读取 Windows Service 持久运行状态失败，已安全跳过自动恢复：{error}"
            ));
            return;
        }
    };
    let Some(desired_login) = desired_login else {
        return;
    };

    if let Err(error) = service_session_authorization() {
        runtime.logs.push(format!(
            "Windows Service 存在持久运行请求，但登录授权无效，已安全跳过自动恢复：{error}"
        ));
        return;
    }

    let config_path = service_root_config_path();
    let restored =
        validate_authorized_service_config_path(&config_path).and_then(|(path, current_login)| {
            if current_login != desired_login {
                return Err("持久运行请求属于另一组登录凭据，拒绝用当前账号自动恢复".to_string());
            }
            start_agent_inner(runtime, path, false)
        });
    match restored {
        Ok(_) => runtime
            .logs
            .push("Windows Service 已恢复上次显式启动的 Agent"),
        Err(error) => runtime.logs.push(format!(
            "Windows Service 无法恢复上次显式启动的 Agent；保留运行请求以便修复后重试：{error}"
        )),
    }
}

fn spawn_service_auth_failure_listener(
    runtime: Arc<AgentRuntime>,
    shutdown: CancellationToken,
) -> Result<thread::JoinHandle<()>, String> {
    let mut statuses = common::subscribe_verified_proxy_auth_statuses();
    thread::Builder::new()
        .name("ppaass-agent-service-auth-status".to_string())
        .spawn(move || {
            let async_runtime = match Builder::new_current_thread().enable_all().build() {
                Ok(runtime) => runtime,
                Err(error) => {
                    runtime
                        .logs
                        .push(format!("创建 Proxy 账号状态监听 runtime 失败：{error}"));
                    return;
                }
            };
            async_runtime.block_on(async move {
                loop {
                    let status = tokio::select! {
                        _ = shutdown.cancelled() => break,
                        status = statuses.recv() => match status {
                            Ok(status) => status,
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        },
                    };
                    let status = match status {
                        common::VerifiedProxyAuthStatus::Active { username } => {
                            VerifiedProxyAuthStatus {
                                username,
                                status: AgentAuthAccountStatus::Active,
                            }
                        }
                        common::VerifiedProxyAuthStatus::UserExpired { username } => {
                            VerifiedProxyAuthStatus {
                                username,
                                status: AgentAuthAccountStatus::Expired,
                            }
                        }
                        common::VerifiedProxyAuthStatus::UserDisabled { username } => {
                            VerifiedProxyAuthStatus {
                                username,
                                status: AgentAuthAccountStatus::Disabled,
                            }
                        }
                    };
                    if let Err(error) = runtime.set_verified_proxy_auth_status(status) {
                        runtime
                            .logs
                            .push(format!("保存 Proxy 账号状态失败：{error}"));
                    }
                }
            });
        })
        .map_err(|error| error.to_string())
}

fn set_service_status(
    status_handle: &service_control_handler::ServiceStatusHandle,
    current_state: ServiceState,
) -> Result<(), String> {
    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(2),
            process_id: None,
        })
        .map_err(|err| format!("设置 Windows Service 状态失败：{err}"))
}

fn run_service_ipc(runtime: Arc<AgentRuntime>, shutdown: CancellationToken) {
    let async_runtime = match Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            runtime
                .logs
                .push(format!("初始化服务 IPC runtime 失败：{err}"));
            return;
        }
    };

    async_runtime.block_on(run_service_ipc_async(runtime, shutdown));
}

async fn run_service_ipc_async(runtime: Arc<AgentRuntime>, shutdown: CancellationToken) {
    let listener = match TcpListener::bind(SERVICE_IPC_ADDR).await {
        Ok(listener) => listener,
        Err(err) => {
            runtime.logs.push(format!("服务 IPC 监听失败：{err}"));
            return;
        }
    };
    runtime
        .logs
        .push(format!("服务 IPC 已监听：{SERVICE_IPC_ADDR}"));
    let mutation_lock = Arc::new(Mutex::new(()));

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        let connection_runtime = runtime.clone();
                        let connection_mutation_lock = mutation_lock.clone();
                        tokio::spawn(async move {
                            respond_to_service_request(
                                connection_runtime,
                                connection_mutation_lock,
                                stream,
                            )
                            .await;
                        });
                    }
                    Err(err) => runtime.logs.push(format!("服务 IPC 接收失败：{err}")),
                }
            }
        }
    }
}

async fn respond_to_service_request(
    runtime: Arc<AgentRuntime>,
    mutation_lock: Arc<Mutex<()>>,
    mut stream: TcpStream,
) {
    let response = read_and_handle_service_request(runtime, mutation_lock, &mut stream).await;
    let payload = serde_json::to_vec(&response).unwrap_or_else(|err| {
        format!(
            "{{\"ok\":false,\"state\":null,\"traffic\":null,\"error\":\"编码响应失败：{err}\"}}"
        )
        .into_bytes()
    });
    let _ = timeout(SERVICE_IPC_IO_TIMEOUT, stream.write_all(&payload)).await;
    let _ = timeout(SERVICE_IPC_IO_TIMEOUT, stream.shutdown()).await;
}

async fn read_and_handle_service_request(
    runtime: Arc<AgentRuntime>,
    mutation_lock: Arc<Mutex<()>>,
    stream: &mut TcpStream,
) -> ServiceResponse {
    let mut payload = Vec::new();
    match timeout(
        SERVICE_IPC_IO_TIMEOUT,
        stream
            .take(MAX_SERVICE_IPC_REQUEST_BYTES + 1)
            .read_to_end(&mut payload),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(err)) => return service_error(format!("读取服务请求失败：{err}")),
        Err(_) => return service_error("读取服务请求超时".to_string()),
    }
    if payload.len() as u64 > MAX_SERVICE_IPC_REQUEST_BYTES {
        return service_error("服务请求过大，已拒绝处理".to_string());
    }

    let mut envelope = match serde_json::from_slice::<ServiceRequestEnvelope>(&payload) {
        Ok(envelope) => envelope,
        Err(err) => return service_error(format!("解析服务请求失败：{err}")),
    };
    let authorization = authorize_service_request(&envelope.auth_token);
    envelope.auth_token.zeroize();
    if authorization.is_err() {
        return service_error("Windows Service 请求未授权，请重新登录".to_string());
    }
    let request = envelope.request;

    let is_mutating = service_request_is_mutating(&request);
    match task::spawn_blocking(move || {
        if is_mutating {
            let Ok(_guard) = mutation_lock.lock() else {
                return service_error("Agent 服务操作锁已损坏".to_string());
            };
            handle_service_request(&runtime, request)
        } else {
            handle_service_request(&runtime, request)
        }
    })
    .await
    {
        Ok(response) => response,
        Err(err) => service_error(format!("处理服务请求失败：{err}")),
    }
}

fn authorize_service_request(auth_token: &str) -> Result<(), String> {
    validate_service_token_format(auth_token)?;
    let authorization = service_session_authorization()?;
    if constant_time_token_eq(auth_token.as_bytes(), authorization.token.as_bytes()) {
        Ok(())
    } else {
        Err("Windows Service 会话令牌不匹配".to_string())
    }
}

fn service_session_authorization() -> Result<ServiceSessionAuthorization, String> {
    let config_root = SERVICE_CONFIG_ROOT
        .get()
        .ok_or_else(|| "Windows Service 未配置受管 Agent 数据目录".to_string())?;
    read_service_session_authorization(&service_session_file_path_for_root(config_root)?)
}

fn read_service_session_authorization(path: &Path) -> Result<ServiceSessionAuthorization, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| "Windows Service 会话不存在或已经退出".to_string())?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_SERVICE_SESSION_FILE_BYTES {
        return Err("Windows Service 会话文件无效".to_string());
    }
    let mut raw = fs::read(path).map_err(|_| "无法读取 Windows Service 会话".to_string())?;
    let parsed = serde_json::from_slice::<ServiceSessionAuthorization>(&raw)
        .map_err(|_| "Windows Service 会话格式无效".to_string());
    raw.zeroize();
    let authorization = parsed?;
    if authorization.version != SERVICE_SESSION_FILE_VERSION {
        return Err("Windows Service 会话版本无效".to_string());
    }
    validate_service_token_format(&authorization.token)?;
    Ok(authorization)
}

fn service_session_file_path_for_root(config_root: &Path) -> Result<PathBuf, String> {
    Ok(service_credentials_dir_for_root(config_root)?.join(SERVICE_SESSION_FILE_NAME))
}

fn service_desired_state_file_path_for_root(config_root: &Path) -> Result<PathBuf, String> {
    Ok(service_credentials_dir_for_root(config_root)?.join(SERVICE_DESIRED_STATE_FILE_NAME))
}

fn service_credentials_dir_for_root(config_root: &Path) -> Result<PathBuf, String> {
    let roaming_or_local = config_root
        .parent()
        .ok_or_else(|| "Windows Service 受管目录缺少 AppData 类型目录".to_string())?;
    let app_data = roaming_or_local
        .parent()
        .ok_or_else(|| "Windows Service 受管目录缺少 AppData 目录".to_string())?;
    Ok(app_data
        .join("Local")
        .join("com.ppaass.agent")
        .join("credentials"))
}

fn service_desired_running() -> Result<Option<ServiceLoginBinding>, String> {
    let config_root = SERVICE_CONFIG_ROOT
        .get()
        .ok_or_else(|| "Windows Service 未配置受管 Agent 数据目录".to_string())?;
    read_service_desired_state(&service_desired_state_file_path_for_root(config_root)?)
}

fn read_service_desired_state(path: &Path) -> Result<Option<ServiceLoginBinding>, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("读取 Windows Service 运行状态元数据失败：{error}")),
    };
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_SERVICE_DESIRED_STATE_FILE_BYTES
    {
        return Err("Windows Service 运行状态文件无效".to_string());
    }
    let state = serde_json::from_slice::<ServiceDesiredState>(
        &fs::read(path).map_err(|error| format!("读取 Windows Service 运行状态失败：{error}"))?,
    )
    .map_err(|_| "Windows Service 运行状态格式无效".to_string())?;
    if state.version != SERVICE_DESIRED_STATE_FILE_VERSION {
        return Err("Windows Service 运行状态版本无效".to_string());
    }
    match (state.desired_running, state.username, state.key_version) {
        (false, None, None) => Ok(None),
        (true, Some(username), Some(key_version))
            if !username.trim().is_empty() && key_version >= 1 =>
        {
            Ok(Some(ServiceLoginBinding {
                username,
                key_version,
            }))
        }
        _ => Err("Windows Service 运行状态与登录绑定不一致".to_string()),
    }
}

fn persist_service_desired_running(
    login_binding: Option<&ServiceLoginBinding>,
) -> Result<(), String> {
    let config_root = SERVICE_CONFIG_ROOT
        .get()
        .ok_or_else(|| "Windows Service 未配置受管 Agent 数据目录".to_string())?;
    persist_service_desired_state(
        &service_desired_state_file_path_for_root(config_root)?,
        login_binding,
    )
}

fn persist_service_desired_state(
    path: &Path,
    login_binding: Option<&ServiceLoginBinding>,
) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "Windows Service 运行状态文件缺少父目录".to_string())?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("Windows Service 受管凭据目录不可用：{error}"))?;
    if !parent_metadata.file_type().is_dir() {
        return Err("Windows Service 受管凭据目录无效".to_string());
    }
    if let Ok(existing) = fs::symlink_metadata(path) {
        if !existing.file_type().is_file() {
            return Err("Windows Service 运行状态文件不是普通文件".to_string());
        }
    }

    let state = ServiceDesiredState {
        version: SERVICE_DESIRED_STATE_FILE_VERSION,
        desired_running: login_binding.is_some(),
        username: login_binding.map(|binding| binding.username.clone()),
        key_version: login_binding.map(|binding| binding.key_version),
    };
    let serialized = serde_json::to_vec(&state)
        .map_err(|error| format!("编码 Windows Service 运行状态失败：{error}"))?;
    let mut temporary = TempFileBuilder::new()
        .prefix(".service-runtime-state-")
        .tempfile_in(parent)
        .map_err(|error| format!("创建 Windows Service 运行状态临时文件失败：{error}"))?;
    // The login flow restricts the credentials directory to the signed-in user
    // and SYSTEM. A file created by the SYSTEM service inherits that exact ACL;
    // recomputing it as SYSTEM would accidentally remove the user's access.
    temporary
        .write_all(&serialized)
        .map_err(|error| format!("写入 Windows Service 运行状态失败：{error}"))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| format!("同步 Windows Service 运行状态失败：{error}"))?;
    temporary
        .persist(path)
        .map_err(|error| format!("保存 Windows Service 运行状态失败：{}", error.error))?;
    if let Ok(directory) = fs::File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

fn validate_service_token_format(token: &str) -> Result<(), String> {
    if token.len() == SERVICE_SESSION_TOKEN_HEX_LEN
        && token.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        Ok(())
    } else {
        Err("Windows Service 会话令牌格式无效".to_string())
    }
}

fn constant_time_token_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn service_request_is_mutating(request: &ServiceRequest) -> bool {
    matches!(
        request,
        ServiceRequest::Start { .. }
            | ServiceRequest::Stop
            | ServiceRequest::SetLogLevel { .. }
            | ServiceRequest::SetPacketCapture { .. }
            | ServiceRequest::ClearPacketCapture { .. }
    )
}

fn handle_service_request(runtime: &AgentRuntime, request: ServiceRequest) -> ServiceResponse {
    match request {
        ServiceRequest::Start { config_path } => match start_service_agent(runtime, &config_path) {
            Ok(state) => service_state_ok(runtime, state),
            Err(err) => service_error(err),
        },
        ServiceRequest::Stop => match stop_service_agent(runtime) {
            Ok(state) => service_state_ok(runtime, state),
            Err(err) => service_error(err),
        },
        ServiceRequest::State => match agent_state(runtime) {
            Ok(state) => service_state_ok(runtime, state),
            Err(err) => service_error(err),
        },
        ServiceRequest::Traffic => ServiceResponse {
            ok: true,
            state: None,
            traffic: Some(agent_traffic_snapshot()),
            dns_records: None,
            packet_capture: None,
            auth_status: None,
            error: None,
        },
        ServiceRequest::DnsRecords => ServiceResponse {
            ok: true,
            state: None,
            traffic: None,
            dns_records: Some(desktop_agent_be::telemetry::dns_resolution_records()),
            packet_capture: None,
            auth_status: None,
            error: None,
        },
        ServiceRequest::SetLogLevel { log_level } => match runtime.logs.set_log_level(&log_level) {
            Ok(()) => match agent_state(runtime) {
                Ok(state) => service_state_ok(runtime, state),
                Err(err) => service_error(err),
            },
            Err(err) => service_error(err),
        },
        ServiceRequest::PacketCaptureStatus => {
            service_packet_capture_result(packet_capture_runtime_status_local(runtime))
        }
        ServiceRequest::SetPacketCapture { enabled } => service_packet_capture_result(
            set_packet_capture_runtime_enabled_local(runtime, enabled),
        ),
        ServiceRequest::ClearPacketCapture { config_path } => {
            let requested_path = config_path.unwrap_or_else(service_root_config_path);
            match validate_service_config_path(&requested_path) {
                Ok(config_path) => {
                    service_packet_capture_result(clear_packet_capture_runtime_local(
                        runtime,
                        Some(config_path.to_string_lossy().to_string()),
                    ))
                }
                Err(error) => service_error(error),
            }
        }
    }
}

fn start_service_agent(runtime: &AgentRuntime, config_path: &str) -> Result<AgentState, String> {
    let (config_path, login_binding) = validate_authorized_service_config_path(config_path)?;
    let state = start_agent_inner(runtime, config_path, false)?;
    if !state.running {
        return Err("Windows Service 启动 Agent 后未进入运行状态".to_string());
    }
    if let Err(persist_error) = persist_service_desired_running(Some(&login_binding)) {
        return match stop_embedded_agent(runtime) {
            Ok(()) => Err(format!(
                "无法持久保存 Agent 运行请求，已回滚本次启动：{persist_error}"
            )),
            Err(stop_error) => Err(format!(
                "无法持久保存 Agent 运行请求（{persist_error}），且回滚 Agent 失败（{stop_error}）"
            )),
        };
    }
    Ok(state)
}

fn stop_service_agent(runtime: &AgentRuntime) -> Result<AgentState, String> {
    // Persist the user's explicit stop before touching the running process. If
    // the Service crashes at any later point it must never resurrect an Agent
    // that the user already asked to stop.
    persist_service_desired_running(None)?;
    stop_embedded_agent(runtime)?;
    agent_state(runtime)
}

fn validate_service_config_path(config_path: &str) -> Result<PathBuf, String> {
    let config_root = SERVICE_CONFIG_ROOT
        .get()
        .ok_or_else(|| "Windows Service 未配置受管 Agent 数据目录".to_string())?;
    validate_service_config_path_for_root(config_path, config_root)
}

fn validate_authorized_service_config_path(
    config_path: &str,
) -> Result<(PathBuf, ServiceLoginBinding), String> {
    let config_root = SERVICE_CONFIG_ROOT
        .get()
        .ok_or_else(|| "Windows Service 未配置受管 Agent 数据目录".to_string())?;
    let canonical = validate_service_config_path_for_root(config_path, config_root)?;
    let app_data_dir = canonical
        .parent()
        .ok_or_else(|| "Windows Service Agent 配置缺少父目录".to_string())?;
    let raw = fs::read_to_string(&canonical)
        .map_err(|error| format!("读取 Windows Service Agent 配置失败：{error}"))?;
    let config = toml::from_str::<toml::Value>(&raw)
        .map_err(|error| format!("Windows Service Agent 配置格式无效：{error}"))?;

    let credentials_dir = service_credentials_dir_for_root(config_root)?;
    let persisted = load_persisted_agent_login_from_dir(&credentials_dir)?
        .ok_or_else(|| "Windows Service 找不到持久登录授权，请重新登录".to_string())?;
    let config_username = service_config_string(&config, &["username"]).unwrap_or_default();
    if config_username != persisted.account.username {
        return Err("Windows Service 配置用户与持久登录用户不一致".to_string());
    }

    let configured_private_key = service_config_string(&config, &["private_key_path"])
        .ok_or_else(|| "Windows Service Agent 配置缺少托管私钥，请先登录".to_string())?;
    let configured_proxy_identity =
        service_config_string(&config, &["proxy_identity_public_key_path"]).ok_or_else(|| {
            "Windows Service Agent 配置缺少托管 Proxy 身份公钥，请先登录".to_string()
        })?;
    ensure_same_canonical_path(
        &resolve_configured_path(app_data_dir, configured_private_key),
        &persisted.private_key_path,
        "私钥",
    )?;
    ensure_same_canonical_path(
        &resolve_configured_path(app_data_dir, configured_proxy_identity),
        &persisted.proxy_identity_public_key_path,
        "Proxy 身份公钥",
    )?;

    Ok((
        canonical,
        ServiceLoginBinding {
            username: persisted.account.username,
            key_version: persisted.account.key_version,
        },
    ))
}

fn resolve_configured_path(app_data_dir: &Path, configured_path: &str) -> PathBuf {
    let configured_path = Path::new(configured_path);
    if configured_path.is_absolute() {
        configured_path.to_path_buf()
    } else {
        app_data_dir.join(configured_path)
    }
}

fn ensure_same_canonical_path(
    configured: &Path,
    persisted: &Path,
    credential_name: &str,
) -> Result<(), String> {
    let configured = fs::canonicalize(configured)
        .map_err(|error| format!("无法定位 Windows Service 配置中的{credential_name}：{error}"))?;
    let persisted = fs::canonicalize(persisted)
        .map_err(|error| format!("无法定位 Windows Service 持久登录{credential_name}：{error}"))?;
    if normalized_path_for_compare(&configured) != normalized_path_for_compare(&persisted) {
        return Err(format!(
            "Windows Service 配置中的{credential_name}与持久登录凭据不一致"
        ));
    }
    Ok(())
}

fn validate_service_config_path_for_root(
    config_path: &str,
    config_root: &Path,
) -> Result<PathBuf, String> {
    let (canonical, app_data_dir) = canonical_managed_config_path(config_path)?;
    let expected_root = canonical_managed_config_root_dir(config_root)?;
    if normalized_path_for_compare(&app_data_dir) != normalized_path_for_compare(&expected_root) {
        return Err("Windows Service Agent 配置不属于当前受管用户".to_string());
    }

    let raw = fs::read_to_string(&canonical)
        .map_err(|err| format!("读取 Windows Service Agent 配置失败：{err}"))?;
    let config = toml::from_str::<toml::Value>(&raw)
        .map_err(|err| format!("Windows Service Agent 配置格式无效：{err}"))?;
    let username = service_config_string(&config, &["username"]).unwrap_or_default();
    if username.trim().is_empty() {
        return Err("Windows Service Agent 配置缺少托管用户名，请先登录".to_string());
    }
    let private_key_path = service_config_string(&config, &["private_key_path"])
        .ok_or_else(|| "Windows Service Agent 配置缺少托管私钥，请先登录".to_string())?;
    validate_managed_private_key_path(&app_data_dir, private_key_path)?;
    let proxy_identity_public_key_path =
        service_config_string(&config, &["proxy_identity_public_key_path"]).ok_or_else(|| {
            "Windows Service Agent 配置缺少托管 Proxy 身份公钥，请先登录".to_string()
        })?;
    validate_managed_proxy_identity_public_key_path(&app_data_dir, proxy_identity_public_key_path)?;

    if let Some(configured_wintun) = service_config_string(&config, &["tun", "wintun_file"]) {
        let trusted_wintun = trusted_windows_wintun_path()?;
        let configured_is_legacy_name = configured_wintun.eq_ignore_ascii_case("wintun.dll");
        let configured_is_trusted_absolute = Path::new(configured_wintun).is_absolute()
            && fs::canonicalize(configured_wintun).is_ok_and(|path| {
                normalized_path_for_compare(&path) == normalized_path_for_compare(&trusted_wintun)
            });
        if !configured_is_legacy_name && !configured_is_trusted_absolute {
            return Err("Windows Service 只允许使用可信安装目录中的 wintun.dll".to_string());
        }
    }

    for path in [
        &["log_dir"][..],
        &["log_file"][..],
        &["tun", "route_state_file"][..],
        &["tun", "dns_state_file"][..],
        &["tun", "packet_capture", "file"][..],
    ] {
        if let Some(value) = service_config_string(&config, path) {
            validate_service_managed_path(&app_data_dir, value)?;
        }
    }
    Ok(canonical)
}

fn canonical_managed_config_path(config_path: &str) -> Result<(PathBuf, PathBuf), String> {
    let canonical = fs::canonicalize(config_path)
        .map_err(|err| format!("无法定位 Windows Service Agent 配置：{err}"))?;
    if canonical.file_name().and_then(|value| value.to_str()) != Some("agent.toml") {
        return Err("Windows Service 只允许使用 AppData 根 agent.toml".to_string());
    }
    let app_data_dir = canonical
        .parent()
        .ok_or_else(|| "Windows Service Agent 配置缺少父目录".to_string())?
        .to_path_buf();
    if !is_expected_windows_app_data_dir(&app_data_dir) {
        return Err("Windows Service Agent 配置不在受管 AppData 目录".to_string());
    }
    Ok((canonical, app_data_dir))
}

fn canonical_managed_config_root_dir(config_root: &Path) -> Result<PathBuf, String> {
    let canonical = fs::canonicalize(config_root)
        .map_err(|err| format!("无法定位 Windows Service 受管配置目录：{err}"))?;
    if !is_expected_windows_app_data_dir(&canonical) {
        return Err("Windows Service 受管配置目录不是 Agent AppData".to_string());
    }
    Ok(canonical)
}

fn service_root_config_path() -> String {
    SERVICE_CONFIG_ROOT
        .get()
        .map(|root| root.join("agent.toml").to_string_lossy().to_string())
        .unwrap_or_default()
}

fn is_expected_windows_app_data_dir(path: &Path) -> bool {
    if !path
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("com.ppaass.agent"))
    {
        return false;
    }
    let Some(roaming_or_local) = path.parent() else {
        return false;
    };
    if !roaming_or_local
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|value| {
            value.eq_ignore_ascii_case("Roaming") || value.eq_ignore_ascii_case("Local")
        })
    {
        return false;
    }
    roaming_or_local
        .parent()
        .and_then(Path::file_name)
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("AppData"))
}

fn validate_managed_private_key_path(
    app_data_dir: &Path,
    configured_path: &str,
) -> Result<(), String> {
    let configured = Path::new(configured_path);
    let candidate = if configured.is_absolute() {
        configured.to_path_buf()
    } else {
        app_data_dir.join(configured)
    };
    let canonical_key = fs::canonicalize(&candidate)
        .map_err(|err| format!("无法定位 Windows Service 托管私钥：{err}"))?;
    let canonical_credentials = canonical_windows_credentials_dirs(app_data_dir);
    if !canonical_credentials
        .iter()
        .any(|directory| canonical_key.parent() == Some(directory.as_path()))
        || !canonical_key
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.starts_with("managed-") && value.ends_with(".pem"))
    {
        return Err("Windows Service 私钥必须来自受管 credentials 目录".to_string());
    }
    Ok(())
}

fn validate_managed_proxy_identity_public_key_path(
    app_data_dir: &Path,
    configured_path: &str,
) -> Result<(), String> {
    let configured = Path::new(configured_path);
    if configured.file_name().and_then(|value| value.to_str())
        != Some(MANAGED_PROXY_IDENTITY_PUBLIC_KEY_FILE)
    {
        return Err(
            "Windows Service Proxy 身份公钥文件名必须为 proxy-identity-public.pem".to_string(),
        );
    }

    let candidate = if configured.is_absolute() {
        configured.to_path_buf()
    } else {
        app_data_dir.join(configured)
    };

    // Reject an arbitrary absolute/UNC location before canonicalization. The
    // service runs elevated, so even probing a user-selected network or local
    // path would unnecessarily expand its privileged filesystem surface.
    let candidate_parent = candidate
        .parent()
        .ok_or_else(|| "Windows Service Proxy 身份公钥路径缺少父目录".to_string())?;
    if !windows_credentials_dir_candidates(app_data_dir)
        .iter()
        .any(|directory| {
            lexical_path_for_compare(candidate_parent) == lexical_path_for_compare(directory)
        })
    {
        return Err("Windows Service Proxy 身份公钥必须来自受管 credentials 目录".to_string());
    }

    let canonical_credentials = canonical_windows_credentials_dirs(app_data_dir);
    if canonical_credentials.is_empty() {
        return Err("Windows Service 无法定位受管 credentials 目录".to_string());
    }
    let canonical_key = fs::canonicalize(&candidate)
        .map_err(|err| format!("无法定位 Windows Service Proxy 身份公钥：{err}"))?;
    let metadata = fs::metadata(&canonical_key)
        .map_err(|err| format!("无法读取 Windows Service Proxy 身份公钥元数据：{err}"))?;
    if !metadata.is_file()
        || canonical_key.file_name().and_then(|value| value.to_str())
            != Some(MANAGED_PROXY_IDENTITY_PUBLIC_KEY_FILE)
        || !canonical_credentials
            .iter()
            .any(|directory| canonical_key.parent() == Some(directory.as_path()))
    {
        return Err(
            "Windows Service Proxy 身份公钥必须是受管 credentials 目录中的固定文件".to_string(),
        );
    }
    Ok(())
}

fn windows_credentials_dir_candidates(app_data_dir: &Path) -> Vec<PathBuf> {
    let mut roots = vec![app_data_dir.to_path_buf()];
    let Some(roaming_or_local) = app_data_dir.parent() else {
        return Vec::new();
    };
    let Some(app_data) = roaming_or_local.parent() else {
        return Vec::new();
    };
    roots.push(app_data.join("Local").join("com.ppaass.agent"));
    roots
        .into_iter()
        .map(|root| root.join("credentials"))
        .collect()
}

fn canonical_windows_credentials_dirs(app_data_dir: &Path) -> Vec<PathBuf> {
    windows_credentials_dir_candidates(app_data_dir)
        .into_iter()
        .filter_map(|credentials| {
            let root = canonical_managed_config_root_dir(credentials.parent()?).ok()?;
            let credentials = fs::canonicalize(root.join("credentials")).ok()?;
            (credentials.parent().is_some_and(|parent| {
                normalized_path_for_compare(parent) == normalized_path_for_compare(&root)
            }))
            .then_some(credentials)
        })
        .collect()
}

fn lexical_path_for_compare(path: &Path) -> String {
    path.to_string_lossy()
        .replace('/', "\\")
        .trim_start_matches(r"\\?\")
        .to_lowercase()
}

fn validate_service_managed_path(app_data_dir: &Path, value: &str) -> Result<(), String> {
    validate_service_relative_path(value)?;

    let canonical_root = canonical_managed_config_root_dir(app_data_dir)?;
    let candidate = app_data_dir.join(value);
    let mut existing_ancestor = candidate.as_path();
    while !existing_ancestor.exists() {
        existing_ancestor = existing_ancestor
            .parent()
            .ok_or_else(|| "Windows Service 配置中的路径无法定位".to_string())?;
    }
    let canonical_ancestor = fs::canonicalize(existing_ancestor)
        .map_err(|err| format!("定位 Windows Service 配置路径失败：{err}"))?;
    if !normalized_path_is_within(&canonical_ancestor, &canonical_root) {
        return Err("Windows Service 配置中的路径通过链接逃逸 Agent AppData".to_string());
    }
    Ok(())
}

fn normalized_path_is_within(path: &Path, root: &Path) -> bool {
    let path = normalized_path_for_compare(path);
    let root = normalized_path_for_compare(root);
    path == root || path.starts_with(&format!("{root}\\"))
}

fn validate_service_relative_path(value: &str) -> Result<(), String> {
    let path = Path::new(value);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::Prefix(_) | Component::RootDir
            )
        })
    {
        return Err("Windows Service 配置中的输出路径必须位于 Agent AppData 内".to_string());
    }
    Ok(())
}

fn service_config_string<'a>(value: &'a toml::Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str()
}

fn service_packet_capture_result(
    result: Result<crate::models::PacketCaptureRuntimeStatus, String>,
) -> ServiceResponse {
    match result {
        Ok(status) => ServiceResponse {
            ok: true,
            state: None,
            traffic: None,
            dns_records: None,
            packet_capture: Some(status),
            auth_status: None,
            error: None,
        },
        Err(error) => service_error(error),
    }
}

fn service_state_ok(runtime: &AgentRuntime, state: AgentState) -> ServiceResponse {
    ServiceResponse {
        ok: true,
        state: Some(state),
        traffic: None,
        dns_records: None,
        packet_capture: None,
        auth_status: runtime.verified_proxy_auth_status().ok().flatten(),
        error: None,
    }
}

fn service_error(error: String) -> ServiceResponse {
    ServiceResponse {
        ok: false,
        state: None,
        traffic: None,
        dns_records: None,
        packet_capture: None,
        auth_status: None,
        error: Some(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_handles_capture_status_locally_without_recursive_ipc() {
        let runtime = AgentRuntime::new();

        let response = handle_service_request(&runtime, ServiceRequest::PacketCaptureStatus);

        assert!(response.ok);
        let status = response.packet_capture.expect("capture status");
        assert!(!status.available);
        assert!(!status.enabled);
    }

    #[test]
    fn service_returns_dns_records_from_its_own_agent_process() {
        let runtime = AgentRuntime::new();

        let response = handle_service_request(&runtime, ServiceRequest::DnsRecords);

        assert!(response.ok);
        assert!(response.dns_records.is_some());
    }

    #[test]
    fn service_reports_typed_verified_proxy_account_status() {
        let runtime = AgentRuntime::new();
        runtime
            .set_verified_proxy_auth_status(VerifiedProxyAuthStatus {
                username: "alice".to_string(),
                status: AgentAuthAccountStatus::Expired,
            })
            .unwrap();

        let response = handle_service_request(&runtime, ServiceRequest::State);
        assert_eq!(
            response.auth_status,
            Some(VerifiedProxyAuthStatus {
                username: "alice".to_string(),
                status: AgentAuthAccountStatus::Expired,
            })
        );

        runtime
            .set_verified_proxy_auth_status(VerifiedProxyAuthStatus {
                username: "alice".to_string(),
                status: AgentAuthAccountStatus::Active,
            })
            .unwrap();
        let response = handle_service_request(&runtime, ServiceRequest::State);
        assert_eq!(
            response.auth_status,
            Some(VerifiedProxyAuthStatus {
                username: "alice".to_string(),
                status: AgentAuthAccountStatus::Active,
            })
        );
    }

    #[test]
    fn only_state_changing_service_requests_are_serialized() {
        assert!(service_request_is_mutating(&ServiceRequest::Start {
            config_path: "agent.toml".to_string(),
        }));
        assert!(service_request_is_mutating(&ServiceRequest::Stop));
        assert!(service_request_is_mutating(
            &ServiceRequest::SetPacketCapture { enabled: true }
        ));
        assert!(!service_request_is_mutating(&ServiceRequest::State));
        assert!(!service_request_is_mutating(&ServiceRequest::Traffic));
        assert!(!service_request_is_mutating(&ServiceRequest::DnsRecords));
        assert!(!service_request_is_mutating(
            &ServiceRequest::PacketCaptureStatus
        ));
    }

    #[test]
    fn service_paths_reject_escape_and_accept_managed_app_data_config() {
        assert!(validate_service_relative_path("captures/agent.pcap").is_ok());
        assert!(validate_service_relative_path("../outside.pcap").is_err());
        assert!(validate_service_relative_path(r"C:\Windows\outside.pcap").is_err());
        assert!(validate_service_relative_path(r"\Windows\outside.pcap").is_err());

        let temp = tempfile::tempdir().unwrap();
        let app_data = temp
            .path()
            .join("AppData")
            .join("Roaming")
            .join("com.ppaass.agent");
        fs::create_dir_all(&app_data).unwrap();
        let credentials = temp
            .path()
            .join("AppData")
            .join("Local")
            .join("com.ppaass.agent")
            .join("credentials");
        fs::create_dir_all(&credentials).unwrap();
        let key = credentials.join("managed-616c696365-v1.pem");
        fs::write(&key, "managed test key").unwrap();
        let proxy_identity = credentials.join(MANAGED_PROXY_IDENTITY_PUBLIC_KEY_FILE);
        fs::write(&proxy_identity, "managed proxy identity").unwrap();
        let config = app_data.join("agent.toml");
        let escaped_key = key.to_string_lossy().replace('\\', "\\\\");
        let escaped_proxy_identity = proxy_identity.to_string_lossy().replace('\\', "\\\\");
        fs::write(
            &config,
            format!(
                "username = \"alice\"\nprivate_key_path = \"{escaped_key}\"\n\
                 proxy_identity_public_key_path = \"{escaped_proxy_identity}\"\n\
                 log_dir = \"logs\"\n"
            ),
        )
        .unwrap();

        assert!(validate_service_config_path_for_root(config.to_str().unwrap(), &app_data).is_ok());

        let other_app_data = temp
            .path()
            .join("Other")
            .join("AppData")
            .join("Local")
            .join("com.ppaass.agent");
        fs::create_dir_all(&other_app_data).unwrap();
        assert!(
            validate_service_config_path_for_root(config.to_str().unwrap(), &other_app_data)
                .is_err()
        );

        fs::write(
            &config,
            format!(
                "username = \"alice\"\nprivate_key_path = \"{escaped_key}\"\n\
                 proxy_identity_public_key_path = \"{escaped_proxy_identity}\"\n\
                 log_dir = \"..\\\\outside\"\n"
            ),
        )
        .unwrap();
        assert!(
            validate_service_config_path_for_root(config.to_str().unwrap(), &app_data).is_err()
        );

        let outside = temp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        let linked_capture_dir = app_data.join("linked-captures");
        if std::os::windows::fs::symlink_dir(&outside, &linked_capture_dir).is_ok() {
            assert!(
                validate_service_managed_path(&app_data, "linked-captures/agent.pcap").is_err()
            );
        }
    }

    #[test]
    fn service_requires_proxy_identity_pin_from_managed_credentials() {
        let temp = tempfile::tempdir().unwrap();
        let app_data = temp
            .path()
            .join("AppData")
            .join("Roaming")
            .join("com.ppaass.agent");
        let credentials = temp
            .path()
            .join("AppData")
            .join("Local")
            .join("com.ppaass.agent")
            .join("credentials");
        fs::create_dir_all(&app_data).unwrap();
        fs::create_dir_all(&credentials).unwrap();

        let private_key = credentials.join("managed-616c696365-v1.pem");
        fs::write(&private_key, "managed test key").unwrap();
        let proxy_identity = credentials.join(MANAGED_PROXY_IDENTITY_PUBLIC_KEY_FILE);
        fs::write(&proxy_identity, "managed proxy identity").unwrap();
        let outside_dir = temp.path().join("outside");
        fs::create_dir_all(&outside_dir).unwrap();
        let outside_identity = outside_dir.join(MANAGED_PROXY_IDENTITY_PUBLIC_KEY_FILE);
        fs::write(&outside_identity, "unmanaged proxy identity").unwrap();

        let config = app_data.join("agent.toml");
        let escaped_private_key = private_key.to_string_lossy().replace('\\', "\\\\");
        let escaped_proxy_identity = proxy_identity.to_string_lossy().replace('\\', "\\\\");
        let escaped_outside_identity = outside_identity.to_string_lossy().replace('\\', "\\\\");

        fs::write(
            &config,
            format!("username = \"alice\"\nprivate_key_path = \"{escaped_private_key}\"\n"),
        )
        .unwrap();
        assert!(
            validate_service_config_path_for_root(config.to_str().unwrap(), &app_data)
                .unwrap_err()
                .contains("缺少托管 Proxy 身份公钥")
        );

        fs::write(
            &config,
            format!(
                "username = \"alice\"\nprivate_key_path = \"{escaped_private_key}\"\n\
                 proxy_identity_public_key_path = \"{escaped_outside_identity}\"\n"
            ),
        )
        .unwrap();
        assert!(
            validate_service_config_path_for_root(config.to_str().unwrap(), &app_data).is_err()
        );

        fs::write(
            &config,
            format!(
                "username = \"alice\"\nprivate_key_path = \"{escaped_private_key}\"\n\
                 proxy_identity_public_key_path = \"{escaped_proxy_identity}\"\n"
            ),
        )
        .unwrap();
        assert!(validate_service_config_path_for_root(config.to_str().unwrap(), &app_data).is_ok());
    }

    #[test]
    fn service_command_extracts_pinned_config_root() {
        let command = concat!(
            r#""C:\Program Files\PPAASS\PPAASS Agent.exe" --ppaass-agent-service "#,
            r#"--ppaass-service-config-root "C:\Users\Alice\AppData\Local\com.ppaass.agent""#
        );
        assert_eq!(
            extract_command_argument_path(command, SERVICE_CONFIG_ROOT_ARG).as_deref(),
            Some(r"C:\Users\Alice\AppData\Local\com.ppaass.agent")
        );
        assert_eq!(
            extract_command_argument_path(
                "--ppaass-service-config-root C:\\AgentData --ppaass-agent-service",
                SERVICE_CONFIG_ROOT_ARG,
            )
            .as_deref(),
            Some(r"C:\AgentData")
        );
        assert!(extract_command_argument_path(command, "--missing").is_none());
        assert!(normalized_path_is_within(
            Path::new(r"C:\Users\Alice\AppData\Local\com.ppaass.agent\captures"),
            Path::new(r"c:\users\alice\appdata\local\com.ppaass.agent")
        ));
        assert!(!normalized_path_is_within(
            Path::new(r"C:\Users\Alice\AppData\Local\com.ppaass.agent-copy"),
            Path::new(r"C:\Users\Alice\AppData\Local\com.ppaass.agent")
        ));
        assert!(sc_service_is_auto_start(
            "START_TYPE         : 2   AUTO_START"
        ));
        assert!(!sc_service_is_auto_start(
            "START_TYPE         : 3   DEMAND_START"
        ));
    }

    #[test]
    fn service_request_encoder_rejects_oversized_payloads() {
        let request = ServiceRequest::Start {
            config_path: "a".repeat(MAX_SERVICE_IPC_REQUEST_BYTES as usize),
        };
        assert!(
            encode_service_request(&request, &"a".repeat(SERVICE_SESSION_TOKEN_HEX_LEN)).is_err()
        );
    }

    #[test]
    fn service_request_envelope_requires_a_well_formed_secret() {
        let request = ServiceRequest::State;
        assert!(encode_service_request(&request, "short").is_err());

        let token = "ab".repeat(SERVICE_SESSION_TOKEN_BYTES);
        let encoded = encode_service_request(&request, &token).unwrap();
        let envelope = serde_json::from_slice::<ServiceRequestEnvelope>(&encoded).unwrap();
        assert_eq!(envelope.auth_token, token);
        assert!(matches!(envelope.request, ServiceRequest::State));
        assert!(constant_time_token_eq(token.as_bytes(), token.as_bytes()));
        assert!(!constant_time_token_eq(
            token.as_bytes(),
            "cd".repeat(SERVICE_SESSION_TOKEN_BYTES).as_bytes()
        ));
    }

    #[test]
    fn service_session_survives_ui_process_exit_and_ignores_local_expiry_metadata() {
        let temp = tempfile::tempdir().unwrap();
        let config_root = temp
            .path()
            .join("AppData")
            .join("Roaming")
            .join("com.ppaass.agent");
        fs::create_dir_all(&config_root).unwrap();
        let session_path = service_session_file_path_for_root(&config_root).unwrap();
        fs::create_dir_all(session_path.parent().unwrap()).unwrap();
        let token = "ab".repeat(SERVICE_SESSION_TOKEN_BYTES);

        let active = ServiceSessionAuthorization {
            version: SERVICE_SESSION_FILE_VERSION,
            token: token.clone(),
            _legacy_ui_process_id: None,
            _legacy_ui_process_creation_time: None,
            _legacy_expires_at: None,
        };
        fs::write(&session_path, serde_json::to_vec(&active).unwrap()).unwrap();
        let loaded = read_service_session_authorization(&session_path).unwrap();
        assert_eq!(loaded.token, token);

        let exited_legacy_ui = ServiceSessionAuthorization {
            version: SERVICE_SESSION_FILE_VERSION,
            token: token.clone(),
            _legacy_ui_process_id: Some(u32::MAX),
            _legacy_ui_process_creation_time: Some(1),
            _legacy_expires_at: None,
        };
        fs::write(
            &session_path,
            serde_json::to_vec(&exited_legacy_ui).unwrap(),
        )
        .unwrap();
        assert!(read_service_session_authorization(&session_path).is_ok());

        let legacy_locally_expired = ServiceSessionAuthorization {
            version: SERVICE_SESSION_FILE_VERSION,
            token,
            _legacy_ui_process_id: Some(u32::MAX),
            _legacy_ui_process_creation_time: Some(1),
            _legacy_expires_at: Some(1),
        };
        fs::write(
            &session_path,
            serde_json::to_vec(&legacy_locally_expired).unwrap(),
        )
        .unwrap();
        assert!(read_service_session_authorization(&session_path).is_ok());
    }

    #[test]
    fn desired_running_state_is_atomic_strict_and_independent_of_local_time() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(SERVICE_DESIRED_STATE_FILE_NAME);
        let alice = ServiceLoginBinding {
            username: "alice".to_string(),
            key_version: 7,
        };

        assert_eq!(read_service_desired_state(&path).unwrap(), None);

        persist_service_desired_state(&path, Some(&alice)).unwrap();
        assert_eq!(
            read_service_desired_state(&path).unwrap(),
            Some(alice.clone())
        );

        persist_service_desired_state(&path, None).unwrap();
        assert_eq!(read_service_desired_state(&path).unwrap(), None);

        fs::write(
            &path,
            br#"{"version":1,"desired_running":true,"username":"alice","key_version":7,"expires_at":1}"#,
        )
        .unwrap();
        assert!(read_service_desired_state(&path).is_err());

        fs::write(
            &path,
            br#"{"version":2,"desired_running":true,"username":"alice","key_version":7}"#,
        )
        .unwrap();
        assert!(read_service_desired_state(&path).is_err());

        fs::write(&path, br#"{"version":1,"desired_running":true}"#).unwrap();
        assert!(read_service_desired_state(&path).is_err());
    }
}
