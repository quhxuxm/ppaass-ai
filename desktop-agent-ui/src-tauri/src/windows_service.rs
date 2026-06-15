#![cfg(windows)]

use std::fs;
use std::net::SocketAddr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Builder;
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
use windows_sys::Win32::UI::Shell::ShellExecuteW;

use crate::agent::{agent_state, start_agent_inner, stop_embedded_agent};
use crate::logging::UiLogBuffer;
use crate::models::{AgentState, ServiceRequest, ServiceResponse};
use crate::runtime::AgentRuntime;
use crate::telemetry::agent_traffic_snapshot;

pub(crate) const SERVICE_ARG: &str = "--ppaass-agent-service";
pub(crate) const INSTALL_SERVICE_ARG: &str = "--ppaass-install-service";

const SERVICE_NAME: &str = "PPAASSAgentService";
const SERVICE_DISPLAY_NAME: &str = "PPAASS Agent Service";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const SERVICE_IPC_ADDR: &str = "127.0.0.1:17981";

define_windows_service!(ffi_service_main, windows_service_main);

pub(crate) fn start_agent_via_windows_service(
    config_path: String,
    logs: &UiLogBuffer,
) -> Result<AgentState, String> {
    ensure_windows_service_available(logs)?;
    let response = send_service_request(&ServiceRequest::Start { config_path })?;
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

pub(crate) fn windows_service_is_running() -> Result<bool, String> {
    let output = run_sc_capture(["query", SERVICE_NAME])?;
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
    let runtime = Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|err| format!("初始化服务 IPC runtime 失败：{err}"))?;
    runtime.block_on(send_service_request_async(request))
}

async fn send_service_request_async(request: &ServiceRequest) -> Result<ServiceResponse, String> {
    let addr = SERVICE_IPC_ADDR
        .parse::<SocketAddr>()
        .map_err(|err| format!("服务 IPC 地址无效：{err}"))?;
    let mut stream = timeout(Duration::from_millis(600), TcpStream::connect(addr))
        .await
        .map_err(|_| "连接 Agent 服务超时".to_string())?
        .map_err(|err| format!("无法连接 Agent 服务：{err}"))?;

    let payload = serde_json::to_vec(request).map_err(|err| format!("编码服务请求失败：{err}"))?;
    timeout(Duration::from_secs(8), stream.write_all(&payload))
        .await
        .map_err(|_| "发送服务请求超时".to_string())?
        .map_err(|err| format!("发送服务请求失败：{err}"))?;
    let _ = stream.shutdown().await;

    let mut response = String::new();
    timeout(Duration::from_secs(8), stream.read_to_string(&mut response))
        .await
        .map_err(|_| "读取服务响应超时".to_string())?
        .map_err(|err| format!("读取服务响应失败：{err}"))?;
    serde_json::from_str(&response).map_err(|err| format!("解析服务响应失败：{err}"))
}

pub(crate) fn install_and_start_windows_service() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|err| format!("定位 UI 程序失败：{err}"))?;
    let bin_path = format!("\"{}\" {SERVICE_ARG}", exe.display());

    if run_sc(["query", SERVICE_NAME]).is_err() {
        run_sc([
            "create",
            SERVICE_NAME,
            "binPath=",
            &bin_path,
            "start=",
            "demand",
            "DisplayName=",
            SERVICE_DISPLAY_NAME,
        ])?;
    } else {
        stop_windows_service_if_running()?;
        run_sc(["config", SERVICE_NAME, "binPath=", &bin_path])?;
    }

    match run_sc(["start", SERVICE_NAME]) {
        Ok(()) => Ok(()),
        Err(err) if err.contains("1056") || err.contains("already running") => Ok(()),
        Err(err) => Err(err),
    }
}

pub(crate) fn run_windows_service() -> Result<(), String> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|err| format!("启动 Windows Service dispatcher 失败：{err}"))
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

fn ensure_windows_service_available(logs: &UiLogBuffer) -> Result<(), String> {
    let service_is_current = windows_service_matches_current_exe().unwrap_or(false);
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
    launch_elevated_service_installer()?;

    let deadline = Instant::now() + Duration::from_secs(35);
    while Instant::now() < deadline {
        let service_is_current = windows_service_matches_current_exe().unwrap_or(false);
        if service_is_current && send_service_request(&ServiceRequest::State).is_ok() {
            logs.push("PPAASS Agent Windows Service 已就绪");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    Err("PPAASS Agent Windows Service 启动超时".to_string())
}

fn launch_elevated_service_installer() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|err| format!("定位 UI 程序失败：{err}"))?;
    let cwd = std::env::current_dir().map_err(|err| format!("定位工作目录失败：{err}"))?;

    let operation = wide_null("runas");
    let exe = wide_null(exe.as_os_str());
    let args = wide_null(INSTALL_SERVICE_ARG);
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

fn normalized_path_for_compare(path: &Path) -> String {
    fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .replace('/', "\\")
        .to_lowercase()
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
    set_service_status(&status_handle, ServiceState::Stopped)?;
    Ok(())
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

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((mut stream, _)) => respond_to_service_request(&runtime, &mut stream).await,
                    Err(err) => runtime.logs.push(format!("服务 IPC 接收失败：{err}")),
                }
            }
        }
    }
}

async fn respond_to_service_request(runtime: &AgentRuntime, stream: &mut TcpStream) {
    let response = handle_service_request(runtime, stream).await;
    let payload = serde_json::to_vec(&response).unwrap_or_else(|err| {
        format!(
            "{{\"ok\":false,\"state\":null,\"traffic\":null,\"error\":\"编码响应失败：{err}\"}}"
        )
        .into_bytes()
    });
    let _ = stream.write_all(&payload).await;
    let _ = stream.shutdown().await;
}

async fn handle_service_request(runtime: &AgentRuntime, stream: &mut TcpStream) -> ServiceResponse {
    let mut payload = String::new();
    if let Err(err) = stream.read_to_string(&mut payload).await {
        return service_error(format!("读取服务请求失败：{err}"));
    }

    let request = match serde_json::from_str::<ServiceRequest>(&payload) {
        Ok(request) => request,
        Err(err) => return service_error(format!("解析服务请求失败：{err}")),
    };

    match request {
        ServiceRequest::Start { config_path } => {
            match start_agent_inner(runtime, PathBuf::from(config_path), false) {
                Ok(state) => service_state_ok(state),
                Err(err) => service_error(err),
            }
        }
        ServiceRequest::Stop => {
            let state = match stop_embedded_agent(runtime) {
                Ok(()) => agent_state(runtime),
                Err(err) => Err(err),
            };
            match state {
                Ok(state) => service_state_ok(state),
                Err(err) => service_error(err),
            }
        }
        ServiceRequest::State => match agent_state(runtime) {
            Ok(state) => service_state_ok(state),
            Err(err) => service_error(err),
        },
        ServiceRequest::Traffic => ServiceResponse {
            ok: true,
            state: None,
            traffic: Some(agent_traffic_snapshot()),
            dns_records: None,
            error: None,
        },
        ServiceRequest::DnsRecords => ServiceResponse {
            ok: true,
            state: None,
            traffic: None,
            dns_records: Some(desktop_agent_be::telemetry::dns_resolution_records()),
            error: None,
        },
        ServiceRequest::SetLogLevel { log_level } => match runtime.logs.set_log_level(&log_level) {
            Ok(()) => match agent_state(runtime) {
                Ok(state) => service_state_ok(state),
                Err(err) => service_error(err),
            },
            Err(err) => service_error(err),
        },
    }
}

fn service_state_ok(state: AgentState) -> ServiceResponse {
    ServiceResponse {
        ok: true,
        state: Some(state),
        traffic: None,
        dns_records: None,
        error: None,
    }
}

fn service_error(error: String) -> ServiceResponse {
    ServiceResponse {
        ok: false,
        state: None,
        traffic: None,
        dns_records: None,
        error: Some(error),
    }
}
