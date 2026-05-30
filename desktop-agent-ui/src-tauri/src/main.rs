#![cfg_attr(windows, windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs;
#[cfg(any(windows, target_os = "macos"))]
use std::io::Read;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream as StdTcpStream, ToSocketAddrs};
#[cfg(windows)]
use std::net::{Shutdown as TcpShutdown, TcpListener as StdTcpListener};
#[cfg(target_os = "macos")]
use std::os::unix::net::UnixStream;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(any(windows, target_os = "linux"))]
use std::process::Stdio;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::path::BaseDirectory;
use tauri::Manager;
use tokio_util::sync::CancellationToken;
use toml::Value;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::Registry;
use tracing_subscriber::reload;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};
#[cfg(windows)]
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};
#[cfg(windows)]
use windows_sys::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteW};

#[cfg(windows)]
const SERVICE_NAME: &str = "PPAASSAgentService";
#[cfg(windows)]
const SERVICE_DISPLAY_NAME: &str = "PPAASS Agent Service";
#[cfg(windows)]
const SERVICE_ARG: &str = "--ppaass-agent-service";
#[cfg(windows)]
const INSTALL_SERVICE_ARG: &str = "--ppaass-install-service";
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[cfg(windows)]
const SERVICE_IPC_ADDR: &str = "127.0.0.1:17981";
#[cfg(windows)]
const TRAY_ID: &str = "main";
#[cfg(windows)]
const TRAY_SHOW_ID: &str = "show";
#[cfg(windows)]
const TRAY_EXIT_ID: &str = "exit";

#[cfg(target_os = "macos")]
const TUN_HELPER_SERVICE_ARG: &str = "--tun-helper-service";
#[cfg(target_os = "macos")]
const TUN_HELPER_SOCKET_ARG: &str = "--tun-helper-socket";
#[cfg(target_os = "macos")]
const TUN_HELPER_ALLOWED_UID_ARG: &str = "--tun-helper-allowed-uid";
#[cfg(target_os = "macos")]
const TUN_HELPER_LOG_LEVEL_ARG: &str = "--log-level";
#[cfg(target_os = "macos")]
const TUN_HELPER_INSTALL_PATH: &str = "/usr/local/libexec/ppaass-desktop-agent";
#[cfg(target_os = "macos")]
const TUN_HELPER_LEGACY_INSTALL_PATH: &str = "/usr/local/libexec/ppaass-tun-helper";
#[cfg(target_os = "macos")]
const TUN_HELPER_SOCKET_PATH: &str = "/var/run/ppaass-ai/tun-helper.sock";
#[cfg(target_os = "macos")]
const TUN_HELPER_PLIST_ID: &str = "com.ppaass.ai.desktop-agent.tun-helper";
#[cfg(target_os = "macos")]
const TUN_HELPER_PLIST_PATH: &str =
    "/Library/LaunchDaemons/com.ppaass.ai.desktop-agent.tun-helper.plist";
#[cfg(target_os = "macos")]
const TUN_HELPER_LEGACY_PLIST_PATH: &str = "/Library/LaunchDaemons/com.ppaass.ai.tun-helper.plist";
#[cfg(target_os = "macos")]
const TUN_HELPER_CURRENT_APP_MARKER: &str = "tun-helper-current-app.txt";

const BUNDLED_AGENT_FILES: &[(&str, &str)] = &[
    ("config/local/agent.toml", "agent.toml"),
    ("config/local/agent.toml", "config/local/agent.toml"),
    ("keys/user1.pem", "keys/user1.pem"),
    ("keys/user2.pem", "keys/user2.pem"),
    ("wintun.dll", "wintun.dll"),
];

static DEPLOYED_AGENT_DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

#[cfg(windows)]
define_windows_service!(ffi_service_main, windows_service_main);

struct AgentRuntime {
    agent: Mutex<Option<EmbeddedAgent>>,
    config_path: Mutex<Option<PathBuf>>,
    logs: UiLogBuffer,
    last_error: Arc<Mutex<Option<String>>>,
}

struct EmbeddedAgent {
    shutdown: CancellationToken,
    join: Option<JoinHandle<()>>,
}

impl AgentRuntime {
    fn new() -> Self {
        Self {
            agent: Mutex::new(None),
            config_path: Mutex::new(None),
            logs: UiLogBuffer::new(1200),
            last_error: Arc::new(Mutex::new(None)),
        }
    }
}

#[derive(Clone)]
struct UiLogBuffer {
    lines: Arc<Mutex<VecDeque<String>>>,
    capacity: usize,
    filter: Arc<Mutex<Option<reload::Handle<EnvFilter, Registry>>>>,
}

impl UiLogBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            lines: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
            capacity,
            filter: Arc::new(Mutex::new(None)),
        }
    }

    fn push(&self, line: impl Into<String>) {
        let Ok(mut lines) = self.lines.lock() else {
            return;
        };
        while lines.len() >= self.capacity {
            lines.pop_front();
        }
        lines.push_back(line.into());
    }

    fn snapshot(&self) -> Vec<String> {
        self.lines
            .lock()
            .map(|lines| lines.iter().cloned().collect())
            .unwrap_or_default()
    }

    fn install_tracing(&self) {
        let (filter, handle) = reload::Layer::new(log_filter("info"));
        let layer = fmt::layer()
            .with_writer(UiLogMakeWriter {
                buffer: self.clone(),
            })
            .with_ansi(false)
            .with_target(true)
            .with_thread_ids(true)
            .with_line_number(true);

        let result = tracing_subscriber::registry()
            .with(filter)
            .with(layer)
            .try_init();

        match result {
            Ok(()) => {
                if let Ok(mut slot) = self.filter.lock() {
                    *slot = Some(handle);
                }
                self.push("UI 日志通道已初始化");
            }
            Err(err) => self.push(format!("UI 日志通道初始化失败：{err}")),
        }
    }

    fn set_log_level(&self, log_level: &str) -> Result<(), String> {
        let normalized = normalize_log_level(log_level);
        let handle = self
            .filter
            .lock()
            .map_err(|_| "日志级别状态锁已损坏".to_string())?
            .clone();
        let Some(handle) = handle else {
            return Ok(());
        };

        handle
            .reload(log_filter(normalized))
            .map_err(|err| format!("更新 UI 日志级别失败：{err}"))?;
        self.push(format!("UI 日志级别已切换为：{normalized}"));
        Ok(())
    }
}

fn normalize_log_level(log_level: &str) -> &'static str {
    match log_level.trim().to_ascii_lowercase().as_str() {
        "trace" => "trace",
        "debug" => "debug",
        "warn" => "warn",
        "error" => "error",
        _ => "info",
    }
}

fn log_filter(log_level: &str) -> EnvFilter {
    EnvFilter::try_new(normalize_log_level(log_level)).unwrap_or_else(|_| EnvFilter::new("info"))
}

#[derive(Clone)]
struct UiLogMakeWriter {
    buffer: UiLogBuffer,
}

impl<'a> MakeWriter<'a> for UiLogMakeWriter {
    type Writer = UiLogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        UiLogWriter {
            buffer: self.buffer.clone(),
            bytes: Vec::new(),
        }
    }
}

struct UiLogWriter {
    buffer: UiLogBuffer,
    bytes: Vec<u8>,
}

impl Write for UiLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for UiLogWriter {
    fn drop(&mut self) {
        let text = String::from_utf8_lossy(&self.bytes);
        for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
            self.buffer.push(line.to_string());
        }
    }
}

#[derive(Debug, Serialize)]
struct LoadedAgentConfig {
    path: String,
    raw: String,
    summary: AgentConfigSummary,
}

#[derive(Debug, Serialize, Deserialize)]
struct AgentState {
    running: bool,
    managed: bool,
    pid: Option<u32>,
    config_path: Option<String>,
    binary_path: Option<String>,
    logs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct AgentConfigSummary {
    listen_addr: String,
    proxy_addrs: Vec<String>,
    username: String,
    private_key_path: String,
    tcp_pool_size: usize,
    udp_pool_size: usize,
    connect_timeout_secs: u64,
    compression_mode: String,
    log_level: String,
    log_dir: Option<String>,
    log_file: String,
    runtime_threads: Option<usize>,
    effective_runtime_threads: usize,
    tcp_mode: String,
    udp_mode: String,
    tcp_yamux_sessions: usize,
    udp_yamux_sessions: usize,
    tun_enabled: bool,
    tun_name: String,
    tun_ipv4: String,
    tun_mtu: u64,
    tun_proxy_dns: bool,
    tun_block_quic: bool,
    direct_mode: String,
    direct_rules: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ConnectivityReport {
    listen_addr: String,
    tun_enabled: bool,
    tun_name: String,
    tun_ready: bool,
    tun_status: String,
    agent_reachable: bool,
    generated_at_ms: u128,
    results: Vec<ConnectivityCheck>,
    tun_results: Vec<ConnectivityCheck>,
}

#[derive(Debug, Serialize)]
struct ConnectivityCheck {
    target: String,
    protocol: String,
    url: String,
    proxy_url: String,
    success: bool,
    http_code: Option<u16>,
    duration_ms: u128,
    error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct NetworkTrafficSnapshot {
    sampled_at_ms: u128,
    total_received_bytes: u64,
    total_transmitted_bytes: u64,
    interfaces: Vec<NetworkInterfaceTraffic>,
}

#[derive(Debug, Serialize, Deserialize)]
struct NetworkInterfaceTraffic {
    name: String,
    received_bytes: u64,
    transmitted_bytes: u64,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum MacosTunHelperProbeResponse {
    Pong,
    Error { message: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
#[cfg(windows)]
enum ServiceRequest {
    Start { config_path: String },
    Stop,
    State,
    Traffic,
    SetLogLevel { log_level: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg(windows)]
struct ServiceResponse {
    ok: bool,
    state: Option<AgentState>,
    traffic: Option<NetworkTrafficSnapshot>,
    error: Option<String>,
}

#[tauri::command]
fn load_agent_config(
    runtime: tauri::State<'_, AgentRuntime>,
    path: Option<String>,
) -> Result<LoadedAgentConfig, String> {
    let config_path = match path.filter(|value| !value.trim().is_empty()) {
        Some(value) => PathBuf::from(value),
        None => locate_config_path().ok_or_else(|| {
            "找不到 agent 配置文件。请确认 agent.toml 或 config/local/agent.toml 存在。".to_string()
        })?,
    };

    let loaded = load_config_from_path(&config_path)?;
    apply_ui_log_level(&runtime, &loaded.summary.log_level);
    Ok(loaded)
}

#[tauri::command]
fn save_agent_config(
    runtime: tauri::State<'_, AgentRuntime>,
    path: String,
    raw: String,
) -> Result<LoadedAgentConfig, String> {
    let config_path = make_absolute_path(Path::new(&path));
    write_config_file(&config_path, &raw)?;

    let loaded = if let Some(primary_path) = primary_agent_config_path(&config_path) {
        write_config_file(&primary_path, &raw)?;
        load_config_from_path(&primary_path)?
    } else {
        load_config_from_path(&config_path)?
    };

    apply_ui_log_level(&runtime, &loaded.summary.log_level);
    #[cfg(windows)]
    let _ = send_service_request(&ServiceRequest::SetLogLevel {
        log_level: loaded.summary.log_level.clone(),
    });

    Ok(loaded)
}

#[tauri::command]
fn get_agent_state(runtime: tauri::State<'_, AgentRuntime>) -> Result<AgentState, String> {
    #[cfg(windows)]
    if let Ok(state) = windows_service_state() {
        return Ok(state);
    }

    agent_state(&runtime)
}

#[tauri::command]
fn start_agent(
    runtime: tauri::State<'_, AgentRuntime>,
    config_path: String,
) -> Result<AgentState, String> {
    #[cfg(windows)]
    {
        return start_agent_via_windows_service(config_path, &runtime.logs);
    }

    #[cfg(not(windows))]
    start_agent_inner(&runtime, PathBuf::from(config_path), true)
}

fn start_agent_inner(
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

fn apply_log_level_from_config_path(
    runtime: &AgentRuntime,
    config_path: &Path,
) -> Result<(), String> {
    let config = desktop_agent_be::config::AgentConfig::load(config_path)
        .map_err(|err| format!("加载 Agent 配置失败：{err}"))?;
    apply_ui_log_level(runtime, &config.log_level);
    Ok(())
}

fn apply_ui_log_level(runtime: &AgentRuntime, log_level: &str) {
    if let Err(err) = runtime.logs.set_log_level(log_level) {
        runtime.logs.push(err);
    }
}

#[tauri::command]
fn stop_agent(runtime: tauri::State<'_, AgentRuntime>) -> Result<AgentState, String> {
    #[cfg(windows)]
    if let Ok(state) = stop_agent_via_windows_service() {
        return Ok(state);
    }

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

    drop(guard);
    agent_state(&runtime)
}

#[tauri::command]
async fn run_connectivity_tests(path: Option<String>) -> Result<ConnectivityReport, String> {
    tauri::async_runtime::spawn_blocking(move || run_connectivity_tests_blocking(path))
        .await
        .map_err(|err| format!("诊断任务执行失败：{err}"))?
}

fn run_connectivity_tests_blocking(path: Option<String>) -> Result<ConnectivityReport, String> {
    let config_path = match path.filter(|value| !value.trim().is_empty()) {
        Some(value) => PathBuf::from(value),
        None => locate_config_path().ok_or_else(|| {
            "找不到 agent 配置文件。请确认 agent.toml 或 config/local/agent.toml 存在。".to_string()
        })?,
    };
    let raw = fs::read_to_string(&config_path).map_err(|err| format!("读取配置失败：{err}"))?;
    let summary = summarize_config(&raw)?;
    let listen_addr = summary.listen_addr.clone();
    let tun_enabled = summary.tun_enabled;
    let tun_name = summary.tun_name.clone();
    let agent_reachable = connect_addr(&listen_addr)
        .map(|addr| StdTcpStream::connect_timeout(&addr, Duration::from_millis(900)).is_ok())
        .unwrap_or(false);

    let targets = [
        ("Google", "https://www.google.com/generate_204"),
        ("YouTube", "https://www.youtube.com/generate_204"),
    ];
    let protocols = [
        ("HTTP", proxy_url("http", &listen_addr)),
        ("SOCKS5", proxy_url("socks5h", &listen_addr)),
    ];

    let mut result_jobs = Vec::new();
    for (target, url) in targets.iter().copied() {
        for (protocol, proxy) in &protocols {
            let target = target.to_string();
            let protocol = (*protocol).to_string();
            let url = url.to_string();
            let proxy = proxy.clone();
            result_jobs.push(thread::spawn(move || {
                run_curl_check(&target, &protocol, &url, Some(proxy.as_str()), &proxy)
            }));
        }
    }
    let results = collect_connectivity_checks(result_jobs);

    let mut tun_results = Vec::new();
    let (tun_ready, tun_status) = if tun_enabled {
        probe_tun_ready(&tun_name)
    } else {
        (false, "TUN 未启用".to_string())
    };
    if tun_enabled {
        let tun_route = format!("tun://{tun_name}");
        if tun_ready {
            let mut tun_jobs = Vec::new();
            for (target, url) in targets.iter().copied() {
                let target = target.to_string();
                let url = url.to_string();
                let tun_route = tun_route.clone();
                tun_jobs.push(thread::spawn(move || {
                    run_curl_check(&target, "TUN", &url, None, &tun_route)
                }));
            }
            tun_results = collect_connectivity_checks(tun_jobs);
        } else {
            for (target, url) in targets.iter().copied() {
                tun_results.push(failed_connectivity_check(
                    target,
                    "TUN",
                    url,
                    &tun_route,
                    &tun_status,
                ));
            }
        }
    }

    Ok(ConnectivityReport {
        listen_addr,
        tun_enabled,
        tun_name,
        tun_ready,
        tun_status,
        agent_reachable,
        generated_at_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or_default(),
        results,
        tun_results,
    })
}

fn collect_connectivity_checks(jobs: Vec<JoinHandle<ConnectivityCheck>>) -> Vec<ConnectivityCheck> {
    jobs.into_iter().filter_map(|job| job.join().ok()).collect()
}

#[tauri::command]
fn get_network_traffic_snapshot() -> Result<NetworkTrafficSnapshot, String> {
    #[cfg(windows)]
    if let Ok(response) = send_service_request(&ServiceRequest::Traffic) {
        if response.ok {
            if let Some(traffic) = response.traffic {
                return Ok(traffic);
            }
        }
    }

    Ok(agent_traffic_snapshot())
}

fn agent_traffic_snapshot() -> NetworkTrafficSnapshot {
    let traffic = desktop_agent_be::telemetry::traffic_snapshot();

    NetworkTrafficSnapshot {
        sampled_at_ms: current_time_millis(),
        total_received_bytes: traffic.inbound_bytes,
        total_transmitted_bytes: traffic.outbound_bytes,
        interfaces: vec![NetworkInterfaceTraffic {
            name: "Agent".to_string(),
            received_bytes: traffic.inbound_bytes,
            transmitted_bytes: traffic.outbound_bytes,
        }],
    }
}

fn load_config_from_path(path: &Path) -> Result<LoadedAgentConfig, String> {
    let config_path = make_absolute_path(path);
    let raw = fs::read_to_string(&config_path).map_err(|err| format!("读取配置失败：{err}"))?;
    let summary = summarize_config(&raw)?;
    let display_path = config_path
        .canonicalize()
        .unwrap_or_else(|_| config_path.clone());
    Ok(LoadedAgentConfig {
        path: display_path.to_string_lossy().to_string(),
        raw,
        summary,
    })
}

fn write_config_file(path: &Path, raw: &str) -> Result<(), String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|err| format!("创建配置目录失败：{err}"))?;
    }
    let mut file = fs::File::create(path).map_err(|err| format!("保存配置失败：{err}"))?;
    file.write_all(raw.as_bytes())
        .map_err(|err| format!("写入配置失败：{err}"))?;
    file.sync_all()
        .map_err(|err| format!("同步配置到磁盘失败：{err}"))?;
    Ok(())
}

fn primary_agent_config_path(path: &Path) -> Option<PathBuf> {
    if path.file_name()?.to_str()? != "agent.toml" {
        return None;
    }
    let local_dir = path.parent()?;
    if local_dir.file_name()?.to_str()? != "local" {
        return None;
    }
    let config_dir = local_dir.parent()?;
    if config_dir.file_name()?.to_str()? != "config" {
        return None;
    }
    config_dir.parent().map(|base| base.join("agent.toml"))
}

fn install_bundled_agent_assets(app: &tauri::App, logs: &UiLogBuffer) -> Result<(), String> {
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|err| format!("定位 Agent 数据目录失败：{err}"))?;
    fs::create_dir_all(&app_data_dir)
        .map_err(|err| format!("创建 Agent 数据目录失败：{}：{err}", app_data_dir.display()))?;
    let _ = DEPLOYED_AGENT_DATA_DIR.set(app_data_dir.clone());

    for (resource_path, deploy_path) in BUNDLED_AGENT_FILES {
        let destination = app_data_dir.join(deploy_path);
        if destination.exists() {
            logs.push(format!("保留已有 Agent 资源：{}", destination.display()));
            continue;
        }
        let source = bundled_agent_source_path(app, resource_path, deploy_path, &app_data_dir)?;

        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("创建 Agent 资源目录失败：{}：{err}", parent.display()))?;
        }
        fs::copy(&source, &destination).map_err(|err| {
            format!(
                "部署 Agent 资源失败：{} -> {}：{err}",
                source.display(),
                destination.display()
            )
        })?;
        logs.push(format!("已部署默认 Agent 资源：{}", destination.display()));
    }

    Ok(())
}

fn bundled_agent_source_path(
    app: &tauri::App,
    resource_path: &str,
    deploy_path: &str,
    app_data_dir: &Path,
) -> Result<PathBuf, String> {
    if deploy_path == "agent.toml" {
        let legacy_config = app_data_dir.join("config/local/agent.toml");
        if legacy_config.is_file() {
            return Ok(legacy_config);
        }
    }

    bundled_agent_resource_path(app, resource_path)
}

fn bundled_agent_resource_path(app: &tauri::App, resource_path: &str) -> Result<PathBuf, String> {
    if let Ok(path) = app.path().resolve(resource_path, BaseDirectory::Resource) {
        if path.is_file() {
            return Ok(path);
        }
    }

    ancestor_dirs()
        .into_iter()
        .map(|base| base.join(resource_path))
        .find(|path| path.is_file())
        .ok_or_else(|| format!("找不到内置 Agent 资源：{resource_path}"))
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum MacosTunHelperStatus {
    Current,
    Missing,
    Outdated,
    NeedsRestart,
}

#[cfg(target_os = "macos")]
fn check_macos_tun_helper_on_startup(logs: &UiLogBuffer) {
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

#[cfg(target_os = "macos")]
fn ensure_macos_tun_helper_for_config(
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

#[cfg(target_os = "macos")]
fn config_needs_macos_tun_helper(config: &desktop_agent_be::config::AgentConfig) -> bool {
    config.tun.enabled && config.tun.macos_helper_enabled
}

#[cfg(target_os = "macos")]
fn ensure_macos_tun_helper(
    config: &desktop_agent_be::config::AgentConfig,
    logs: &UiLogBuffer,
) -> Result<(), String> {
    let source = std::env::current_exe().map_err(|err| format!("定位当前 App 程序失败：{err}"))?;
    let force_refresh = macos_tun_helper_current_app_update_pending(&source, logs);
    ensure_macos_tun_helper_from_source(&source, config, logs, force_refresh)
}

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
fn macos_tun_helper_current_app_marker_path() -> Result<PathBuf, String> {
    DEPLOYED_AGENT_DATA_DIR
        .get()
        .map(|dir| dir.join(TUN_HELPER_CURRENT_APP_MARKER))
        .ok_or_else(|| "Agent 数据目录尚未初始化".to_string())
}

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
fn macos_tun_helper_socket(config: &desktop_agent_be::config::AgentConfig) -> &str {
    let socket_path = config.tun.macos_helper_socket.trim();
    if socket_path.is_empty() {
        TUN_HELPER_SOCKET_PATH
    } else {
        socket_path
    }
}

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
fn macos_tun_helper_socket_ready(socket_path: &str) -> bool {
    macos_tun_helper_ping(socket_path).is_ok()
}

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
fn macos_tun_helper_plist_has_core_config(
    plist: &str,
    socket_path: &str,
    allowed_uid: u32,
) -> bool {
    // Log level changes should not force a privileged helper reinstall on every
    // start. The helper is considered current when the executable, socket, and
    // access control are correct; binary updates still trigger reinstall via
    // files_identical().
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

#[cfg(target_os = "macos")]
fn files_identical(left: &Path, right: &Path) -> io::Result<bool> {
    let left_metadata = fs::metadata(left)?;
    let right_metadata = fs::metadata(right)?;
    if left_metadata.len() != right_metadata.len() {
        return Ok(false);
    }

    Ok(fs::read(left)? == fs::read(right)?)
}

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(target_os = "macos")]
fn apple_script_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(target_os = "macos")]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(target_os = "macos")]
fn run_macos_tun_helper_service_from_args() -> Result<(), String> {
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

#[cfg(target_os = "macos")]
fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find_map(|pair| {
        if pair[0] == flag {
            Some(pair[1].clone())
        } else {
            None
        }
    })
}

fn current_time_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

fn probe_tun_ready(tun_name: &str) -> (bool, String) {
    let interface_ready = tun_interface_ready(tun_name);
    let routes_ready = tun_routes_ready(tun_name);
    let display_name = resolved_tun_name(tun_name).unwrap_or_else(|| tun_name.to_string());

    match (interface_ready, routes_ready) {
        (true, true) => (true, format!("TUN 已就绪：{display_name}")),
        (false, true) => (false, format!("TUN 网卡未就绪：{display_name}")),
        (true, false) => (false, format!("TUN 路由未就绪：{display_name}")),
        (false, false) => (false, format!("TUN 网卡和路由未就绪：{display_name}")),
    }
}

#[cfg(target_os = "windows")]
fn tun_interface_ready(tun_name: &str) -> bool {
    powershell_status(
        "$adapter = Get-NetAdapter -Name $env:PPAASS_TUN_NAME -ErrorAction SilentlyContinue; if ($adapter -and $adapter.Status -eq 'Up') { exit 0 }; exit 1",
        tun_name,
    )
}

#[cfg(target_os = "windows")]
fn tun_routes_ready(tun_name: &str) -> bool {
    powershell_status(
        "$routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/1','128.0.0.0/1' -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -eq $env:PPAASS_TUN_NAME }); if ($routes.Count -ge 2) { exit 0 }; exit 1",
        tun_name,
    )
}

#[cfg(target_os = "windows")]
fn powershell_status(script: &str, tun_name: &str) -> bool {
    Command::new("powershell.exe")
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
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(target_os = "macos")]
fn tun_interface_ready(tun_name: &str) -> bool {
    macos_ifconfig_up(tun_name)
        || macos_active_tun_route_interface().is_some_and(|name| macos_ifconfig_up(&name))
}

#[cfg(target_os = "macos")]
fn tun_routes_ready(tun_name: &str) -> bool {
    (route_get_uses_tun("1.1.1.1", tun_name) && route_get_uses_tun("200.0.0.1", tun_name))
        || macos_active_tun_route_interface().is_some()
}

#[cfg(target_os = "macos")]
fn route_get_uses_tun(target: &str, tun_name: &str) -> bool {
    route_get_interface(target).is_some_and(|name| name == tun_name)
}

#[cfg(target_os = "macos")]
fn resolved_tun_name(tun_name: &str) -> Option<String> {
    if macos_ifconfig_up(tun_name) {
        return Some(tun_name.to_string());
    }
    macos_active_tun_route_interface()
}

#[cfg(not(target_os = "macos"))]
fn resolved_tun_name(tun_name: &str) -> Option<String> {
    Some(tun_name.to_string())
}

#[cfg(target_os = "macos")]
fn macos_ifconfig_up(tun_name: &str) -> bool {
    let output = Command::new("ifconfig").arg(tun_name).output().ok();
    output.is_some_and(|output| {
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
    if first == second && first.starts_with("utun") {
        Some(first)
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn route_get_interface(target: &str) -> Option<String> {
    Command::new("route")
        .args(["-n", "get", target])
        .output()
        .ok()
        .and_then(|output| {
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
        })
}

#[cfg(target_os = "linux")]
fn tun_interface_ready(tun_name: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", "dev", tun_name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(target_os = "linux")]
fn tun_routes_ready(tun_name: &str) -> bool {
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
fn tun_interface_ready(_tun_name: &str) -> bool {
    false
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn tun_routes_ready(_tun_name: &str) -> bool {
    false
}

fn failed_connectivity_check(
    target: &str,
    protocol: &str,
    url: &str,
    route_label: &str,
    error: &str,
) -> ConnectivityCheck {
    ConnectivityCheck {
        target: target.to_string(),
        protocol: protocol.to_string(),
        url: url.to_string(),
        proxy_url: route_label.to_string(),
        success: false,
        http_code: None,
        duration_ms: 0,
        error: Some(error.to_string()),
    }
}

fn run_curl_check(
    target: &str,
    protocol: &str,
    url: &str,
    proxy_url: Option<&str>,
    route_label: &str,
) -> ConnectivityCheck {
    let start = Instant::now();
    let null_output = if cfg!(target_os = "windows") {
        "NUL"
    } else {
        "/dev/null"
    };
    let curl_bin = if cfg!(target_os = "windows") {
        "curl.exe"
    } else {
        "curl"
    };

    let mut args = vec![
        "-sS".to_string(),
        "-L".to_string(),
        "-o".to_string(),
        null_output.to_string(),
        "-w".to_string(),
        "http_code=%{http_code}\ntime_total=%{time_total}\nerrormsg=%{errormsg}\n".to_string(),
    ];
    if let Some(proxy_url) = proxy_url {
        args.extend(["--proxy".to_string(), proxy_url.to_string()]);
    } else {
        args.extend(["--noproxy".to_string(), "*".to_string()]);
    }
    args.extend([
        "--connect-timeout".to_string(),
        "10".to_string(),
        "--max-time".to_string(),
        "25".to_string(),
        url.to_string(),
    ]);

    let output = Command::new(curl_bin).args(&args).output();

    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let http_code = curl_field(&stdout, "http_code")
                .and_then(|value| value.parse::<u16>().ok())
                .filter(|value| *value > 0);
            let errormsg = curl_field(&stdout, "errormsg")
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| stderr.trim().to_string());
            let success =
                output.status.success() && http_code.is_some_and(|code| (200..400).contains(&code));

            ConnectivityCheck {
                target: target.to_string(),
                protocol: protocol.to_string(),
                url: url.to_string(),
                proxy_url: route_label.to_string(),
                success,
                http_code,
                duration_ms: start.elapsed().as_millis(),
                error: if success {
                    None
                } else if errormsg.is_empty() {
                    Some(format!("curl exit status: {}", output.status))
                } else {
                    Some(errormsg)
                },
            }
        }
        Err(err) => ConnectivityCheck {
            target: target.to_string(),
            protocol: protocol.to_string(),
            url: url.to_string(),
            proxy_url: route_label.to_string(),
            success: false,
            http_code: None,
            duration_ms: start.elapsed().as_millis(),
            error: Some(format!("运行 curl 失败：{err}")),
        },
    }
}

fn curl_field(output: &str, key: &str) -> Option<String> {
    output.lines().find_map(|line| {
        line.strip_prefix(key)
            .and_then(|value| value.strip_prefix('='))
            .map(ToOwned::to_owned)
    })
}

fn proxy_url(scheme: &str, listen_addr: &str) -> String {
    if let Ok(addr) = listen_addr.parse::<SocketAddr>() {
        return format!("{scheme}://{}", display_connect_addr(addr));
    }
    format!("{scheme}://{listen_addr}")
}

fn connect_addr(listen_addr: &str) -> Option<SocketAddr> {
    if let Ok(addr) = listen_addr.parse::<SocketAddr>() {
        return Some(normalize_listen_addr(addr));
    }
    listen_addr
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
        .map(normalize_listen_addr)
}

fn normalize_listen_addr(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
        }
        IpAddr::V6(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), addr.port())
        }
        _ => addr,
    }
}

fn display_connect_addr(addr: SocketAddr) -> String {
    let addr = normalize_listen_addr(addr);
    match addr.ip() {
        IpAddr::V4(ip) => format!("{ip}:{}", addr.port()),
        IpAddr::V6(ip) => format!("[{ip}]:{}", addr.port()),
    }
}

fn agent_state(runtime: &AgentRuntime) -> Result<AgentState, String> {
    let (running, pid) = process_status(runtime)?;
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
    config_path.parent().and_then(|parent| {
        parent
            .ancestors()
            .take(8)
            .find(|ancestor| is_agent_base_dir(ancestor))
            .map(Path::to_path_buf)
    })
}

fn is_agent_base_dir(path: &Path) -> bool {
    path.join("wintun.dll").is_file()
        || path.join("desktop-agent-be").is_dir()
        || (path.join("config/local/agent.toml").is_file() && path.join("keys").is_dir())
}

fn make_absolute_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }

    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(path)
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
    runtime
        .last_error
        .lock()
        .ok()
        .and_then(|last_error| last_error.clone())
}

#[cfg(windows)]
fn start_agent_via_windows_service(
    config_path: String,
    logs: &UiLogBuffer,
) -> Result<AgentState, String> {
    ensure_windows_service_available(logs)?;
    let response = send_service_request(&ServiceRequest::Start { config_path })?;
    service_state_response(response)
}

#[cfg(windows)]
fn stop_agent_via_windows_service() -> Result<AgentState, String> {
    let response = send_service_request(&ServiceRequest::Stop)?;
    service_state_response(response)
}

#[cfg(windows)]
fn windows_service_state() -> Result<AgentState, String> {
    let response = send_service_request(&ServiceRequest::State)?;
    service_state_response(response)
}

#[cfg(windows)]
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

#[cfg(windows)]
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

#[cfg(windows)]
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

#[cfg(windows)]
fn send_service_request(request: &ServiceRequest) -> Result<ServiceResponse, String> {
    let addr = SERVICE_IPC_ADDR
        .parse::<SocketAddr>()
        .map_err(|err| format!("服务 IPC 地址无效：{err}"))?;
    let mut stream = StdTcpStream::connect_timeout(&addr, Duration::from_millis(600))
        .map_err(|err| format!("无法连接 Agent 服务：{err}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(8)))
        .map_err(|err| format!("设置服务 IPC 读超时失败：{err}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(8)))
        .map_err(|err| format!("设置服务 IPC 写超时失败：{err}"))?;

    let payload = serde_json::to_vec(request).map_err(|err| format!("编码服务请求失败：{err}"))?;
    stream
        .write_all(&payload)
        .map_err(|err| format!("发送服务请求失败：{err}"))?;
    let _ = stream.shutdown(TcpShutdown::Write);

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|err| format!("读取服务响应失败：{err}"))?;
    serde_json::from_str(&response).map_err(|err| format!("解析服务响应失败：{err}"))
}

#[cfg(windows)]
fn wide_null(value: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    value
        .as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
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

    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .env("PPAASS_AGENT_PORT", port.to_string())
        .stdin(Stdio::null())
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

#[cfg(windows)]
fn install_and_start_windows_service() -> Result<(), String> {
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

#[cfg(windows)]
fn run_sc<const N: usize>(args: [&str; N]) -> Result<(), String> {
    run_sc_capture(args).map(|_| ())
}

#[cfg(windows)]
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

#[cfg(windows)]
fn windows_service_matches_current_exe() -> Result<bool, String> {
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

#[cfg(windows)]
fn parse_sc_binary_path(output: &str) -> Option<&str> {
    output.lines().find_map(|line| {
        if !line.contains("BINARY_PATH_NAME") {
            return None;
        }
        line.split_once(':').map(|(_, value)| value.trim())
    })
}

#[cfg(windows)]
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

#[cfg(windows)]
fn normalized_path_for_compare(path: &Path) -> String {
    fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .replace('/', "\\")
        .to_lowercase()
}

#[cfg(windows)]
fn stop_windows_service_if_running() -> Result<(), String> {
    match run_sc(["stop", SERVICE_NAME]) {
        Ok(()) => wait_windows_service_stopped(),
        Err(err) if err.contains("1062") || err.contains("has not been started") => Ok(()),
        Err(err) => Err(err),
    }
}

#[cfg(windows)]
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

#[cfg(windows)]
fn run_windows_service() -> Result<(), String> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|err| format!("启动 Windows Service dispatcher 失败：{err}"))
}

#[cfg(windows)]
fn windows_service_main(_arguments: Vec<std::ffi::OsString>) {
    if let Err(err) = run_windows_service_inner() {
        eprintln!("PPAASS Agent Service failed: {err}");
    }
}

#[cfg(windows)]
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

    if let Ok(mut guard) = runtime.agent.lock() {
        if let Some(mut agent) = guard.take() {
            agent.shutdown.cancel();
            if let Some(join) = agent.join.take() {
                let _ = join.join();
            }
        }
    }
    let _ = ipc_thread.join();
    set_service_status(&status_handle, ServiceState::Stopped)?;
    Ok(())
}

#[cfg(windows)]
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

#[cfg(windows)]
fn run_service_ipc(runtime: Arc<AgentRuntime>, shutdown: CancellationToken) {
    let listener = match StdTcpListener::bind(SERVICE_IPC_ADDR) {
        Ok(listener) => listener,
        Err(err) => {
            runtime.logs.push(format!("服务 IPC 监听失败：{err}"));
            return;
        }
    };
    let _ = listener.set_nonblocking(true);
    runtime
        .logs
        .push(format!("服务 IPC 已监听：{SERVICE_IPC_ADDR}"));

    while !shutdown.is_cancelled() {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let response = handle_service_request(&runtime, &mut stream);
                let payload = serde_json::to_vec(&response).unwrap_or_else(|err| {
                    format!(
                        "{{\"ok\":false,\"state\":null,\"traffic\":null,\"error\":\"编码响应失败：{err}\"}}"
                    )
                    .into_bytes()
                });
                let _ = stream.write_all(&payload);
                let _ = stream.shutdown(TcpShutdown::Both);
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(80));
            }
            Err(err) => {
                runtime.logs.push(format!("服务 IPC 接收失败：{err}"));
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

#[cfg(windows)]
fn handle_service_request(runtime: &AgentRuntime, stream: &mut StdTcpStream) -> ServiceResponse {
    let mut payload = String::new();
    if let Err(err) = stream.read_to_string(&mut payload) {
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
            let state = match stop_service_agent(runtime) {
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

#[cfg(windows)]
fn stop_service_agent(runtime: &AgentRuntime) -> Result<(), String> {
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

#[cfg(windows)]
fn service_state_ok(state: AgentState) -> ServiceResponse {
    ServiceResponse {
        ok: true,
        state: Some(state),
        traffic: None,
        error: None,
    }
}

#[cfg(windows)]
fn service_error(error: String) -> ServiceResponse {
    ServiceResponse {
        ok: false,
        state: None,
        traffic: None,
        error: Some(error),
    }
}

fn summarize_config(raw: &str) -> Result<AgentConfigSummary, String> {
    let value = raw
        .parse::<Value>()
        .map_err(|err| format!("配置 TOML 解析失败：{err}"))?;
    let runtime_threads = int_at(&value, &["runtime_threads"])
        .filter(|value| *value > 0)
        .map(|value| value as usize);

    Ok(AgentConfigSummary {
        listen_addr: string_or(&value, &["listen_addr"], "127.0.0.1:10080"),
        proxy_addrs: string_array_at(&value, &["proxy_addrs"]),
        username: string_or(&value, &["username"], "user1"),
        private_key_path: string_or(&value, &["private_key_path"], "keys/user1.pem"),
        tcp_pool_size: int_at(&value, &["tcp_pool_size"]).unwrap_or(10) as usize,
        udp_pool_size: int_at(&value, &["udp_pool_size"]).unwrap_or(5) as usize,
        connect_timeout_secs: int_at(&value, &["connect_timeout_secs"]).unwrap_or(30),
        compression_mode: string_or(&value, &["compression_mode"], "none"),
        log_level: string_or(&value, &["log_level"], "info"),
        log_dir: string_at(&value, &["log_dir"]),
        log_file: string_or(&value, &["log_file"], "desktop-agent.log"),
        runtime_threads,
        effective_runtime_threads: runtime_threads.unwrap_or_else(default_runtime_threads),
        tcp_mode: string_or(&value, &["transport", "tcp_mode"], "auto"),
        udp_mode: string_or(&value, &["transport", "udp_mode"], "auto"),
        tcp_yamux_sessions: int_at(&value, &["yamux", "tcp", "sessions"]).unwrap_or(5) as usize,
        udp_yamux_sessions: int_at(&value, &["yamux", "udp", "sessions"]).unwrap_or(5) as usize,
        tun_enabled: bool_at(&value, &["tun", "enabled"]).unwrap_or(false),
        tun_name: string_or(&value, &["tun", "name"], default_tun_name()),
        tun_ipv4: string_or(&value, &["tun", "ipv4"], "10.10.10.1/24"),
        tun_mtu: int_at(&value, &["tun", "mtu"]).unwrap_or(1500),
        tun_proxy_dns: bool_at(&value, &["tun", "proxy_dns"]).unwrap_or(false),
        tun_block_quic: bool_at(&value, &["tun", "block_quic"]).unwrap_or(true),
        direct_mode: string_or(&value, &["direct_access", "mode"], "proxy_all"),
        direct_rules: string_array_at(&value, &["direct_access", "rules"]),
    })
}

fn default_runtime_threads() -> usize {
    std::thread::available_parallelism()
        .map(|threads| threads.get())
        .unwrap_or(1)
}

fn str_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    value_at(value, path)?.as_str()
}

fn string_at(value: &Value, path: &[&str]) -> Option<String> {
    str_at(value, path).map(ToOwned::to_owned)
}

fn string_or(value: &Value, path: &[&str], default: &str) -> String {
    str_at(value, path).unwrap_or(default).to_string()
}

fn int_at(value: &Value, path: &[&str]) -> Option<u64> {
    value_at(value, path)?.as_integer().and_then(
        |value| {
            if value >= 0 {
                Some(value as u64)
            } else {
                None
            }
        },
    )
}

fn bool_at(value: &Value, path: &[&str]) -> Option<bool> {
    value_at(value, path)?.as_bool()
}

fn string_array_at(value: &Value, path: &[&str]) -> Vec<String> {
    value_at(value, path)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn value_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter()
        .try_fold(value, |current, key| current.get(*key))
}

fn default_tun_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "ppaass-tun"
    } else if cfg!(target_os = "macos") {
        "utun8"
    } else {
        "tun0"
    }
}

fn locate_config_path() -> Option<PathBuf> {
    let file_names = [
        "agent.toml",
        "config/local/agent.toml",
        "config/remote/agent.toml",
    ];

    for base in ancestor_dirs()
        .into_iter()
        .chain(deployed_agent_dirs().into_iter())
    {
        for file_name in file_names {
            let path = base.join(file_name);
            if path.is_file() {
                return Some(path);
            }
        }
    }
    None
}

fn deployed_agent_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(dir) = DEPLOYED_AGENT_DATA_DIR.get() {
        push_unique_path(&mut dirs, dir.clone());
    }
    if let Ok(app_data) = std::env::var("APPDATA") {
        push_unique_path(&mut dirs, PathBuf::from(app_data).join("com.ppaass.agent"));
    }
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        push_unique_path(
            &mut dirs,
            PathBuf::from(local_app_data).join("com.ppaass.agent"),
        );
    }
    dirs
}

#[cfg(windows)]
fn setup_windows_tray(app: &tauri::App) -> Result<(), String> {
    let icon = app
        .default_window_icon()
        .cloned()
        .ok_or_else(|| "找不到默认窗口图标，无法创建系统托盘".to_string())?;
    let menu = tauri::menu::MenuBuilder::new(app)
        .text(TRAY_SHOW_ID, "显示")
        .separator()
        .text(TRAY_EXIT_ID, "退出")
        .build()
        .map_err(|err| format!("创建系统托盘菜单失败：{err}"))?;

    tauri::tray::TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon)
        .tooltip("PPAASS Desktop Agent")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            TRAY_SHOW_ID => restore_main_window(app),
            TRAY_EXIT_ID => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let tauri::tray::TrayIconEvent::Click {
                button: tauri::tray::MouseButton::Left,
                button_state: tauri::tray::MouseButtonState::Up,
                ..
            } = event
            {
                restore_main_window(tray.app_handle());
            }
        })
        .build(app)
        .map_err(|err| format!("创建系统托盘失败：{err}"))?;

    Ok(())
}

#[cfg(windows)]
fn hide_window_to_tray_after_minimize(window: tauri::Window) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_millis(80)).await;
        if window.is_minimized().unwrap_or(false) {
            let _ = window.hide();
        }
    });
}

#[cfg(windows)]
fn restore_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn ancestor_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(current_dir) = std::env::current_dir() {
        for ancestor in current_dir.ancestors().take(8) {
            dirs.push(ancestor.to_path_buf());
        }
    }
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            for ancestor in parent.ancestors().take(8) {
                dirs.push(ancestor.to_path_buf());
            }
        }
    }
    dirs
}

fn main() {
    #[cfg(target_os = "macos")]
    {
        if std::env::args().any(|arg| arg == TUN_HELPER_SERVICE_ARG) {
            if let Err(err) = run_macos_tun_helper_service_from_args() {
                eprintln!("{err}");
                std::process::exit(1);
            }
            return;
        }
    }

    #[cfg(windows)]
    {
        if std::env::args().any(|arg| arg == INSTALL_SERVICE_ARG) {
            if let Err(err) = install_and_start_windows_service() {
                eprintln!("{err}");
            }
            return;
        }
        if std::env::args().any(|arg| arg == SERVICE_ARG) {
            if let Err(err) = run_windows_service() {
                eprintln!("{err}");
            }
            return;
        }
    }

    let runtime = AgentRuntime::new();
    runtime.logs.install_tracing();
    let setup_logs = runtime.logs.clone();

    tauri::Builder::default()
        .setup(move |app| {
            install_bundled_agent_assets(app, &setup_logs)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
            #[cfg(windows)]
            setup_windows_tray(app).map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
            #[cfg(target_os = "macos")]
            check_macos_tun_helper_on_startup(&setup_logs);
            Ok(())
        })
        .on_window_event(|window, event| {
            #[cfg(not(windows))]
            let _ = (window, event);
            #[cfg(windows)]
            if window.label() == "main" && matches!(event, tauri::WindowEvent::Resized(_)) {
                hide_window_to_tray_after_minimize(window.clone());
            }
        })
        .manage(runtime)
        .invoke_handler(tauri::generate_handler![
            load_agent_config,
            save_agent_config,
            get_agent_state,
            start_agent,
            stop_agent,
            run_connectivity_tests,
            get_network_traffic_snapshot
        ])
        .run(tauri::generate_context!())
        .expect("error while running PPAASS Desktop Agent UI");
}
