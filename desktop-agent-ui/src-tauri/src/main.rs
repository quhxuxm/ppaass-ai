#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream as StdTcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use sysinfo::Networks;
use toml::Value;

#[derive(Default)]
struct AgentRuntime {
    child: Mutex<Option<Child>>,
    config_path: Mutex<Option<PathBuf>>,
}

#[derive(Debug, Serialize)]
struct LoadedAgentConfig {
    path: String,
    raw: String,
    summary: AgentConfigSummary,
}

#[derive(Debug, Serialize)]
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
    agent_reachable: bool,
    generated_at_ms: u128,
    results: Vec<ConnectivityCheck>,
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

#[derive(Debug, Serialize)]
struct NetworkTrafficSnapshot {
    sampled_at_ms: u128,
    total_received_bytes: u64,
    total_transmitted_bytes: u64,
    interfaces: Vec<NetworkInterfaceTraffic>,
}

#[derive(Debug, Serialize)]
struct NetworkInterfaceTraffic {
    name: String,
    received_bytes: u64,
    transmitted_bytes: u64,
}

#[tauri::command]
fn load_agent_config(path: Option<String>) -> Result<LoadedAgentConfig, String> {
    let config_path = match path.filter(|value| !value.trim().is_empty()) {
        Some(value) => PathBuf::from(value),
        None => locate_config_path().ok_or_else(|| {
            "找不到 agent 配置文件。请确认 agent.toml 或 config/local/agent.toml 存在。".to_string()
        })?,
    };

    load_config_from_path(&config_path)
}

#[tauri::command]
fn save_agent_config(path: String, raw: String) -> Result<LoadedAgentConfig, String> {
    let config_path = PathBuf::from(path);
    if let Some(parent) = config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|err| format!("创建配置目录失败：{err}"))?;
    }
    fs::write(&config_path, raw).map_err(|err| format!("保存配置失败：{err}"))?;
    load_config_from_path(&config_path)
}

#[tauri::command]
fn get_agent_state(runtime: tauri::State<'_, AgentRuntime>) -> Result<AgentState, String> {
    agent_state(&runtime)
}

#[tauri::command]
fn start_agent(
    runtime: tauri::State<'_, AgentRuntime>,
    config_path: String,
) -> Result<AgentState, String> {
    let (running, _) = process_status(&runtime)?;
    if running {
        return agent_state(&runtime);
    }

    let binary_path = locate_agent_binary().ok_or_else(|| {
        "找不到 desktop-agent 可执行文件。请先运行 cargo build --release -p desktop-agent-be。"
            .to_string()
    })?;
    let config_path = PathBuf::from(config_path);
    let work_dir = locate_repo_root().unwrap_or_else(|| {
        config_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    });

    let child = Command::new(&binary_path)
        .arg("--config")
        .arg(&config_path)
        .current_dir(work_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| format!("启动 desktop-agent 失败：{err}"))?;

    *runtime
        .config_path
        .lock()
        .map_err(|_| "配置路径状态锁已损坏".to_string())? = Some(config_path);
    *runtime
        .child
        .lock()
        .map_err(|_| "进程状态锁已损坏".to_string())? = Some(child);

    agent_state(&runtime)
}

#[tauri::command]
fn stop_agent(runtime: tauri::State<'_, AgentRuntime>) -> Result<AgentState, String> {
    let mut guard = runtime
        .child
        .lock()
        .map_err(|_| "进程状态锁已损坏".to_string())?;

    if let Some(mut child) = guard.take() {
        let _ = child.kill();
        let _ = child.wait();
    }

    drop(guard);
    agent_state(&runtime)
}

#[tauri::command]
fn run_connectivity_tests(path: Option<String>) -> Result<ConnectivityReport, String> {
    let config_path = match path.filter(|value| !value.trim().is_empty()) {
        Some(value) => PathBuf::from(value),
        None => locate_config_path().ok_or_else(|| {
            "找不到 agent 配置文件。请确认 agent.toml 或 config/local/agent.toml 存在。".to_string()
        })?,
    };
    let raw = fs::read_to_string(&config_path).map_err(|err| format!("读取配置失败：{err}"))?;
    let summary = summarize_config(&raw)?;
    let listen_addr = summary.listen_addr;
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

    let mut results = Vec::new();
    for (target, url) in targets {
        for (protocol, proxy) in &protocols {
            results.push(run_curl_check(target, protocol, url, proxy));
        }
    }

    Ok(ConnectivityReport {
        listen_addr,
        agent_reachable,
        generated_at_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or_default(),
        results,
    })
}

#[tauri::command]
fn get_network_traffic_snapshot() -> Result<NetworkTrafficSnapshot, String> {
    let networks = Networks::new_with_refreshed_list();
    let mut total_received_bytes = 0_u64;
    let mut total_transmitted_bytes = 0_u64;
    let mut interfaces = Vec::new();

    for (name, data) in &networks {
        if is_loopback_interface(name) {
            continue;
        }

        let received_bytes = data.total_received();
        let transmitted_bytes = data.total_transmitted();
        if received_bytes == 0 && transmitted_bytes == 0 {
            continue;
        }

        total_received_bytes = total_received_bytes.saturating_add(received_bytes);
        total_transmitted_bytes = total_transmitted_bytes.saturating_add(transmitted_bytes);
        interfaces.push(NetworkInterfaceTraffic {
            name: name.to_string(),
            received_bytes,
            transmitted_bytes,
        });
    }

    interfaces.sort_by(|left, right| {
        let left_total = left
            .received_bytes
            .saturating_add(left.transmitted_bytes);
        let right_total = right
            .received_bytes
            .saturating_add(right.transmitted_bytes);
        right_total.cmp(&left_total)
    });

    Ok(NetworkTrafficSnapshot {
        sampled_at_ms: current_time_millis(),
        total_received_bytes,
        total_transmitted_bytes,
        interfaces,
    })
}

fn load_config_from_path(path: &Path) -> Result<LoadedAgentConfig, String> {
    let raw = fs::read_to_string(path).map_err(|err| format!("读取配置失败：{err}"))?;
    let summary = summarize_config(&raw)?;
    Ok(LoadedAgentConfig {
        path: path.to_string_lossy().to_string(),
        raw,
        summary,
    })
}

fn current_time_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

fn is_loopback_interface(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase();
    normalized == "lo"
        || normalized == "lo0"
        || normalized.contains("loopback")
        || normalized.contains("pseudo-interface")
}

fn run_curl_check(target: &str, protocol: &str, url: &str, proxy_url: &str) -> ConnectivityCheck {
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

    let output = Command::new(curl_bin)
        .args([
            "-sS",
            "-L",
            "-o",
            null_output,
            "-w",
            "http_code=%{http_code}\ntime_total=%{time_total}\nerrormsg=%{errormsg}\n",
            "--proxy",
            proxy_url,
            "--connect-timeout",
            "10",
            "--max-time",
            "25",
            url,
        ])
        .output();

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
                proxy_url: proxy_url.to_string(),
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
            proxy_url: proxy_url.to_string(),
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
    let (managed_running, pid) = process_status(runtime)?;
    let config_path = runtime
        .config_path
        .lock()
        .map_err(|_| "配置路径状态锁已损坏".to_string())?
        .clone()
        .or_else(locate_config_path);
    let logs = read_recent_logs(config_path.as_deref());
    let external_reachable = if managed_running {
        false
    } else {
        config_path
            .as_deref()
            .and_then(|path| fs::read_to_string(path).ok())
            .and_then(|raw| summarize_config(&raw).ok())
            .and_then(|summary| connect_addr(&summary.listen_addr))
            .map(|addr| StdTcpStream::connect_timeout(&addr, Duration::from_millis(350)).is_ok())
            .unwrap_or(false)
    };

    Ok(AgentState {
        running: managed_running || external_reachable,
        managed: managed_running,
        pid,
        config_path: config_path.map(|path| path.to_string_lossy().to_string()),
        binary_path: locate_agent_binary().map(|path| path.to_string_lossy().to_string()),
        logs,
    })
}

fn process_status(runtime: &AgentRuntime) -> Result<(bool, Option<u32>), String> {
    let mut guard = runtime
        .child
        .lock()
        .map_err(|_| "进程状态锁已损坏".to_string())?;

    match guard.as_mut() {
        Some(child) => match child.try_wait() {
            Ok(Some(_)) => {
                *guard = None;
                Ok((false, None))
            }
            Ok(None) => Ok((true, guard.as_ref().map(Child::id))),
            Err(err) => Err(format!("读取 agent 进程状态失败：{err}")),
        },
        None => Ok((false, None)),
    }
}

fn read_recent_logs(config_path: Option<&Path>) -> Vec<String> {
    let config = config_path.and_then(|path| fs::read_to_string(path).ok());
    let summary = config.as_deref().and_then(|raw| summarize_config(raw).ok());

    let mut candidates = Vec::new();
    if let Some(summary) = summary {
        if let Some(log_dir) = summary.log_dir {
            candidates.push(PathBuf::from(log_dir).join(summary.log_file));
        }
    }
    for base in ancestor_dirs() {
        candidates.push(base.join("logs").join("desktop-agent.log"));
        candidates.push(base.join("desktop-agent.log"));
    }

    for path in candidates {
        if let Ok(content) = fs::read_to_string(path) {
            let mut lines = content
                .lines()
                .rev()
                .take(80)
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>();
            lines.reverse();
            return lines;
        }
    }
    Vec::new()
}

fn summarize_config(raw: &str) -> Result<AgentConfigSummary, String> {
    let value = raw
        .parse::<Value>()
        .map_err(|err| format!("配置 TOML 解析失败：{err}"))?;

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
        runtime_threads: int_at(&value, &["runtime_threads"]).map(|value| value as usize),
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

    for base in ancestor_dirs() {
        for file_name in file_names {
            let path = base.join(file_name);
            if path.is_file() {
                return Some(path);
            }
        }
    }
    None
}

fn locate_agent_binary() -> Option<PathBuf> {
    let binary_name = if cfg!(target_os = "windows") {
        "desktop-agent.exe"
    } else {
        "desktop-agent"
    };

    for base in ancestor_dirs() {
        for path in [
            base.join(binary_name),
            base.join("target").join("release").join(binary_name),
            base.join("target").join("debug").join(binary_name),
        ] {
            if path.is_file() {
                return Some(path);
            }
        }
    }
    None
}

fn locate_repo_root() -> Option<PathBuf> {
    ancestor_dirs()
        .into_iter()
        .find(|base| base.join("Cargo.toml").is_file() && base.join("desktop-agent-be").is_dir())
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
    tauri::Builder::default()
        .manage(AgentRuntime::default())
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
