use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tauri::path::BaseDirectory;
use tauri::Manager;
use tempfile::Builder;
use toml::Value;
use toml_edit::{value, DocumentMut};

use crate::logging::UiLogBuffer;
use crate::models::{AgentConfigSummary, LoadedAgentConfig};

const BUNDLED_AGENT_CONFIG_PATH: &str = "agent.toml";
// Windows Service must load wintun.dll from the protected installation directory.
// Never deploy executable code into the user-writable Agent data directory.
const BUNDLED_AGENT_SUPPORT_FILES: &[(&str, &str)] = &[];
const LEGACY_BUNDLED_DEMO_KEYS: &[(&str, &str)] = &[
    (
        "keys/user1.pem",
        "f643613d2d534bd85a8ee6022c91a1c526eec013922d1cb178a03e22a9a4f71c",
    ),
    (
        "keys/user2.pem",
        "9a237dc718f468584f094c02482bdef4ca89c1f7ed855a03ac7880e027025288",
    ),
];

// UDP Yamux 保持较小默认值，避免普通 UDP/QUIC 场景创建过多长期外层 TCP。
const DEFAULT_UDP_YAMUX_SESSIONS: u64 = 5;
const DEFAULT_UDP_SESSION_POOL_SIZE: u64 = 4;
const MAX_UDP_SESSION_POOL_SIZE: u64 = 8;

static DEPLOYED_AGENT_DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

pub(crate) fn load_config_from_path(path: &Path) -> Result<LoadedAgentConfig, String> {
    let config_path = make_absolute_path(path);
    let raw = fs::read_to_string(&config_path).map_err(|err| format!("读取配置失败：{err}"))?;
    loaded_config_from_raw(config_path, raw)
}

pub(crate) fn proxy_web_url_from_config(path: &Path) -> Result<String, String> {
    let config_path = make_absolute_path(path);
    let raw = fs::read_to_string(&config_path)
        .map_err(|_| "无法读取 Agent 认证服务配置，请联系管理员".to_string())?;
    proxy_web_url_from_raw(&raw)
}

fn proxy_web_url_from_raw(raw: &str) -> Result<String, String> {
    let config =
        toml::from_str::<Value>(raw).map_err(|_| "Agent 配置格式无效，请联系管理员".to_string())?;
    str_at(&config, &["proxy_web_url"])
        .map(ToOwned::to_owned)
        .ok_or_else(|| "Agent 缺少认证服务配置，请联系管理员".to_string())
}

pub(crate) fn load_default_config(
    app: &tauri::AppHandle,
    current_path: Option<&str>,
) -> Result<LoadedAgentConfig, String> {
    let default_path = default_agent_config_resource_path(app)?;
    let raw = fs::read_to_string(&default_path)
        .map_err(|err| format!("读取默认配置失败：{}：{err}", default_path.display()))?;
    let config_path = current_path
        .filter(|value| !value.trim().is_empty())
        .map(|value| make_absolute_path(Path::new(value)))
        .or_else(locate_config_path)
        .unwrap_or_else(|| make_absolute_path(Path::new("agent.toml")));

    loaded_config_from_raw(config_path, raw)
}

fn loaded_config_from_raw(config_path: PathBuf, raw: String) -> Result<LoadedAgentConfig, String> {
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

pub(crate) fn write_config_file(path: &Path, raw: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| format!("配置文件路径缺少父目录：{}", path.display()))?;
    fs::create_dir_all(parent).map_err(|err| format!("创建配置目录失败：{err}"))?;
    clear_readonly_file_attribute(path)
        .map_err(|err| format!("准备写入配置失败：{}：{err}", path.display()))?;
    let existing_permissions = fs::metadata(path)
        .ok()
        .map(|metadata| metadata.permissions());
    let mut temporary = Builder::new()
        .prefix(".agent-config-")
        .tempfile_in(parent)
        .map_err(|err| format!("创建配置临时文件失败：{}：{err}", parent.display()))?;
    if let Some(permissions) = existing_permissions {
        temporary
            .as_file()
            .set_permissions(permissions)
            .map_err(|err| format!("保留配置文件权限失败：{err}"))?;
    }
    temporary
        .write_all(raw.as_bytes())
        .map_err(|err| format!("写入配置失败：{err}"))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|err| format!("同步配置到磁盘失败：{err}"))?;
    temporary
        .persist(path)
        .map_err(|err| format!("保存配置失败：{}：{}", path.display(), err.error))?;
    if let Ok(directory) = fs::File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

pub(crate) fn apply_managed_credentials_to_config(
    path: &Path,
    username: &str,
    private_key_path: &Path,
    proxy_identity_public_key_path: &Path,
) -> Result<LoadedAgentConfig, String> {
    let config_path = make_absolute_path(path);
    let loaded = load_config_from_path(&config_path)?;
    let proxy_web_url = proxy_web_url_from_raw(&loaded.raw)?;
    let raw = enforce_managed_identity(
        &loaded.raw,
        username,
        private_key_path,
        proxy_identity_public_key_path,
        &proxy_web_url,
    )?;
    write_config_file(&config_path, &raw)?;

    if let Some(primary_path) = primary_agent_config_path(&config_path) {
        write_config_file(&primary_path, &raw)?;
        load_config_from_path(&primary_path)
    } else {
        load_config_from_path(&config_path)
    }
}

pub(crate) fn clear_managed_credentials_from_config(path: &Path) -> Result<(), String> {
    let config_path = make_absolute_path(path);
    let loaded = load_config_from_path(&config_path)?;
    let mut document = loaded
        .raw
        .parse::<DocumentMut>()
        .map_err(|err| format!("配置 TOML 解析失败：{err}"))?;
    document.remove("username");
    document.remove("private_key_path");
    document.remove("proxy_identity_public_key_path");
    let raw = document.to_string();
    summarize_config(&raw)?;
    write_config_file(&config_path, &raw)?;
    if let Some(primary_path) = primary_agent_config_path(&config_path) {
        write_config_file(&primary_path, &raw)?;
    }
    Ok(())
}

pub(crate) fn enforce_managed_identity(
    raw: &str,
    username: &str,
    private_key_path: &Path,
    proxy_identity_public_key_path: &Path,
    proxy_web_url: &str,
) -> Result<String, String> {
    let mut document = raw
        .parse::<DocumentMut>()
        .map_err(|err| format!("配置 TOML 解析失败：{err}"))?;
    document["username"] = value(username);
    document["private_key_path"] = value(private_key_path.to_string_lossy().as_ref());
    document["proxy_identity_public_key_path"] =
        value(proxy_identity_public_key_path.to_string_lossy().as_ref());
    document["proxy_web_url"] = value(proxy_web_url);
    let managed_raw = document.to_string();
    summarize_config(&managed_raw)?;
    Ok(managed_raw)
}

pub(crate) fn redact_managed_identity(
    mut loaded: LoadedAgentConfig,
) -> Result<LoadedAgentConfig, String> {
    let mut document = loaded
        .raw
        .parse::<DocumentMut>()
        .map_err(|err| format!("配置 TOML 解析失败：{err}"))?;
    document.remove("username");
    document.remove("private_key_path");
    document.remove("proxy_identity_public_key_path");
    document.remove("proxy_web_url");
    loaded.raw = document.to_string();
    loaded.summary.username.clear();
    loaded.summary.private_key_path.clear();
    Ok(loaded)
}

pub(crate) fn toggle_tun_enabled_in_config(
    path: Option<&Path>,
) -> Result<LoadedAgentConfig, String> {
    let config_path = resolve_config_path(path)?;
    let loaded = load_config_from_path(&config_path)?;
    write_tun_enabled_to_config(&config_path, &loaded.raw, !loaded.summary.tun_enabled)
}

fn resolve_config_path(path: Option<&Path>) -> Result<PathBuf, String> {
    match path {
        Some(path) => Ok(make_absolute_path(path)),
        None => locate_config_path().ok_or_else(|| {
            "找不到 agent 配置文件。请确认 agent.toml 或 config/local/agent.toml 存在。".to_string()
        }),
    }
}

fn write_tun_enabled_to_config(
    config_path: &Path,
    raw: &str,
    enabled: bool,
) -> Result<LoadedAgentConfig, String> {
    let raw = upsert_toml_bool(raw, "tun", "enabled", enabled);
    write_config_file(config_path, &raw)?;

    if let Some(primary_path) = primary_agent_config_path(config_path) {
        write_config_file(&primary_path, &raw)?;
        load_config_from_path(&primary_path)
    } else {
        load_config_from_path(config_path)
    }
}

pub(crate) fn primary_agent_config_path(path: &Path) -> Option<PathBuf> {
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

pub(crate) fn install_bundled_agent_assets(
    app: &tauri::App,
    logs: &UiLogBuffer,
) -> Result<(), String> {
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|err| format!("定位 Agent 数据目录失败：{err}"))?;
    fs::create_dir_all(&app_data_dir)
        .map_err(|err| format!("创建 Agent 数据目录失败：{}：{err}", app_data_dir.display()))?;
    let _ = DEPLOYED_AGENT_DATA_DIR.set(app_data_dir.clone());

    let config_resource_path = bundled_agent_config_resource(cfg!(debug_assertions));
    let bundled_files = std::iter::once((config_resource_path, BUNDLED_AGENT_CONFIG_PATH))
        .chain(BUNDLED_AGENT_SUPPORT_FILES.iter().copied());

    for (resource_path, deploy_path) in bundled_files {
        let destination = app_data_dir.join(deploy_path);
        if destination.exists() {
            logs.push(format!("保留已有 Agent 资源：{}", destination.display()));
            continue;
        }
        let source = bundled_agent_resource_path(app, resource_path)?;

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
        if deploy_path.ends_with("agent.toml") {
            clear_readonly_file_attribute(&destination).map_err(|err| {
                format!(
                    "准备 Agent 配置资源可写失败：{}：{err}",
                    destination.display()
                )
            })?;
        }
        logs.push(format!("已部署默认 Agent 资源：{}", destination.display()));
    }

    if !cfg!(debug_assertions) {
        remove_legacy_bundled_demo_keys(&app_data_dir, logs);
    }

    Ok(())
}

fn remove_legacy_bundled_demo_keys(app_data_dir: &Path, logs: &UiLogBuffer) {
    for (relative_path, expected_sha256) in LEGACY_BUNDLED_DEMO_KEYS {
        let path = app_data_dir.join(relative_path);
        if !path.is_file() {
            continue;
        }
        let Ok(bytes) = fs::read(&path) else {
            logs.push(format!(
                "无法读取旧版演示私钥，未自动清理：{}",
                path.display()
            ));
            continue;
        };
        let actual_sha256 = Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if actual_sha256 != *expected_sha256 {
            continue;
        }
        match fs::remove_file(&path) {
            Ok(()) => logs.push(format!("已清理旧版内置演示私钥：{}", path.display())),
            Err(_) => logs.push(format!("无法清理旧版内置演示私钥：{}", path.display())),
        }
    }
}

fn bundled_agent_config_resource(debug: bool) -> &'static str {
    if debug {
        "config/local/agent.toml"
    } else {
        "config/remote/agent.toml"
    }
}

pub(crate) fn summarize_config(raw: &str) -> Result<AgentConfigSummary, String> {
    let value = toml::from_str::<Value>(raw).map_err(|err| format!("配置 TOML 解析失败：{err}"))?;
    if value_at(&value, &["quic_connection_pool_size"]).is_some() {
        return Err(
            "配置字段 quic_connection_pool_size 已移除，请使用 udp_session_pool_size".to_string(),
        );
    }
    for (removed, current) in [
        ("helper_enabled", "macos_helper_enabled"),
        ("helper_socket", "macos_helper_socket"),
        (
            "helper_fallback_to_privilege",
            "macos_helper_fallback_to_privilege",
        ),
    ] {
        if value_at(&value, &["tun", removed]).is_some() {
            return Err(format!(
                "配置字段 tun.{removed} 已移除，请使用 tun.{current}"
            ));
        }
    }
    let transport_mode =
        normalize_transport_mode(str_at(&value, &["transport_mode"]).unwrap_or("udp"))?;
    let tun_quic_policy = normalize_quic_policy(
        string_at(&value, &["tun", "quic_policy"])
            .as_deref()
            .unwrap_or("allow"),
    );
    let runtime_threads = int_at(&value, &["runtime_threads"])
        .filter(|value| *value > 0)
        .map(|value| value as usize);

    Ok(AgentConfigSummary {
        listen_addr: string_or(&value, &["listen_addr"], "0.0.0.0:10080"),
        proxy_addrs: string_array_at(&value, &["proxy_addrs"]),
        username: string_or(&value, &["username"], ""),
        private_key_path: string_or(&value, &["private_key_path"], ""),
        transport_mode,
        udp_session_pool_size: int_at(&value, &["udp_session_pool_size"])
            .unwrap_or(DEFAULT_UDP_SESSION_POOL_SIZE)
            .clamp(1, MAX_UDP_SESSION_POOL_SIZE) as usize,
        connect_timeout_secs: int_at(&value, &["connect_timeout_secs"]).unwrap_or(30),
        compression_mode: string_or(&value, &["compression_mode"], "none"),
        log_level: string_or(&value, &["log_level"], "info"),
        log_dir: string_at(&value, &["log_dir"]),
        log_file: string_or(&value, &["log_file"], "desktop-agent.log"),
        runtime_threads,
        effective_runtime_threads: runtime_threads.unwrap_or_else(default_runtime_threads),
        udp_yamux_sessions: int_at(&value, &["yamux", "udp", "sessions"])
            .unwrap_or(DEFAULT_UDP_YAMUX_SESSIONS) as usize,
        udp_yamux_max_streams_per_session: int_at(
            &value,
            &["yamux", "udp", "max_streams_per_session"],
        )
        .unwrap_or(256) as usize,
        udp_yamux_open_stream_timeout_secs: int_at(
            &value,
            &["yamux", "udp", "open_stream_timeout_secs"],
        )
        .unwrap_or(10),
        udp_yamux_keepalive_interval_secs: int_at(
            &value,
            &["yamux", "udp", "keepalive_interval_secs"],
        )
        .unwrap_or(30),
        udp_yamux_connection_write_timeout_secs: int_at(
            &value,
            &["yamux", "udp", "connection_write_timeout_secs"],
        )
        .unwrap_or(10),
        udp_yamux_stream_window_size_kb: int_at(&value, &["yamux", "udp", "stream_window_size_kb"])
            .unwrap_or(8192) as usize,
        tun_enabled: bool_at(&value, &["tun", "enabled"]).unwrap_or(false),
        tun_name: string_or(&value, &["tun", "name"], default_tun_name()),
        tun_ipv4: string_or(&value, &["tun", "ipv4"], "10.10.10.1/24"),
        tun_mtu: int_at(&value, &["tun", "mtu"]).unwrap_or(1500),
        tun_proxy_udp: bool_at(&value, &["tun", "proxy_udp"]).unwrap_or(true),
        tun_proxy_dns: bool_at(&value, &["tun", "proxy_dns"]).unwrap_or(true),
        tun_quic_policy,
        tun_packet_capture_file: string_or(
            &value,
            &["tun", "packet_capture", "file"],
            "captures/ppaass-tun.pcap",
        ),
        direct_mode: string_or(&value, &["direct_access", "mode"], "proxy_all"),
        direct_rules: string_array_at(&value, &["direct_access", "rules"]),
    })
}

pub(crate) fn locate_config_path() -> Option<PathBuf> {
    let file_names = [
        "agent.toml",
        "config/local/agent.toml",
        "config/remote/agent.toml",
    ];

    for base in config_search_dirs() {
        for file_name in file_names {
            let path = base.join(file_name);
            if path.is_file() {
                return Some(path);
            }
        }
    }
    None
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

fn default_agent_config_resource_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let resource_path = bundled_agent_config_resource(cfg!(debug_assertions));
    if let Ok(path) = app.path().resolve(resource_path, BaseDirectory::Resource) {
        if path.is_file() {
            return Ok(path);
        }
    }

    ancestor_dirs()
        .into_iter()
        .map(|base| base.join(resource_path))
        .find(|path| path.is_file())
        .ok_or_else(|| format!("找不到内置 Agent 默认配置：{resource_path}"))
}

fn clear_readonly_file_attribute(path: &Path) -> io::Result<()> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    if !metadata.is_file() || !metadata.permissions().readonly() {
        return Ok(());
    }

    let mut permissions = metadata.permissions();
    clear_readonly_permissions(&mut permissions);
    fs::set_permissions(path, permissions)
}

#[cfg(unix)]
fn clear_readonly_permissions(permissions: &mut fs::Permissions) {
    permissions.set_mode(permissions.mode() | 0o200);
}

#[cfg(not(unix))]
fn clear_readonly_permissions(permissions: &mut fs::Permissions) {
    permissions.set_readonly(false);
}

fn upsert_toml_bool(raw: &str, section: &str, key: &str, value: bool) -> String {
    let mut lines = raw.lines().map(str::to_string).collect::<Vec<_>>();
    let assignment = format!("{key} = {}", if value { "true" } else { "false" });
    let section_header = format!("[{section}]");
    let section_start = lines
        .iter()
        .position(|line| line.trim() == section_header.as_str());

    if let Some(section_start) = section_start {
        let section_end = lines
            .iter()
            .enumerate()
            .skip(section_start + 1)
            .find_map(|(index, line)| {
                if line.trim().starts_with('[') && line.trim().ends_with(']') {
                    Some(index)
                } else {
                    None
                }
            })
            .unwrap_or(lines.len());

        if let Some(existing_index) = lines
            .iter()
            .enumerate()
            .take(section_end)
            .skip(section_start + 1)
            .find_map(|(index, line)| {
                let trimmed = line.trim_start();
                if trimmed.starts_with(key) && trimmed[key.len()..].trim_start().starts_with('=') {
                    Some(index)
                } else {
                    None
                }
            })
        {
            lines[existing_index] = assignment;
        } else {
            lines.insert(section_end, assignment);
        }
    } else {
        if !lines.is_empty() && !raw.ends_with('\n') {
            lines.push(String::new());
        }
        lines.push(section_header);
        lines.push(assignment);
    }

    let mut next = lines.join("\n");
    if raw.ends_with('\n') {
        next.push('\n');
    }
    next
}

fn default_runtime_threads() -> usize {
    std::thread::available_parallelism()
        .map(|threads| threads.get())
        .unwrap_or(1)
}

fn config_search_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if cfg!(debug_assertions) {
        for dir in ancestor_dirs().into_iter().chain(deployed_agent_dirs()) {
            push_unique_path(&mut dirs, dir);
        }
    } else {
        for dir in deployed_agent_dirs().into_iter().chain(ancestor_dirs()) {
            push_unique_path(&mut dirs, dir);
        }
    }
    dirs
}

fn str_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    value_at(value, path)?
        .as_str()
        .filter(|value| !value.trim().is_empty())
}

fn string_at(value: &Value, path: &[&str]) -> Option<String> {
    str_at(value, path).map(ToOwned::to_owned)
}

fn string_or(value: &Value, path: &[&str], default: &str) -> String {
    str_at(value, path).unwrap_or(default).to_string()
}

fn int_at(value: &Value, path: &[&str]) -> Option<u64> {
    let value = value_at(value, path)?.as_integer()?;
    if value >= 0 {
        Some(value as u64)
    } else {
        None
    }
}

fn bool_at(value: &Value, path: &[&str]) -> Option<bool> {
    value_at(value, path)?.as_bool()
}

fn string_array_at(value: &Value, path: &[&str]) -> Vec<String> {
    let Some(items) = array_at(value, path) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect()
}

fn normalize_quic_policy(value: &str) -> String {
    match value {
        "allow" | "block" => value.to_string(),
        _ => "allow".to_string(),
    }
}

fn normalize_transport_mode(value: &str) -> Result<String, String> {
    match value {
        "auto" | "udp" | "tcp" => Ok(value.to_string()),
        _ => Err(format!(
            "transport_mode 只支持 auto、udp 或 tcp，当前值为 {value:?}"
        )),
    }
}

fn array_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a [Value]> {
    let items = value_at(value, path)?.as_array()?;
    Some(items.as_slice())
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

pub(crate) fn make_absolute_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }

    std::env::current_dir()
        .map(|cwd| cwd.join(path))
        .unwrap_or_else(|_| path.to_path_buf())
}

fn push_unique_path(candidates: &mut Vec<PathBuf>, path: PathBuf) {
    if !candidates.iter().any(|candidate| candidate == &path) {
        candidates.push(path);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        apply_managed_credentials_to_config, bundled_agent_config_resource,
        clear_managed_credentials_from_config, enforce_managed_identity, load_config_from_path,
        proxy_web_url_from_config, redact_managed_identity, summarize_config,
        toggle_tun_enabled_in_config, upsert_toml_bool, write_config_file,
    };
    use crate::models::LoadedAgentConfig;
    use std::fs;

    #[test]
    fn write_config_file_overwrites_readonly_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        fs::write(&path, "username = \"old\"\n").unwrap();

        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&path, permissions).unwrap();

        write_config_file(&path, "username = \"new\"\n").unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "username = \"new\"\n");
        assert!(!fs::metadata(&path).unwrap().permissions().readonly());
    }

    #[test]
    fn toggle_tun_enabled_in_config_flips_current_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        fs::write(&path, "[tun]\nenabled = false\n").unwrap();

        let loaded = toggle_tun_enabled_in_config(Some(&path)).unwrap();
        assert!(loaded.summary.tun_enabled);
        assert!(loaded.summary.tun_proxy_dns);
        assert!(fs::read_to_string(&path)
            .unwrap()
            .contains("enabled = true"));

        let loaded = toggle_tun_enabled_in_config(Some(&path)).unwrap();
        assert!(!loaded.summary.tun_enabled);
        assert!(fs::read_to_string(&path)
            .unwrap()
            .contains("enabled = false"));

        fs::write(&path, "[tun]\nenabled = false\nproxy_dns = false\n").unwrap();
        let explicitly_disabled_dns = toggle_tun_enabled_in_config(Some(&path)).unwrap();
        assert!(explicitly_disabled_dns.summary.tun_enabled);
        assert!(!explicitly_disabled_dns.summary.tun_proxy_dns);
        assert!(fs::read_to_string(&path)
            .unwrap()
            .contains("proxy_dns = false"));
    }

    #[test]
    fn summarize_config_preserves_udp_yamux_settings() {
        let summary = summarize_config(
            r#"
listen_addr = "0.0.0.0:10080"
proxy_addrs = ["127.0.0.1:8080"]
username = "user1"
private_key_path = "keys/user1.pem"

[yamux.udp]
sessions = 3
max_streams_per_session = 32
open_stream_timeout_secs = 5
keepalive_interval_secs = 0
connection_write_timeout_secs = 9
stream_window_size_kb = 1024
"#,
        )
        .unwrap();

        assert_eq!(summary.udp_yamux_sessions, 3);
        assert_eq!(summary.udp_yamux_max_streams_per_session, 32);
        assert_eq!(summary.udp_yamux_open_stream_timeout_secs, 5);
        assert_eq!(summary.udp_yamux_keepalive_interval_secs, 0);
        assert_eq!(summary.udp_yamux_connection_write_timeout_secs, 9);
        assert_eq!(summary.udp_yamux_stream_window_size_kb, 1024);
    }

    #[test]
    fn summarize_config_defaults_to_udp_and_clamps_udp_session_pool_size() {
        let base = r#"
listen_addr = "0.0.0.0:10080"
proxy_addrs = ["127.0.0.1:8080"]
username = "user1"
private_key_path = "keys/user1.pem"
"#;

        let default_summary = summarize_config(base).unwrap();
        assert_eq!(default_summary.transport_mode, "udp");
        assert_eq!(
            summarize_config(&format!("{base}transport_mode = \"auto\"\n"))
                .unwrap()
                .transport_mode,
            "auto"
        );
        assert_eq!(default_summary.udp_session_pool_size, 4);
        assert_eq!(
            summarize_config(&format!("{base}udp_session_pool_size = 0\n"))
                .unwrap()
                .udp_session_pool_size,
            1
        );
        assert_eq!(
            summarize_config(&format!("{base}udp_session_pool_size = 64\n"))
                .unwrap()
                .udp_session_pool_size,
            8
        );
        assert_eq!(
            summarize_config(&format!("{base}udp_session_pool_size = 6\n"))
                .unwrap()
                .udp_session_pool_size,
            6
        );
    }

    #[test]
    fn summarize_config_rejects_removed_quic_transport_configuration() {
        let removed_mode = summarize_config("transport_mode = \"quic\"\n");
        assert!(removed_mode.is_err());

        let removed_pool = summarize_config("quic_connection_pool_size = 4\n");
        assert!(removed_pool.is_err());
    }

    #[test]
    fn summarize_config_rejects_removed_tun_helper_fields() {
        for (removed, current) in [
            ("helper_enabled", "macos_helper_enabled"),
            ("helper_socket", "macos_helper_socket"),
            (
                "helper_fallback_to_privilege",
                "macos_helper_fallback_to_privilege",
            ),
        ] {
            let error = summarize_config(&format!("[tun]\n{removed} = true\n")).unwrap_err();

            assert!(error.contains(current));
        }
    }

    #[test]
    fn summarize_config_allows_tun_quic_by_default() {
        let summary = summarize_config(
            r#"
listen_addr = "0.0.0.0:10080"
proxy_addrs = ["127.0.0.1:8080"]
username = "user1"
private_key_path = "keys/user1.pem"
"#,
        )
        .unwrap();

        assert_eq!(summary.tun_quic_policy, "allow");
    }

    #[test]
    fn summarize_config_proxies_tun_udp_by_default() {
        let summary = summarize_config(
            r#"
listen_addr = "0.0.0.0:10080"
proxy_addrs = ["127.0.0.1:8080"]
username = "user1"
private_key_path = "keys/user1.pem"
"#,
        )
        .unwrap();

        assert!(summary.tun_proxy_udp);
    }

    #[test]
    fn summarize_config_uses_default_tun_dns_proxy() {
        let summary = summarize_config(
            r#"
listen_addr = "0.0.0.0:10080"
proxy_addrs = ["127.0.0.1:8080"]

[tun]
enabled = true
"#,
        )
        .unwrap();

        assert!(summary.tun_enabled);
        assert!(summary.tun_proxy_dns);
    }

    #[test]
    fn summarize_config_preserves_explicitly_disabled_tun_dns_proxy() {
        let summary = summarize_config(
            r#"
listen_addr = "0.0.0.0:10080"
proxy_addrs = ["127.0.0.1:8080"]

[tun]
enabled = true
proxy_dns = false
"#,
        )
        .unwrap();

        assert!(summary.tun_enabled);
        assert!(!summary.tun_proxy_dns);
    }

    #[test]
    fn summarize_config_reads_disabled_tun_udp_proxy() {
        let summary = summarize_config(
            r#"
listen_addr = "0.0.0.0:10080"
proxy_addrs = ["127.0.0.1:8080"]
username = "user1"
private_key_path = "keys/user1.pem"

[tun]
proxy_udp = false
"#,
        )
        .unwrap();

        assert!(!summary.tun_proxy_udp);
    }

    #[test]
    fn summarize_config_reads_block_policy() {
        let summary = summarize_config(
            r#"
listen_addr = "0.0.0.0:10080"
proxy_addrs = ["127.0.0.1:8080"]
username = "user1"
private_key_path = "keys/user1.pem"

[tun]
quic_policy = "block"
"#,
        )
        .unwrap();

        assert_eq!(summary.tun_quic_policy, "block");
    }

    #[test]
    fn summarize_config_reads_packet_capture() {
        let summary = summarize_config(
            r#"
listen_addr = "0.0.0.0:10080"
proxy_addrs = ["127.0.0.1:8080"]
username = "user1"
private_key_path = "keys/user1.pem"

[tun.packet_capture]
file = "captures/debug.pcap"
"#,
        )
        .unwrap();

        assert_eq!(summary.tun_packet_capture_file, "captures/debug.pcap");
    }

    #[test]
    fn upsert_toml_bool_updates_or_adds_nested_key() {
        let updated = upsert_toml_bool(
            r#"listen_addr = "0.0.0.0:10080"

[tun]
enabled = false
name = "ppaass-tun"
"#,
            "tun",
            "enabled",
            true,
        );
        assert!(updated.contains("[tun]\nenabled = true\nname = \"ppaass-tun\""));

        let inserted = upsert_toml_bool("username = \"user1\"\n", "tun", "enabled", true);
        assert!(inserted.contains("[tun]\nenabled = true"));
    }

    #[test]
    fn enforce_managed_identity_overrides_quoted_keys_and_escapes_paths() {
        let raw = concat!(
            "\"username\" = \"attacker\"\n",
            "\"private_key_path\" = \"attacker.pem\"\n\n",
            "\"proxy_identity_public_key_path\" = \"attacker-identity.pem\"\n",
            "[tun]\n",
            "enabled = false\n",
        );
        let key_path = std::path::Path::new(r#"C:\Users\me\private "key".pem"#);
        let identity_path = std::path::Path::new(r#"C:\Users\me\proxy identity.pem"#);
        let updated = enforce_managed_identity(
            raw,
            "new-user",
            key_path,
            identity_path,
            "https://managed.example.com",
        )
        .unwrap();
        let summary = summarize_config(&updated).unwrap();
        assert_eq!(summary.username, "new-user");
        assert_eq!(summary.private_key_path, r#"C:\Users\me\private "key".pem"#);
        assert!(updated.contains("[tun]\nenabled = false"));
        assert!(!updated.contains("attacker"));
    }

    #[test]
    fn redact_managed_identity_removes_credentials_from_ui_config() {
        let raw = concat!(
            "# identity is managed by Proxy Web\n",
            "\"username\" = \"alice\"\n",
            "\"private_key_path\" = \"/secret/managed.pem\"\n",
            "\"proxy_identity_public_key_path\" = \"/secret/proxy-identity.pem\"\n",
            "\"proxy_web_url\" = \"https://hidden.example.com\"\n",
            "listen_addr = \"127.0.0.1:10080\"\n\n",
            "[tun]\n",
            "enabled = false\n",
        );
        let loaded = LoadedAgentConfig {
            path: "/tmp/agent.toml".to_string(),
            raw: raw.to_string(),
            summary: summarize_config(raw).unwrap(),
        };

        let redacted = redact_managed_identity(loaded).unwrap();
        assert!(!redacted.raw.contains("username"));
        assert!(!redacted.raw.contains("private_key_path"));
        assert!(!redacted.raw.contains("proxy_identity_public_key_path"));
        assert!(!redacted.raw.contains("proxy_web_url"));
        assert!(!redacted.raw.contains("hidden.example.com"));
        assert!(!redacted.raw.contains("/secret/managed.pem"));
        assert!(redacted.raw.contains("listen_addr = \"127.0.0.1:10080\""));
        assert!(redacted.raw.contains("[tun]\nenabled = false"));
        assert!(redacted.summary.username.is_empty());
        assert!(redacted.summary.private_key_path.is_empty());

        let serialized = serde_json::to_string(&redacted).unwrap();
        assert!(!serialized.contains("username"));
        assert!(!serialized.contains("private_key_path"));
        assert!(!serialized.contains("proxy_identity_public_key_path"));
        assert!(!serialized.contains("proxy_web_url"));
        assert!(!serialized.contains("hidden.example.com"));
        assert!(!serialized.contains("/secret/managed.pem"));
    }

    #[test]
    fn applies_managed_credentials_without_changing_other_config() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent.toml");
        fs::write(
            &path,
            "listen_addr = \"127.0.0.1:10080\"\nproxy_web_url = \"https://hidden.example.com\"\nusername = \"old\"\nprivate_key_path = \"old.pem\"\n\n[tun]\nenabled = false\n",
        )
        .unwrap();
        let key_path = directory.path().join("credentials/new.pem");
        let identity_path = directory
            .path()
            .join("credentials/proxy-identity-public.pem");
        let loaded =
            apply_managed_credentials_to_config(&path, "alice", &key_path, &identity_path).unwrap();
        assert_eq!(loaded.summary.username, "alice");
        assert_eq!(loaded.summary.private_key_path, key_path.to_string_lossy());
        assert_eq!(loaded.summary.listen_addr, "127.0.0.1:10080");
        assert!(!loaded.summary.tun_enabled);
        assert_eq!(
            proxy_web_url_from_config(&path).unwrap(),
            "https://hidden.example.com"
        );
    }

    #[test]
    fn managed_identity_round_trip_keeps_secret_on_disk_but_not_in_ui() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent.toml");
        let key_path = directory.path().join("credentials/managed.pem");
        let identity_path = directory
            .path()
            .join("credentials/proxy-identity-public.pem");
        fs::write(
            &path,
            "listen_addr = \"127.0.0.1:10080\"\nproxy_web_url = \"https://hidden.example.com\"\nusername = \"old\"\nprivate_key_path = \"old.pem\"\n",
        )
        .unwrap();

        let loaded =
            apply_managed_credentials_to_config(&path, "alice", &key_path, &identity_path).unwrap();
        let redacted = redact_managed_identity(loaded).unwrap();
        assert!(!redacted.raw.contains("private_key_path"));
        assert!(!redacted.raw.contains("proxy_web_url"));

        let edited = format!(
            "{}proxy_web_url = \"https://attacker.example.com\"\ntransport_mode = \"tcp\"\n",
            redacted.raw
        );
        let enforced = enforce_managed_identity(
            &edited,
            "alice",
            &key_path,
            &identity_path,
            "https://hidden.example.com",
        )
        .unwrap();
        write_config_file(&path, &enforced).unwrap();
        let persisted = load_config_from_path(&path).unwrap();
        assert_eq!(persisted.summary.username, "alice");
        assert_eq!(
            persisted.summary.private_key_path,
            key_path.to_string_lossy()
        );
        assert_eq!(persisted.summary.transport_mode, "tcp");
        assert_eq!(
            proxy_web_url_from_config(&path).unwrap(),
            "https://hidden.example.com"
        );
        assert!(!persisted.raw.contains("attacker.example.com"));
    }

    #[test]
    fn clearing_managed_credentials_preserves_hidden_proxy_web_endpoint() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent.toml");
        fs::write(
            &path,
            "proxy_web_url = \"https://hidden.example.com\"\nusername = \"alice\"\nprivate_key_path = \"credentials/managed.pem\"\nproxy_identity_public_key_path = \"credentials/proxy-identity-public.pem\"\ntransport_mode = \"tcp\"\n",
        )
        .unwrap();

        clear_managed_credentials_from_config(&path).unwrap();

        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("username"));
        assert!(!raw.contains("private_key_path"));
        assert!(!raw.contains("proxy_identity_public_key_path"));
        assert!(raw.contains("proxy_web_url = \"https://hidden.example.com\""));
        assert!(raw.contains("transport_mode = \"tcp\""));
    }

    #[test]
    fn proxy_web_url_must_exist_in_desktop_agent_config() {
        let directory = tempfile::tempdir().unwrap();
        let configured = directory.path().join("configured.toml");
        let missing = directory.path().join("missing.toml");
        fs::write(&configured, "proxy_web_url = \"http://127.0.0.1:8787\"\n").unwrap();
        fs::write(&missing, "listen_addr = \"127.0.0.1:10080\"\n").unwrap();

        assert_eq!(
            proxy_web_url_from_config(&configured).unwrap(),
            "http://127.0.0.1:8787"
        );
        assert!(proxy_web_url_from_config(&missing).is_err());
    }

    #[test]
    fn bundled_config_selector_separates_debug_and_release_defaults() {
        assert_eq!(
            bundled_agent_config_resource(true),
            "config/local/agent.toml"
        );
        assert_eq!(
            bundled_agent_config_resource(false),
            "config/remote/agent.toml"
        );
    }

    #[test]
    fn release_bundled_config_keeps_tun_off_with_proxy_dns_ready() {
        let summary = summarize_config(include_str!("../../../config/remote/agent.toml")).unwrap();

        assert!(!summary.tun_enabled);
        assert!(summary.tun_proxy_dns);
    }
}
