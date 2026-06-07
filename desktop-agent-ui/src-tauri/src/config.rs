use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tauri::path::BaseDirectory;
use tauri::Manager;
use toml::Value;

use crate::logging::UiLogBuffer;
use crate::models::{AgentConfigSummary, LoadedAgentConfig};

const BUNDLED_AGENT_FILES: &[(&str, &str)] = &[
    ("config/local/agent.toml", "agent.toml"),
    ("config/local/agent.toml", "config/local/agent.toml"),
    ("keys/user1.pem", "keys/user1.pem"),
    ("keys/user2.pem", "keys/user2.pem"),
    ("wintun.dll", "wintun.dll"),
];

static DEPLOYED_AGENT_DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

pub(crate) fn load_config_from_path(path: &Path) -> Result<LoadedAgentConfig, String> {
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

pub(crate) fn write_config_file(path: &Path, raw: &str) -> Result<(), String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|err| format!("创建配置目录失败：{err}"))?;
    }
    clear_readonly_file_attribute(path)
        .map_err(|err| format!("准备写入配置失败：{}：{err}", path.display()))?;
    let mut file =
        fs::File::create(path).map_err(|err| format!("保存配置失败：{}：{err}", path.display()))?;
    file.write_all(raw.as_bytes())
        .map_err(|err| format!("写入配置失败：{err}"))?;
    file.sync_all()
        .map_err(|err| format!("同步配置到磁盘失败：{err}"))?;
    Ok(())
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

    Ok(())
}

pub(crate) fn summarize_config(raw: &str) -> Result<AgentConfigSummary, String> {
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

#[cfg(target_os = "macos")]
pub(crate) fn deployed_agent_data_file(file_name: &str) -> Option<PathBuf> {
    DEPLOYED_AGENT_DATA_DIR.get().map(|dir| dir.join(file_name))
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
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions)
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
    use super::write_config_file;
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
}
