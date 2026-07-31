use super::*;

pub fn load_config_from_path(path: &Path) -> Result<LoadedAgentConfig, String> {
    let config_path = make_absolute_path(path);
    let raw = fs::read_to_string(&config_path).map_err(|err| format!("读取配置失败：{err}"))?;
    loaded_config_from_raw(config_path, raw)
}

pub fn proxy_registry_url_from_config(path: &Path) -> Result<String, String> {
    let config_path = make_absolute_path(path);
    let raw = fs::read_to_string(&config_path)
        .map_err(|_| "无法读取 Agent 认证服务配置，请联系管理员".to_string())?;
    proxy_registry_url_from_raw(&raw)
}

pub(crate) fn proxy_registry_url_from_raw(raw: &str) -> Result<String, String> {
    let config =
        toml::from_str::<Value>(raw).map_err(|_| "Agent 配置格式无效，请联系管理员".to_string())?;
    str_at(&config, &["proxy_registry_url"])
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

pub fn loaded_config_from_raw(
    config_path: PathBuf,
    raw: String,
) -> Result<LoadedAgentConfig, String> {
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

pub fn write_config_file(path: &Path, raw: &str) -> Result<(), String> {
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

pub fn apply_managed_credentials_to_config(
    path: &Path,
    username: &str,
    private_key_path: &Path,
) -> Result<LoadedAgentConfig, String> {
    let config_path = make_absolute_path(path);
    let loaded = load_config_from_path(&config_path)?;
    let proxy_registry_url = proxy_registry_url_from_raw(&loaded.raw)?;
    let raw =
        enforce_managed_identity(&loaded.raw, username, private_key_path, &proxy_registry_url)?;
    write_config_file(&config_path, &raw)?;
    load_config_from_path(&config_path)
}

pub fn clear_managed_credentials_from_config(path: &Path) -> Result<(), String> {
    let config_path = make_absolute_path(path);
    let loaded = load_config_from_path(&config_path)?;
    let mut document = loaded
        .raw
        .parse::<DocumentMut>()
        .map_err(|err| format!("配置 TOML 解析失败：{err}"))?;
    document.remove("username");
    document.remove("private_key_path");
    let raw = document.to_string();
    summarize_config(&raw)?;
    write_config_file(&config_path, &raw)?;
    Ok(())
}

pub fn enforce_managed_identity(
    raw: &str,
    username: &str,
    private_key_path: &Path,
    proxy_registry_url: &str,
) -> Result<String, String> {
    let mut document = raw
        .parse::<DocumentMut>()
        .map_err(|err| format!("配置 TOML 解析失败：{err}"))?;
    document["username"] = value(username);
    document["private_key_path"] = value(private_key_path.to_string_lossy().as_ref());
    document["proxy_registry_url"] = value(proxy_registry_url);
    let managed_raw = document.to_string();
    summarize_config(&managed_raw)?;
    Ok(managed_raw)
}

pub fn redact_managed_identity(mut loaded: LoadedAgentConfig) -> Result<LoadedAgentConfig, String> {
    let mut document = loaded
        .raw
        .parse::<DocumentMut>()
        .map_err(|err| format!("配置 TOML 解析失败：{err}"))?;
    document.remove("username");
    document.remove("private_key_path");
    document.remove("proxy_registry_url");
    loaded.raw = document.to_string();
    loaded.summary.username.clear();
    loaded.summary.private_key_path.clear();
    Ok(loaded)
}

pub fn toggle_tun_enabled_in_config(path: Option<&Path>) -> Result<LoadedAgentConfig, String> {
    let config_path = resolve_config_path(path)?;
    let loaded = load_config_from_path(&config_path)?;
    write_tun_enabled_to_config(&config_path, &loaded.raw, !loaded.summary.tun_enabled)
}

pub(crate) fn resolve_config_path(path: Option<&Path>) -> Result<PathBuf, String> {
    match path {
        Some(path) => Ok(make_absolute_path(path)),
        None => locate_config_path()
            .ok_or_else(|| "找不到 Agent 配置文件。请确认 agent.toml 存在。".to_string()),
    }
}

pub(crate) fn write_tun_enabled_to_config(
    config_path: &Path,
    raw: &str,
    enabled: bool,
) -> Result<LoadedAgentConfig, String> {
    let raw = upsert_toml_bool(raw, "tun", "enabled", enabled);
    write_config_file(config_path, &raw)?;
    load_config_from_path(config_path)
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

    let bundled_files = std::iter::once((
        BUNDLED_AGENT_CONFIG_RESOURCE_PATH,
        BUNDLED_AGENT_CONFIG_PATH,
    ))
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

pub(crate) fn remove_legacy_bundled_demo_keys(app_data_dir: &Path, logs: &UiLogBuffer) {
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
