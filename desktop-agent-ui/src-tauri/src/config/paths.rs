use super::*;

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

pub(crate) fn bundled_agent_resource_path(
    app: &tauri::App,
    resource_path: &str,
) -> Result<PathBuf, String> {
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

pub(crate) fn default_agent_config_resource_path(
    app: &tauri::AppHandle,
) -> Result<PathBuf, String> {
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

pub(crate) fn clear_readonly_file_attribute(path: &Path) -> io::Result<()> {
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
pub(crate) fn clear_readonly_permissions(permissions: &mut fs::Permissions) {
    permissions.set_mode(permissions.mode() | 0o200);
}

#[cfg(not(unix))]
pub(crate) fn clear_readonly_permissions(permissions: &mut fs::Permissions) {
    permissions.set_readonly(false);
}

pub(crate) fn default_tun_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "ppaass-tun"
    } else if cfg!(target_os = "macos") {
        "utun8"
    } else {
        "tun0"
    }
}

pub(crate) fn deployed_agent_dirs() -> Vec<PathBuf> {
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

pub(crate) fn ancestor_dirs() -> Vec<PathBuf> {
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

pub(crate) fn push_unique_path(candidates: &mut Vec<PathBuf>, path: PathBuf) {
    if !candidates.iter().any(|candidate| candidate == &path) {
        candidates.push(path);
    }
}
