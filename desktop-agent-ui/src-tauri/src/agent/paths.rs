use super::*;

pub fn normalize_agent_config_paths(
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

    config.tun.route_state_file = Some(resolve_agent_state_path(
        base_dir,
        config.tun.route_state_file.as_deref(),
        TUN_HELPER_ROUTE_STATE_FILE_NAME,
    ));
    config.tun.dns_state_file = Some(resolve_agent_state_path(
        base_dir,
        config.tun.dns_state_file.as_deref(),
        TUN_HELPER_DNS_STATE_FILE_NAME,
    ));

    let capture_file = config.tun.packet_capture.file.trim();
    if !capture_file.is_empty() {
        config.tun.packet_capture.file = resolve_agent_path(base_dir, capture_file)
            .to_string_lossy()
            .into();
    }
}

pub fn resolve_agent_state_path(
    base_dir: &Path,
    configured: Option<&str>,
    default_name: &str,
) -> String {
    let configured = configured
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(default_name);
    resolve_agent_path(base_dir, configured)
        .to_string_lossy()
        .into_owned()
}

pub(crate) fn resolve_agent_output_path(config_path: &Path, value: &str) -> PathBuf {
    resolve_agent_path(&agent_base_dir(config_path), value)
}

pub(crate) fn resolve_existing_agent_path(base_dir: &Path, value: &str) -> PathBuf {
    let path = Path::new(value);
    if path.is_absolute() {
        return path.to_path_buf();
    }

    agent_asset_candidates(base_dir, path)
        .into_iter()
        .find(|candidate| candidate.exists())
        .unwrap_or_else(|| base_dir.join(path))
}

pub(crate) fn resolve_agent_path(base_dir: &Path, value: &str) -> PathBuf {
    let path = Path::new(value);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    }
}

pub(crate) fn agent_asset_candidates(base_dir: &Path, path: &Path) -> Vec<PathBuf> {
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

pub(crate) fn push_unique_path(candidates: &mut Vec<PathBuf>, path: PathBuf) {
    if !candidates.iter().any(|candidate| candidate == &path) {
        candidates.push(path);
    }
}

pub(crate) fn agent_base_dir(config_path: &Path) -> PathBuf {
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

pub(crate) fn find_agent_base_dir(config_path: &Path) -> Option<PathBuf> {
    let parent = config_path.parent()?;
    parent
        .ancestors()
        .take(8)
        .find(|ancestor| is_agent_base_dir(ancestor))
        .map(Path::to_path_buf)
}

pub(crate) fn is_agent_base_dir(path: &Path) -> bool {
    path.join("wintun.dll").is_file()
        || path.join("desktop-agent-be").is_dir()
        || (path.join("config/agent.toml").is_file() && path.join("keys").is_dir())
}
