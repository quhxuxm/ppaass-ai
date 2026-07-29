use super::*;

pub(crate) fn is_expected_windows_app_data_dir(path: &Path) -> bool {
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

pub(crate) fn validate_managed_private_key_path(
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

pub(crate) fn validate_managed_proxy_identity_public_key_path(
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

pub(crate) fn windows_credentials_dir_candidates(app_data_dir: &Path) -> Vec<PathBuf> {
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

pub(crate) fn canonical_windows_credentials_dirs(app_data_dir: &Path) -> Vec<PathBuf> {
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

pub(crate) fn lexical_path_for_compare(path: &Path) -> String {
    path.to_string_lossy()
        .replace('/', "\\")
        .trim_start_matches(r"\\?\")
        .to_lowercase()
}

pub(crate) fn validate_service_managed_path(
    app_data_dir: &Path,
    value: &str,
) -> Result<(), String> {
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

pub(crate) fn normalized_path_is_within(path: &Path, root: &Path) -> bool {
    let path = normalized_path_for_compare(path);
    let root = normalized_path_for_compare(root);
    path == root || path.starts_with(&format!("{root}\\"))
}

pub(crate) fn validate_service_relative_path(value: &str) -> Result<(), String> {
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

pub(crate) fn service_config_string<'a>(value: &'a toml::Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str()
}

pub(crate) fn service_packet_capture_result(
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

pub(crate) fn service_state_ok(runtime: &AgentRuntime, state: AgentState) -> ServiceResponse {
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

pub(crate) fn service_error(error: String) -> ServiceResponse {
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
