use super::*;

pub(crate) fn authorize_service_request(auth_token: &str) -> Result<(), String> {
    validate_service_token_format(auth_token)?;
    let authorization = service_session_authorization()?;
    if constant_time_token_eq(auth_token.as_bytes(), authorization.token.as_bytes()) {
        Ok(())
    } else {
        Err("Windows Service 会话令牌不匹配".to_string())
    }
}

pub(crate) fn service_session_authorization() -> Result<ServiceSessionAuthorization, String> {
    let config_root = SERVICE_CONFIG_ROOT
        .get()
        .ok_or_else(|| "Windows Service 未配置受管 Agent 数据目录".to_string())?;
    read_service_session_authorization(&service_session_file_path_for_root(config_root)?)
}

pub fn read_service_session_authorization(
    path: &Path,
) -> Result<ServiceSessionAuthorization, String> {
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

pub fn service_session_file_path_for_root(config_root: &Path) -> Result<PathBuf, String> {
    Ok(service_credentials_dir_for_root(config_root)?.join(SERVICE_SESSION_FILE_NAME))
}

pub(crate) fn service_desired_state_file_path_for_root(
    config_root: &Path,
) -> Result<PathBuf, String> {
    Ok(service_credentials_dir_for_root(config_root)?.join(SERVICE_DESIRED_STATE_FILE_NAME))
}

pub(crate) fn service_credentials_dir_for_root(config_root: &Path) -> Result<PathBuf, String> {
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

pub(crate) fn service_desired_running() -> Result<Option<ServiceLoginBinding>, String> {
    let config_root = SERVICE_CONFIG_ROOT
        .get()
        .ok_or_else(|| "Windows Service 未配置受管 Agent 数据目录".to_string())?;
    read_service_desired_state(&service_desired_state_file_path_for_root(config_root)?)
}

pub fn read_service_desired_state(path: &Path) -> Result<Option<ServiceLoginBinding>, String> {
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

pub(crate) fn persist_service_desired_running(
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

pub fn persist_service_desired_state(
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

pub(crate) fn validate_service_token_format(token: &str) -> Result<(), String> {
    if token.len() == SERVICE_SESSION_TOKEN_HEX_LEN
        && token.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        Ok(())
    } else {
        Err("Windows Service 会话令牌格式无效".to_string())
    }
}

pub fn constant_time_token_eq(left: &[u8], right: &[u8]) -> bool {
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
