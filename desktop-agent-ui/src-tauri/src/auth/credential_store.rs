use super::*;

pub(crate) fn write_managed_private_key(
    app: &tauri::AppHandle,
    username: &str,
    key_version: i64,
    private_key_pem: &str,
) -> Result<PathBuf, String> {
    let credentials_dir = managed_credentials_dir(app)?;
    let file_name = managed_private_key_file_name(username, key_version);
    write_private_key_to_dir(&credentials_dir, &file_name, private_key_pem)
}

pub(crate) fn write_managed_proxy_identity_public_key(
    app: &tauri::AppHandle,
    public_key_pem: &str,
) -> Result<PathBuf, String> {
    validate_proxy_identity_public_key(public_key_pem)?;
    let credentials_dir = managed_credentials_dir(app)?;
    write_private_key_to_dir(
        &credentials_dir,
        PROXY_IDENTITY_PUBLIC_KEY_FILE,
        public_key_pem,
    )
}

pub(crate) fn persist_agent_login(
    app: &tauri::AppHandle,
    account: &AgentAuthAccount,
    account_status: AgentAuthAccountStatus,
    agent_access_token: Option<&AgentAccessToken>,
) -> Result<(), String> {
    persist_agent_login_to_dir(
        &managed_credentials_dir(app)?,
        account,
        account_status,
        agent_access_token,
    )
}

pub(crate) fn load_persisted_agent_login(
    app: &tauri::AppHandle,
) -> Result<Option<PersistedAgentLogin>, String> {
    load_persisted_agent_login_from_dir(&managed_credentials_dir(app)?)
}

pub(crate) fn destroy_persisted_agent_login(app: &tauri::AppHandle) -> Result<(), String> {
    let path = managed_credentials_dir(app)?.join(PERSISTED_AGENT_LOGIN_FILE);
    match fs::remove_file(&path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                if let Ok(directory) = fs::File::open(parent) {
                    let _ = directory.sync_all();
                }
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("删除 Agent 持久登录记录失败：{error}")),
    }
}

pub(crate) fn managed_credentials_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    #[cfg(windows)]
    let app_data_dir = app
        .path()
        .app_local_data_dir()
        .map_err(|error| format!("定位 Agent 本地数据目录失败：{error}"))?;
    #[cfg(not(windows))]
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("定位 Agent 数据目录失败：{error}"))?;
    Ok(app_data_dir.join(CREDENTIALS_DIR))
}

pub(crate) fn persist_agent_login_to_dir(
    credentials_dir: &Path,
    account: &AgentAuthAccount,
    account_status: AgentAuthAccountStatus,
    agent_access_token: Option<&AgentAccessToken>,
) -> Result<(), String> {
    validate_persisted_account(account)?;
    fs::create_dir_all(credentials_dir)
        .map_err(|error| format!("创建 Agent 登录记录目录失败：{error}"))?;
    #[cfg(unix)]
    fs::set_permissions(credentials_dir, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("设置 Agent 登录记录目录权限失败：{error}"))?;
    #[cfg(windows)]
    set_windows_restricted_acl(credentials_dir, true)?;

    let record = PersistedAgentLoginRecord {
        version: PERSISTED_AGENT_LOGIN_VERSION,
        account: account.clone(),
        account_status,
        agent_access_token: agent_access_token.map(|token| token.value.to_string()),
        agent_access_token_expires_at: agent_access_token.map(|token| token.expires_at),
        refresh_after_seconds: agent_access_token.map(|token| token.refresh_after_seconds),
    };
    let serialized =
        serde_json::to_vec(&record).map_err(|error| format!("编码 Agent 登录记录失败：{error}"))?;
    let destination = credentials_dir.join(PERSISTED_AGENT_LOGIN_FILE);
    let mut temporary = Builder::new()
        .prefix(".agent-login-")
        .tempfile_in(credentials_dir)
        .map_err(|error| format!("创建 Agent 登录记录临时文件失败：{error}"))?;
    #[cfg(unix)]
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("设置 Agent 登录记录权限失败：{error}"))?;
    temporary
        .write_all(&serialized)
        .map_err(|error| format!("写入 Agent 登录记录失败：{error}"))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| format!("同步 Agent 登录记录失败：{error}"))?;
    temporary
        .persist(&destination)
        .map_err(|error| format!("保存 Agent 登录记录失败：{}", error.error))?;
    #[cfg(unix)]
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("设置 Agent 登录记录权限失败：{error}"))?;
    #[cfg(windows)]
    set_windows_restricted_acl(&destination, false)?;
    if let Ok(directory) = fs::File::open(credentials_dir) {
        let _ = directory.sync_all();
    }
    Ok(())
}

pub(crate) fn load_persisted_agent_login_from_dir(
    credentials_dir: &Path,
) -> Result<Option<PersistedAgentLogin>, String> {
    let record_path = credentials_dir.join(PERSISTED_AGENT_LOGIN_FILE);
    let metadata = match fs::symlink_metadata(&record_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("读取 Agent 登录记录元数据失败：{error}")),
    };
    if !metadata.file_type().is_file() || metadata.len() > MAX_PERSISTED_AGENT_LOGIN_BYTES {
        return Err("Agent 登录记录文件无效".to_string());
    }
    let record = serde_json::from_slice::<PersistedAgentLoginRecord>(
        &fs::read(&record_path).map_err(|error| format!("读取 Agent 登录记录失败：{error}"))?,
    )
    .map_err(|_| "Agent 登录记录格式无效".to_string())?;
    if record.version != PERSISTED_AGENT_LOGIN_VERSION {
        return Err("Agent 登录记录版本无效".to_string());
    }
    validate_persisted_account(&record.account)?;
    let agent_access_token = match (
        record.agent_access_token,
        record.agent_access_token_expires_at,
        record.refresh_after_seconds,
    ) {
        (Some(value), Some(expires_at), Some(refresh_after_seconds)) => Some(
            validated_agent_access_token(value, expires_at, refresh_after_seconds)
                .map_err(|_| "Agent 权限同步凭据无效，请重新登录".to_string())?,
        ),
        (None, None, None) => None,
        _ => return Err("Agent 权限同步凭据记录不完整，请重新登录".to_string()),
    };

    let private_key_path = credentials_dir.join(managed_private_key_file_name(
        &record.account.username,
        record.account.key_version,
    ));
    let proxy_identity_public_key_path = credentials_dir.join(PROXY_IDENTITY_PUBLIC_KEY_FILE);
    validate_persisted_credential_file(&private_key_path, MAX_PRIVATE_KEY_RESPONSE_BYTES as u64)?;
    validate_persisted_credential_file(
        &proxy_identity_public_key_path,
        MAX_PRIVATE_KEY_RESPONSE_BYTES as u64,
    )?;
    let private_key_pem = fs::read_to_string(&private_key_path)
        .map_err(|error| format!("读取持久登录私钥失败：{error}"))?;
    RsaKeyPair::from_private_key_pem(&private_key_pem)
        .map_err(|_| "持久登录私钥格式无效".to_string())?;
    let proxy_identity_public_key_pem = fs::read_to_string(&proxy_identity_public_key_path)
        .map_err(|error| format!("读取持久登录 Proxy 身份公钥失败：{error}"))?;
    validate_proxy_identity_public_key(&proxy_identity_public_key_pem)?;

    Ok(Some(PersistedAgentLogin {
        account: record.account,
        account_status: record.account_status,
        private_key_path,
        proxy_identity_public_key_path,
        agent_access_token,
    }))
}

pub(crate) fn validate_persisted_account(account: &AgentAuthAccount) -> Result<(), String> {
    if account.username.trim().is_empty() || account.key_version < 1 {
        return Err("Agent 登录记录中的账号信息无效".to_string());
    }
    // `expires_at` is display-only local metadata. It must never be compared
    // with the local clock to revoke a long-running Agent session.
    Ok(())
}

pub(crate) fn validate_persisted_credential_file(
    path: &Path,
    maximum_bytes: u64,
) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "Agent 持久登录凭据缺失，请重新登录".to_string())?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum_bytes {
        return Err("Agent 持久登录凭据文件无效，请重新登录".to_string());
    }
    Ok(())
}

pub(crate) fn destroy_managed_private_key(path: &Path) -> Result<(), String> {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "托管私钥文件名无效".to_string())?;
    if !file_name.starts_with("managed-") || !file_name.ends_with(".pem") {
        return Err("拒绝删除非托管私钥文件".to_string());
    }
    if !path.exists() {
        return Ok(());
    }

    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|error| format!("清空托管私钥失败：{error}"))?;
    file.flush()
        .map_err(|error| format!("清空托管私钥失败：{error}"))?;
    file.sync_all()
        .map_err(|error| format!("同步托管私钥清理失败：{error}"))?;
    drop(file);
    fs::remove_file(path).map_err(|error| format!("删除托管私钥失败：{error}"))
}

pub(crate) fn destroy_managed_proxy_identity_public_key(path: &Path) -> Result<(), String> {
    if path.file_name().and_then(|value| value.to_str()) != Some(PROXY_IDENTITY_PUBLIC_KEY_FILE) {
        return Err("拒绝删除非托管 Proxy 身份公钥文件".to_string());
    }
    if path.exists() {
        fs::remove_file(path).map_err(|error| format!("删除 Proxy 身份公钥失败：{error}"))?;
    }
    Ok(())
}

pub(crate) fn require_active_profile(me: &MeResponse) -> Result<&MeProfile, String> {
    if me.key_state == "active" {
        return me
            .profile
            .as_ref()
            .ok_or_else(|| "当前账号没有可用的 Proxy 用户配置".to_string());
    }
    match me.key_state.as_str() {
        "missing" | "expired" => {
            if me
                .pending_request
                .as_ref()
                .is_some_and(|request| request.status == "pending")
            {
                Err("密钥申请正在等待管理员审批".to_string())
            } else {
                Err("当前没有可用密钥，请先在用户中心提交申请并等待管理员批准".to_string())
            }
        }
        "disabled" => Err("Proxy 用户已停用".to_string()),
        _ => Err("Proxy Web 返回了未知的密钥状态".to_string()),
    }
}
