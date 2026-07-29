use super::super::*;

pub(crate) fn default_web_permissions() -> Vec<String> {
    with_required_web_permissions(Vec::new())
}

pub(crate) fn without_deprecated_agent_permissions(mut permissions: Vec<String>) -> Vec<String> {
    permissions.retain(|permission| permission != DEPRECATED_AGENT_CONFIG_VIEW_PERMISSION);
    permissions
}

pub(crate) fn with_required_web_permissions(permissions: Vec<String>) -> Vec<String> {
    let mut permissions = without_deprecated_agent_permissions(permissions);
    permissions.extend(REQUIRED_WEB_USER_PERMISSIONS.map(str::to_string));
    permissions.sort_unstable();
    permissions.dedup();
    permissions
}

pub(crate) fn new_account_id() -> String {
    format!("acc_{}", random_token(24))
}

pub(crate) fn new_key_request_id() -> String {
    format!("keyreq_{}", random_token(24))
}

pub(crate) fn normalize_agent_platform(value: &str) -> Result<String, ApiError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "android" => Ok("android".to_string()),
        "windows" => Ok("windows".to_string()),
        _ => Err(ApiError::bad_request(
            "platform 目前只支持 android 或 windows",
        )),
    }
}

pub(crate) fn generate_agent_user_code() -> String {
    let mut entropy = [0_u8; AGENT_USER_CODE_CHARACTERS];
    rand::rng().fill(&mut entropy);
    let canonical = entropy
        .iter()
        .map(|byte| AGENT_USER_CODE_ALPHABET[usize::from(*byte) % AGENT_USER_CODE_ALPHABET.len()])
        .map(char::from)
        .collect::<String>();
    format!(
        "{}-{}-{}",
        &canonical[0..4],
        &canonical[4..8],
        &canonical[8..12]
    )
}

pub(crate) fn canonical_agent_user_code(value: &str) -> Result<String, ApiError> {
    let canonical = value
        .bytes()
        .filter(|byte| *byte != b'-' && !byte.is_ascii_whitespace())
        .map(|byte| byte.to_ascii_uppercase())
        .collect::<Vec<_>>();
    if canonical.len() != AGENT_USER_CODE_CHARACTERS
        || !canonical
            .iter()
            .all(|byte| AGENT_USER_CODE_ALPHABET.contains(byte))
    {
        return Err(ApiError::bad_request("设备授权短码格式无效"));
    }
    String::from_utf8(canonical).map_err(|_| ApiError::bad_request("设备授权短码格式无效"))
}

pub(crate) fn agent_device_code_hash(value: &str) -> Result<String, ApiError> {
    if value.len() != 43
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ApiError::bad_request("device_code 格式无效"));
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApiError::bad_request("device_code 格式无效"))?;
    if decoded.len() != AGENT_DEVICE_CODE_BYTES
        || base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&decoded) != value
    {
        return Err(ApiError::bad_request("device_code 格式无效"));
    }
    Ok(hash_agent_code(
        AGENT_DEVICE_CODE_HASH_DOMAIN,
        value.as_bytes(),
    ))
}

pub(crate) fn agent_user_code_hash(value: &str) -> Result<String, ApiError> {
    let canonical = canonical_agent_user_code(value)?;
    Ok(hash_agent_code(
        AGENT_USER_CODE_HASH_DOMAIN,
        canonical.as_bytes(),
    ))
}

pub(crate) fn hash_agent_code(domain: &[u8], value: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(value);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.finalize())
}

pub(crate) fn require_active_agent_account(account: &WebAccount) -> Result<(), ApiError> {
    if account.status != AccountStatus::Active {
        return Err(ApiError::forbidden("账号已停用"));
    }
    Ok(())
}

pub(crate) async fn load_agent_credentials(
    state: &AppState,
    account: &WebAccount,
) -> Result<(UserRecord, PrivateKeyResponse, Vec<String>), ApiError> {
    require_active_agent_account(account)?;
    let managed = state
        .accounts
        .get_managed_user(&account.account_id)
        .await?
        .ok_or_else(|| ApiError::not_found("账号不存在"))?;
    let profile = match key_state(&managed, current_timestamp()) {
        KeyState::Active => managed.profile.clone().ok_or_else(ApiError::internal)?,
        KeyState::Disabled => return Err(ApiError::forbidden("Proxy 用户已停用")),
        KeyState::Missing | KeyState::Expired => {
            return Err(ApiError::conflict(
                "key_request_required",
                "当前没有可用密钥，请先提交密钥申请",
            ));
        }
    };
    let proxy_addresses = assigned_proxy_addresses(&managed, account)?;
    require_profile_permission(&profile, PRIVATE_KEY_READ_PERMISSION)?;
    let private_key = load_private_key(state, profile.clone()).await?;
    if private_key.private_key_pem.len() > MAX_AGENT_PRIVATE_KEY_BYTES {
        warn!(
            username = profile.username,
            bytes = private_key.private_key_pem.len(),
            "拒绝返回异常大小的 Agent 私钥"
        );
        return Err(ApiError::internal());
    }
    Ok((profile, private_key, proxy_addresses))
}

pub(crate) async fn load_agent_credentials_for_claim(
    state: &AppState,
    account: &WebAccount,
) -> Result<(UserRecord, PrivateKeyResponse, Vec<String>), ApiError> {
    let managed = state
        .accounts
        .get_managed_user(&account.account_id)
        .await?
        .ok_or_else(agent_device_authorization_invalidated)?;
    let profile = match key_state(&managed, current_timestamp()) {
        KeyState::Active => managed
            .profile
            .clone()
            .ok_or_else(agent_device_authorization_invalidated)?,
        KeyState::Missing | KeyState::Expired | KeyState::Disabled => {
            return Err(agent_device_authorization_invalidated());
        }
    };
    if require_profile_permission(&profile, PRIVATE_KEY_READ_PERMISSION).is_err() {
        return Err(agent_device_authorization_invalidated());
    }
    let proxy_addresses = assigned_proxy_addresses(&managed, account)?;
    let private_key = load_private_key(state, profile.clone()).await?;
    if private_key.private_key_pem.len() > MAX_AGENT_PRIVATE_KEY_BYTES {
        warn!(
            username = profile.username,
            bytes = private_key.private_key_pem.len(),
            "拒绝返回异常大小的 Agent 私钥"
        );
        return Err(ApiError::internal());
    }
    Ok((profile, private_key, proxy_addresses))
}

pub(crate) fn assigned_proxy_addresses(
    managed: &ManagedUser,
    account: &WebAccount,
) -> Result<Vec<String>, ApiError> {
    let mut addresses = managed
        .assigned_proxy_addresses
        .iter()
        .filter(|address| address.enabled)
        .map(|address| address.address.clone())
        .collect::<Vec<_>>();
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.is_empty() {
        return Err(
            UserRepositoryError::ProxyAddressNotAssigned(account.account_id.clone()).into(),
        );
    }
    Ok(addresses)
}

pub(crate) fn ensure_visible_agent_authorization(
    authorization: &AgentDeviceAuthorization,
    account: &WebAccount,
) -> Result<(), ApiError> {
    if authorization.expires_at <= current_timestamp() {
        return Err(agent_device_expired_error());
    }
    match authorization.status {
        AgentDeviceAuthorizationStatus::Pending => Ok(()),
        AgentDeviceAuthorizationStatus::Authorized | AgentDeviceAuthorizationStatus::Denied
            if authorization.authorized_account_id.as_deref()
                == Some(account.account_id.as_str()) =>
        {
            Ok(())
        }
        AgentDeviceAuthorizationStatus::Authorized
        | AgentDeviceAuthorizationStatus::Denied
        | AgentDeviceAuthorizationStatus::Consumed => Err(ApiError::conflict(
            "device_authorization_finalized",
            "该设备授权码已经被处理",
        )),
    }
}

pub(crate) fn agent_device_expired_error() -> ApiError {
    ApiError::device_authorization_error(
        StatusCode::BAD_REQUEST,
        "expired_token",
        "设备授权码已过期，请在 Agent 中重新开始登录",
        None,
    )
}

pub(crate) fn agent_device_authorization_invalidated() -> ApiError {
    ApiError::device_authorization_error(
        StatusCode::FORBIDDEN,
        "authorization_invalidated",
        "账号状态已变化，请在 Agent 中重新开始登录",
        None,
    )
}
