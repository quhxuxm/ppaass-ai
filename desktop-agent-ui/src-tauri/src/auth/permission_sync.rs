use super::*;

#[derive(Deserialize)]
struct AgentPermissionSyncResponse {
    account: AuthenticationAccount,
    profile: Option<AgentDeviceProfile>,
    key_state: String,
    agent_access_token: String,
    agent_access_token_expires_at: i64,
    refresh_after_seconds: u64,
}

pub struct AgentPermissionSnapshot {
    pub role: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub permissions: Option<Vec<String>>,
    pub proxy_addresses: Vec<String>,
    pub profile_enabled: Option<bool>,
    pub key_version: Option<i64>,
    pub expires_at: Option<i64>,
    pub account_status: AgentAuthAccountStatus,
    pub token: AgentAccessToken,
}

#[derive(Debug)]
pub struct AgentPermissionSyncFailure {
    pub message: String,
    pub credentials_invalid: bool,
    pub proxy_address_not_assigned: bool,
}

pub async fn fetch_agent_permission_snapshot(
    proxy_registry_url: &str,
    access_token: &str,
    expected_username: &str,
) -> Result<AgentPermissionSnapshot, AgentPermissionSyncFailure> {
    let base_url =
        normalize_proxy_registry_url(proxy_registry_url).map_err(|_| transient_config_error())?;
    let client = build_proxy_registry_client().map_err(transient_error)?;
    let response = client
        .get(endpoint(&base_url, "api/v1/agent/me").map_err(transient_error)?)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|error| transient_error(map_request_error(error)))?;
    if response.status() == StatusCode::UNAUTHORIZED {
        return Err(AgentPermissionSyncFailure {
            message: "权限同步凭据失效，请重新登录以恢复同步".to_string(),
            credentials_invalid: true,
            proxy_address_not_assigned: false,
        });
    }
    if !response.status().is_success() {
        let status = response.status();
        let proxy_address_not_assigned = if status == StatusCode::CONFLICT {
            read_bounded_response(response, MAX_NORMAL_RESPONSE_BYTES)
                .await
                .ok()
                .and_then(|(_, bytes)| serde_json::from_slice::<ErrorEnvelope>(&bytes).ok())
                .is_some_and(|envelope| envelope.error.code == "proxy_address_not_assigned")
        } else {
            false
        };
        return Err(AgentPermissionSyncFailure {
            message: if proxy_address_not_assigned {
                "管理员未分配 Proxy 地址".to_string()
            } else {
                format!(
                    "权限同步暂时失败（HTTP {}），将保留上次已验证权限",
                    status.as_u16()
                )
            },
            credentials_invalid: false,
            proxy_address_not_assigned,
        });
    }
    let response =
        decode_json_response::<AgentPermissionSyncResponse>(response, MAX_NORMAL_RESPONSE_BYTES)
            .await
            .map_err(transient_error)?;
    validate_permission_sync_response(response, expected_username).map_err(|message| {
        if message == "管理员未分配 Proxy 地址" {
            AgentPermissionSyncFailure {
                message,
                credentials_invalid: false,
                proxy_address_not_assigned: true,
            }
        } else {
            transient_error(message)
        }
    })
}

fn validate_permission_sync_response(
    response: AgentPermissionSyncResponse,
    expected_username: &str,
) -> Result<AgentPermissionSnapshot, String> {
    if !matches!(response.account.role.as_str(), "user" | "admin") {
        return Err("权限同步返回了未知账号角色".to_string());
    }
    if let Some(linked_username) = response.account.linked_username.as_deref() {
        if linked_username != expected_username {
            return Err("权限同步返回了其他账号的数据".to_string());
        }
    }
    let profile = response.profile;
    if let Some(profile) = profile.as_ref() {
        if profile.username != expected_username {
            return Err("权限同步返回了其他 Proxy 用户的数据".to_string());
        }
        validate_permissions(&profile.permissions)?;
        let proxy_addresses = profile.proxy_addresses.as_deref().unwrap_or_default();
        if validate_managed_proxy_addresses(proxy_addresses, false).is_err() {
            return Err("管理员未分配 Proxy 地址".to_string());
        }
    } else if response.key_state == "active" {
        return Err("权限同步缺少 active 用户配置".to_string());
    }
    let account_status = if response.account.status != "active"
        || response.key_state == "disabled"
        || profile.as_ref().is_some_and(|profile| !profile.enabled)
    {
        AgentAuthAccountStatus::Disabled
    } else if matches!(response.key_state.as_str(), "missing" | "expired") {
        AgentAuthAccountStatus::Expired
    } else if response.key_state == "active" {
        AgentAuthAccountStatus::Active
    } else {
        return Err("权限同步返回了未知密钥状态".to_string());
    };
    let token = validated_agent_access_token(
        response.agent_access_token,
        response.agent_access_token_expires_at,
        response.refresh_after_seconds,
    )?;
    Ok(AgentPermissionSnapshot {
        role: response.account.role,
        display_name: validated_display_name(response.account.display_name)?,
        avatar_url: validated_avatar_url(response.account.avatar_url)?,
        permissions: profile.as_ref().map(|profile| profile.permissions.clone()),
        proxy_addresses: profile
            .as_ref()
            .and_then(|profile| profile.proxy_addresses.clone())
            .unwrap_or_default(),
        profile_enabled: profile.as_ref().map(|profile| profile.enabled),
        key_version: profile.as_ref().map(|profile| profile.key_version),
        expires_at: profile.as_ref().and_then(|profile| profile.expires_at),
        account_status,
        token,
    })
}

pub fn apply_permission_snapshot(
    current: &AgentAuthAccount,
    snapshot: &AgentPermissionSnapshot,
) -> (AgentAuthAccount, AgentAuthAccountStatus, Option<String>) {
    let mut account = current.clone();
    account.role.clone_from(&snapshot.role);
    account.display_name.clone_from(&snapshot.display_name);
    account.avatar_url.clone_from(&snapshot.avatar_url);
    account.permissions = snapshot.permissions.clone().unwrap_or_default();
    if snapshot.profile_enabled == Some(false) {
        return (account, AgentAuthAccountStatus::Disabled, None);
    }
    let mut status = snapshot.account_status;
    let warning = match snapshot.key_version {
        Some(version) if version != current.key_version => {
            status = AgentAuthAccountStatus::Expired;
            Some("Proxy Registry 密钥版本已变化，请重新登录以应用最新密钥".to_string())
        }
        Some(_) => {
            account.expires_at = snapshot.expires_at;
            None
        }
        None => None,
    };
    (account, status, warning)
}

fn validate_permissions(permissions: &[String]) -> Result<(), String> {
    if permissions.len() > 128 {
        return Err("权限同步返回的权限数量过多".to_string());
    }
    if permissions.iter().any(|permission| {
        permission.is_empty()
            || permission.len() > 128
            || !permission
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    }) {
        return Err("权限同步返回了无效权限码".to_string());
    }
    Ok(())
}

fn transient_config_error() -> AgentPermissionSyncFailure {
    transient_error("Agent 权限同步服务配置无效".to_string())
}

fn transient_error(message: String) -> AgentPermissionSyncFailure {
    AgentPermissionSyncFailure {
        message,
        credentials_invalid: false,
        proxy_address_not_assigned: false,
    }
}
