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

pub(crate) struct AgentPermissionSnapshot {
    pub(crate) role: String,
    pub(crate) permissions: Option<Vec<String>>,
    pub(crate) profile_enabled: Option<bool>,
    pub(crate) key_version: Option<i64>,
    pub(crate) expires_at: Option<i64>,
    pub(crate) account_status: AgentAuthAccountStatus,
    pub(crate) token: AgentAccessToken,
}

#[derive(Debug)]
pub(crate) struct AgentPermissionSyncFailure {
    pub(crate) message: String,
    pub(crate) credentials_invalid: bool,
}

pub(crate) async fn fetch_agent_permission_snapshot(
    proxy_web_url: &str,
    access_token: &str,
    expected_username: &str,
) -> Result<AgentPermissionSnapshot, AgentPermissionSyncFailure> {
    let base_url = normalize_proxy_web_url(proxy_web_url).map_err(|_| transient_config_error())?;
    let client = build_proxy_web_client().map_err(transient_error)?;
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
        });
    }
    if !response.status().is_success() {
        return Err(AgentPermissionSyncFailure {
            message: format!(
                "权限同步暂时失败（HTTP {}），将保留上次已验证权限",
                response.status().as_u16()
            ),
            credentials_invalid: false,
        });
    }
    let response =
        decode_json_response::<AgentPermissionSyncResponse>(response, MAX_NORMAL_RESPONSE_BYTES)
            .await
            .map_err(transient_error)?;
    validate_permission_sync_response(response, expected_username).map_err(transient_error)
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
        permissions: profile.as_ref().map(|profile| profile.permissions.clone()),
        profile_enabled: profile.as_ref().map(|profile| profile.enabled),
        key_version: profile.as_ref().map(|profile| profile.key_version),
        expires_at: profile.as_ref().and_then(|profile| profile.expires_at),
        account_status,
        token,
    })
}

pub(crate) fn apply_permission_snapshot(
    current: &AgentAuthAccount,
    snapshot: &AgentPermissionSnapshot,
) -> (AgentAuthAccount, AgentAuthAccountStatus, Option<String>) {
    let mut account = current.clone();
    account.role.clone_from(&snapshot.role);
    account.permissions = snapshot.permissions.clone().unwrap_or_default();
    if snapshot.profile_enabled == Some(false) {
        return (account, AgentAuthAccountStatus::Disabled, None);
    }
    let mut status = snapshot.account_status;
    let warning = match snapshot.key_version {
        Some(version) if version != current.key_version => {
            status = AgentAuthAccountStatus::Expired;
            Some("Proxy Web 密钥版本已变化，请重新登录以应用最新密钥".to_string())
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(role: &str) -> AgentAuthAccount {
        AgentAuthAccount {
            username: "alice".to_string(),
            role: role.to_string(),
            permissions: vec!["old.permission".to_string()],
            key_version: 7,
            expires_at: Some(4_000_000_000),
        }
    }

    #[test]
    fn snapshot_updates_permissions_without_changing_current_key_material_version() {
        let snapshot = AgentPermissionSnapshot {
            role: "user".to_string(),
            permissions: Some(vec!["agent.packet_capture".to_string()]),
            profile_enabled: Some(true),
            key_version: Some(7),
            expires_at: Some(4_100_000_000),
            account_status: AgentAuthAccountStatus::Active,
            token: validated_agent_access_token("A".repeat(43), 4_000_000_000, 10).unwrap(),
        };
        let (updated, status, warning) = apply_permission_snapshot(&account("user"), &snapshot);
        assert_eq!(updated.permissions, ["agent.packet_capture"]);
        assert_eq!(updated.expires_at, Some(4_100_000_000));
        assert_eq!(status, AgentAuthAccountStatus::Active);
        assert!(warning.is_none());
        assert_eq!(snapshot.token.refresh_after_seconds, 60);
    }

    #[test]
    fn changed_key_version_preserves_local_version_and_marks_account_expired() {
        let snapshot = AgentPermissionSnapshot {
            role: "admin".to_string(),
            permissions: Some(Vec::new()),
            profile_enabled: Some(true),
            key_version: Some(8),
            expires_at: None,
            account_status: AgentAuthAccountStatus::Active,
            token: validated_agent_access_token("B".repeat(43), 4_000_000_000, 300).unwrap(),
        };
        let (updated, status, warning) = apply_permission_snapshot(&account("user"), &snapshot);
        assert_eq!(updated.role, "admin");
        assert_eq!(updated.key_version, 7);
        assert_eq!(status, AgentAuthAccountStatus::Expired);
        assert!(warning.unwrap().contains("重新登录"));
    }

    #[test]
    fn missing_profile_clears_stale_user_permissions() {
        let snapshot = AgentPermissionSnapshot {
            role: "user".to_string(),
            permissions: None,
            profile_enabled: None,
            key_version: None,
            expires_at: None,
            account_status: AgentAuthAccountStatus::Expired,
            token: validated_agent_access_token("C".repeat(43), 4_000_000_000, 300).unwrap(),
        };
        let (updated, status, warning) = apply_permission_snapshot(&account("user"), &snapshot);
        assert!(updated.permissions.is_empty());
        assert_eq!(status, AgentAuthAccountStatus::Expired);
        assert!(warning.is_none());
    }
}
