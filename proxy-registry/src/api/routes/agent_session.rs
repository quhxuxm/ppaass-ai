use super::super::*;
use crate::agent_tokens::AGENT_PROFILE_REFRESH_SECONDS;

#[instrument(skip(state, headers, payload))]
pub(crate) async fn agent_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<PasswordLoginRequest>, JsonRejection>,
) -> Result<Json<AgentCredentialResponse>, ApiError> {
    validate_native_agent_request(&headers)?;
    let request = payload.map_err(ApiError::from_json_rejection)?.0;
    let account = authenticate_password_account(&state, request).await?;
    let (profile, private_key, proxy_addresses) = load_agent_credentials(&state, &account).await?;
    state
        .accounts
        .update_last_login(&account.account_id, current_timestamp())
        .await?;
    let issued = state
        .agent_tokens
        .issue(&account.account_id)
        .map_err(|error| {
            warn!(account_id = account.account_id, %error, "签发 Agent access token 失败");
            ApiError::internal()
        })?;
    info!(
        account_id = account.account_id,
        username = profile.username,
        "Agent 密码认证成功并签发持续权限同步凭据"
    );
    Ok(Json(
        agent_credential_response(
            &state,
            account,
            profile,
            proxy_addresses,
            private_key,
            issued,
        )
        .await?,
    ))
}

#[instrument(skip(state, headers))]
pub(crate) async fn get_agent_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AgentProfileSyncResponse>, ApiError> {
    validate_native_agent_request(&headers)?;
    let account = authenticate_agent_token(&state, &headers).await?;
    let managed = state
        .accounts
        .get_managed_user(&account.account_id)
        .await?
        .ok_or_else(ApiError::unauthorized)?;
    let key_state = key_state(&managed, current_timestamp());
    let profile = if let Some(profile) = managed.profile.clone() {
        let addresses = assigned_proxy_addresses(&managed, &account)?;
        Some(
            agent_profile_response_for_account(&state, &account, &managed, profile, addresses)
                .await?,
        )
    } else {
        None
    };
    let issued = state
        .agent_tokens
        .issue(&account.account_id)
        .map_err(|error| {
            warn!(account_id = account.account_id, %error, "刷新 Agent access token 失败");
            ApiError::internal()
        })?;
    Ok(Json(AgentProfileSyncResponse {
        account,
        profile,
        key_state,
        agent_access_token: issued.token,
        agent_access_token_expires_at: issued.expires_at,
        refresh_after_seconds: AGENT_PROFILE_REFRESH_SECONDS,
    }))
}

pub(crate) async fn authenticate_agent_token(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<WebAccount, ApiError> {
    let token = bearer_token(headers)?;
    let claims = state
        .agent_tokens
        .verify(token)
        .map_err(|_| ApiError::unauthorized())?;
    let account = state
        .accounts
        .get_account_by_id(&claims.account_id)
        .await?
        .ok_or_else(ApiError::unauthorized)?;
    Ok(account)
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, ApiError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(ApiError::unauthorized)?;
    let token = value
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty() && !token.bytes().any(|byte| byte.is_ascii_whitespace()))
        .ok_or_else(ApiError::unauthorized)?;
    Ok(token)
}

async fn agent_credential_response(
    state: &AppState,
    account: WebAccount,
    profile: UserRecord,
    proxy_addresses: Vec<String>,
    private_key: PrivateKeyResponse,
    issued: crate::agent_tokens::IssuedAgentAccessToken,
) -> Result<AgentCredentialResponse, ApiError> {
    let managed = state
        .accounts
        .get_managed_user(&account.account_id)
        .await?
        .ok_or_else(ApiError::unauthorized)?;
    let profile =
        agent_profile_response_for_account(state, &account, &managed, profile, proxy_addresses)
            .await?;
    Ok(AgentCredentialResponse {
        account,
        profile,
        public_key_pem: private_key.public_key_pem,
        private_key_pem: private_key.private_key_pem,
        agent_access_token: issued.token,
        agent_access_token_expires_at: issued.expires_at,
        refresh_after_seconds: AGENT_PROFILE_REFRESH_SECONDS,
    })
}

pub(crate) fn agent_profile_response(
    profile: UserRecord,
    proxy_addresses: Vec<String>,
) -> AgentDeviceProfileResponse {
    AgentDeviceProfileResponse {
        username: profile.username,
        permissions: profile.permissions,
        proxy_addresses,
        proxy_entries: None,
        selected_proxy_entry_id: None,
        enabled: profile.enabled,
        key_version: profile.key_version,
        expires_at: profile.expires_at,
    }
}

pub(crate) async fn agent_profile_response_for_account(
    state: &AppState,
    account: &WebAccount,
    managed: &ManagedUser,
    profile: UserRecord,
    proxy_addresses: Vec<String>,
) -> Result<AgentDeviceProfileResponse, ApiError> {
    let can_select = account.role == AccountRole::Admin
        || profile
            .permissions
            .iter()
            .any(|permission| permission == PROXY_ENTRY_SELECT_PERMISSION);
    let mut response = agent_profile_response(profile, proxy_addresses);
    if !can_select {
        return Ok(response);
    }
    let entries = state
        .proxy_addresses
        .list_proxy_addresses()
        .await?
        .into_iter()
        .filter(|address| address.enabled)
        .map(agent_proxy_entry_response)
        .collect();
    response.proxy_entries = Some(entries);
    response.selected_proxy_entry_id = managed
        .selected_proxy_address
        .as_ref()
        .filter(|address| address.enabled)
        .map(|address| address.proxy_address_id.clone());
    Ok(response)
}

fn agent_proxy_entry_response(address: ProxyAddress) -> AgentProxyEntryResponse {
    let icon_key = address
        .entry_id
        .clone()
        .unwrap_or_else(|| address.proxy_address_id.clone());
    let description = match (&address.entry_id, &address.entry_version) {
        (Some(entry_id), Some(version)) => format!("{entry_id} · v{version}"),
        (Some(entry_id), None) => entry_id.clone(),
        (None, _) => "Registry 管理的 Proxy Entry".to_string(),
    };
    let online = address.entry_last_heartbeat_at.map(|heartbeat| {
        heartbeat >= current_timestamp().saturating_sub(PROXY_ENTRY_ONLINE_WINDOW_SECONDS)
    });
    AgentProxyEntryResponse {
        proxy_entry_id: address.proxy_address_id,
        label: address.label,
        address: address.address,
        description,
        icon_key,
        entry_id: address.entry_id,
        online,
    }
}

#[instrument(skip(state, headers, payload))]
pub(crate) async fn select_agent_proxy_entry(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<SelectAgentProxyEntryRequest>, JsonRejection>,
) -> Result<Json<AgentProfileSyncResponse>, ApiError> {
    validate_native_agent_request(&headers)?;
    let account = authenticate_agent_token(&state, &headers).await?;
    let Json(request) = payload.map_err(ApiError::from_json_rejection)?;
    let managed = state
        .accounts
        .select_proxy_address(
            &account.account_id,
            &request.proxy_entry_id,
            PROXY_ENTRY_SELECT_PERMISSION,
        )
        .await?;
    let profile = managed.profile.clone().ok_or_else(ApiError::unauthorized)?;
    let addresses = assigned_proxy_addresses(&managed, &account)?;
    let profile =
        agent_profile_response_for_account(&state, &account, &managed, profile, addresses).await?;
    let issued = state
        .agent_tokens
        .issue(&account.account_id)
        .map_err(|_| ApiError::internal())?;
    info!(
        account_id = account.account_id,
        proxy_entry_id = request.proxy_entry_id,
        "Agent 已更改自选 Proxy Entry"
    );
    Ok(Json(AgentProfileSyncResponse {
        account,
        profile: Some(profile),
        key_state: key_state(&managed, current_timestamp()),
        agent_access_token: issued.token,
        agent_access_token_expires_at: issued.expires_at,
        refresh_after_seconds: AGENT_PROFILE_REFRESH_SECONDS,
    }))
}
