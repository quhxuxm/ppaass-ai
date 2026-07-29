use super::super::*;
use crate::agent_tokens::AGENT_PROFILE_REFRESH_SECONDS;

#[instrument(skip(state, headers, payload))]
pub(crate) async fn agent_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    OptionalPeerAddress(peer): OptionalPeerAddress,
    payload: Result<Json<PasswordLoginRequest>, JsonRejection>,
) -> Result<Json<AgentCredentialResponse>, ApiError> {
    validate_native_agent_request(&headers)?;
    let request = payload.map_err(ApiError::from_json_rejection)?.0;
    let account = authenticate_password_account(&state, &headers, peer, request).await?;
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
    Ok(Json(agent_credential_response(
        account,
        profile,
        proxy_addresses,
        private_key,
        issued,
    )))
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
    let proxy_addresses = managed
        .profile
        .as_ref()
        .map(|_| assigned_proxy_addresses(&managed, &account))
        .transpose()?;
    let profile = managed
        .profile
        .zip(proxy_addresses)
        .map(|(profile, addresses)| agent_profile_response(profile, addresses));
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

async fn authenticate_agent_token(
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

fn agent_credential_response(
    account: WebAccount,
    profile: UserRecord,
    proxy_addresses: Vec<String>,
    private_key: PrivateKeyResponse,
    issued: crate::agent_tokens::IssuedAgentAccessToken,
) -> AgentCredentialResponse {
    AgentCredentialResponse {
        account,
        profile: agent_profile_response(profile, proxy_addresses),
        public_key_pem: private_key.public_key_pem,
        proxy_identity_public_key_pem: private_key.proxy_identity_public_key_pem,
        private_key_pem: private_key.private_key_pem,
        agent_access_token: issued.token,
        agent_access_token_expires_at: issued.expires_at,
        refresh_after_seconds: AGENT_PROFILE_REFRESH_SECONDS,
    }
}

pub(crate) fn agent_profile_response(
    profile: UserRecord,
    proxy_addresses: Vec<String>,
) -> AgentDeviceProfileResponse {
    AgentDeviceProfileResponse {
        username: profile.username,
        permissions: profile.permissions,
        proxy_addresses,
        enabled: profile.enabled,
        key_version: profile.key_version,
        expires_at: profile.expires_at,
    }
}
