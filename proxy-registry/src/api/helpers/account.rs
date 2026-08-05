use super::super::*;

pub(crate) fn initial_user_origin(managed: &ManagedUser) -> UserOrigin {
    if managed
        .providers
        .iter()
        .any(|identity| identity.provider == "wechat")
    {
        UserOrigin::Wechat
    } else {
        UserOrigin::Local
    }
}

pub(crate) async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedSession, ApiError> {
    state
        .sessions
        .authenticate(state.accounts.as_ref(), headers)
        .await
}

pub(crate) async fn require_admin(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedSession, ApiError> {
    let session = authenticate(state, headers).await?;
    if session.account.role != AccountRole::Admin {
        return Err(ApiError::forbidden("需要管理员权限"));
    }
    Ok(session)
}

pub(crate) async fn require_admin_actor(
    state: &AppState,
    headers: &HeaderMap,
    mutation: bool,
) -> Result<WebAccount, ApiError> {
    if headers.contains_key(header::AUTHORIZATION) {
        validate_native_agent_request(headers)?;
        if headers.contains_key(header::COOKIE) {
            return Err(ApiError::forbidden(
                "管理员 Agent 请求不能同时携带浏览器会话",
            ));
        }
        let account = authenticate_agent_token(state, headers).await?;
        require_active_agent_account(&account)?;
        if account.role != AccountRole::Admin {
            return Err(ApiError::forbidden("需要管理员权限"));
        }
        return Ok(account);
    }

    if mutation {
        validate_browser_mutation(headers)?;
    }
    let session = require_admin(state, headers).await?;
    if mutation {
        state.sessions.require_csrf(&session, headers)?;
    }
    Ok(session.account)
}

pub(crate) async fn require_active_key_profile(
    state: &AppState,
    account: &WebAccount,
) -> Result<UserRecord, ApiError> {
    let managed = state
        .accounts
        .get_managed_user(&account.account_id)
        .await?
        .ok_or_else(|| ApiError::not_found("账号不存在"))?;
    match key_state(&managed, current_timestamp()) {
        KeyState::Active => managed.profile.ok_or_else(ApiError::internal),
        KeyState::Disabled => Err(ApiError::forbidden("Proxy 用户已停用")),
        KeyState::Missing | KeyState::Expired => Err(ApiError::conflict(
            "key_request_required",
            "当前没有可用密钥，请先提交密钥申请",
        )),
    }
}

pub(crate) fn key_state(managed: &ManagedUser, timestamp: i64) -> KeyState {
    let Some(profile) = managed.profile.as_ref() else {
        return KeyState::Missing;
    };
    if !profile.enabled {
        return KeyState::Disabled;
    }
    if profile
        .expires_at
        .is_some_and(|expires_at| expires_at <= timestamp)
    {
        return KeyState::Expired;
    }
    if !managed.has_private_key {
        return KeyState::Missing;
    }
    KeyState::Active
}

pub(crate) fn me_profile_response(
    profile: UserRecord,
    expose_public_key: bool,
    proxy_addresses: Vec<String>,
) -> MeProfileResponse {
    let UserRecord {
        username,
        public_key_pem,
        permissions,
        enabled,
        origin,
        key_version,
        expires_at,
        created_at,
        updated_at,
    } = profile;
    MeProfileResponse {
        username,
        public_key_pem: expose_public_key.then_some(public_key_pem),
        permissions,
        proxy_addresses,
        enabled,
        origin,
        key_version,
        expires_at,
        created_at,
        updated_at,
    }
}

pub(crate) async fn resolve_managed_user(
    state: &AppState,
    identifier: &str,
) -> Result<ManagedUser, ApiError> {
    if let Some(user) = state
        .accounts
        .get_managed_user_by_username(identifier)
        .await?
    {
        return Ok(user);
    }
    if let Some(account) = state.accounts.get_account_by_login(identifier).await? {
        return state
            .accounts
            .get_managed_user(&account.account_id)
            .await?
            .ok_or_else(|| ApiError::not_found("用户不存在"));
    }
    Err(ApiError::not_found("用户不存在"))
}

pub(crate) fn require_profile_permission(
    profile: &UserRecord,
    permission: &str,
) -> Result<(), ApiError> {
    if profile
        .permissions
        .iter()
        .any(|candidate| candidate == permission)
    {
        Ok(())
    } else {
        Err(ApiError::forbidden(format!("缺少权限：{permission}")))
    }
}

pub(crate) async fn load_private_key(
    state: &AppState,
    profile: UserRecord,
) -> Result<PrivateKeyResponse, ApiError> {
    let encrypted = state
        .accounts
        .load_encrypted_private_key(&profile.username)
        .await?
        .ok_or_else(|| ApiError::not_found("该用户没有可恢复的托管私钥，请先重生成密钥"))?;
    if encrypted.key_version != profile.key_version {
        warn!(
            username = profile.username,
            profile_version = profile.key_version,
            private_version = encrypted.key_version,
            "公钥与托管私钥版本不一致"
        );
        return Err(ApiError::internal());
    }
    let private_key_pem = state
        .private_keys
        .decrypt(
            &encrypted.username,
            encrypted.key_version,
            &encrypted.encrypted_private_key,
        )
        .map_err(|error| {
            warn!(username = profile.username, %error, "托管私钥解密失败");
            ApiError::internal()
        })?;
    Ok(PrivateKeyResponse {
        username: profile.username,
        public_key_pem: profile.public_key_pem,
        private_key_pem,
        key_version: profile.key_version,
    })
}

pub(crate) async fn rotate_profile_key(
    state: &AppState,
    profile: UserRecord,
    actor: AccountActor,
    audit_reason: Option<String>,
) -> Result<PrivateKeyResponse, ApiError> {
    let next_version = profile
        .key_version
        .checked_add(1)
        .ok_or_else(ApiError::internal)?;
    let GeneratedKeys {
        public_key_pem,
        private_key_pem,
        encrypted_private_key,
    } = generate_keys(&state.private_keys, &profile.username, next_version).await?;
    let updated = state
        .accounts
        .rotate_keypair(KeyPairRotation {
            username: profile.username,
            expected_key_version: profile.key_version,
            public_key_pem,
            encrypted_private_key,
            actor,
            audit_reason,
        })
        .await?;
    Ok(PrivateKeyResponse {
        username: updated.username,
        public_key_pem: updated.public_key_pem,
        private_key_pem,
        key_version: updated.key_version,
    })
}
