use super::super::*;

pub(crate) async fn admin_list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ManagedUsersResponse>, ApiError> {
    require_admin(&state, &headers).await?;
    let users = state
        .accounts
        .list_managed_users()
        .await?
        .into_iter()
        .map(AdminManagedUserResponse::from)
        .collect();
    Ok(Json(ManagedUsersResponse { users }))
}

pub(crate) async fn admin_get_user(
    State(state): State<AppState>,
    Path(identifier): Path<String>,
    headers: HeaderMap,
) -> Result<Json<AdminManagedUserResponse>, ApiError> {
    require_admin(&state, &headers).await?;
    Ok(Json(
        resolve_managed_user(&state, &identifier).await?.into(),
    ))
}

#[instrument(skip(state, headers, payload))]
pub(crate) async fn admin_create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<AdminCreateUserRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    validate_browser_mutation(&headers)?;
    let session = require_admin(&state, &headers).await?;
    state.sessions.require_csrf(&session, &headers)?;
    let Json(request) = payload.map_err(ApiError::from_json_rejection)?;
    let username = normalize_username(&request.username)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let expires_at = parse_future_expiration(request.expires_at, &username)?;
    let password_hash = state
        .passwords
        .hash_password(request.password)
        .await
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let generated = generate_initial_stored_keys(&state, &username).await?;
    let permissions = with_required_web_permissions(request.permissions.unwrap_or_default());
    let managed = state
        .accounts
        .create_managed_user(NewManagedUser {
            account_id: new_account_id(),
            login_name: username.clone(),
            password_hash: Some(password_hash),
            role: AccountRole::User,
            status: AccountStatus::Active,
            display_name: normalize_nickname(request.display_name)?,
            email: None,
            avatar_url: None,
            profile: NewUser {
                username: username.clone(),
                public_key_pem: generated.public_key_pem,
                permissions,
                enabled: request.enabled,
                origin: UserOrigin::Admin,
                expires_at: Some(expires_at),
            },
            encrypted_private_key: generated.encrypted_private_key,
            external_identity: None,
            proxy_address_ids: request.proxy_address_ids,
            created_by: Some(AccountActor {
                account_id: session.account.account_id.clone(),
                login_name: session.account.login_name.clone(),
            }),
            audit_reason: Some(request.audit_reason),
        })
        .await?;
    info!(
        admin_account_id = session.account.account_id,
        username, "管理员创建普通用户并生成 RSA 密钥"
    );
    Ok((
        StatusCode::CREATED,
        Json(CreatedManagedUserResponse {
            user: managed.into(),
        }),
    )
        .into_response())
}

#[instrument(skip(state, headers, payload), fields(identifier))]
pub(crate) async fn admin_update_user(
    State(state): State<AppState>,
    Path(identifier): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<AdminUpdateUserRequest>, JsonRejection>,
) -> Result<Json<AdminManagedUserResponse>, ApiError> {
    validate_browser_mutation(&headers)?;
    let session = require_admin(&state, &headers).await?;
    state.sessions.require_csrf(&session, &headers)?;
    let Json(request) = payload.map_err(ApiError::from_json_rejection)?;
    let managed = resolve_managed_user(&state, &identifier).await?;
    let expires_at = match request.expires_at {
        PatchField::Missing => None,
        PatchField::Null => Some(None),
        PatchField::Value(value) => {
            let username = managed
                .profile
                .as_ref()
                .map(|profile| profile.username.as_str())
                .unwrap_or(&identifier);
            Some(Some(value.parse(username)?))
        }
    };
    let mut update = ManagedUserUpdate {
        role: request.role,
        status: request.status,
        enabled: request.enabled,
        permissions: request
            .permissions
            .map(without_deprecated_agent_permissions),
        expires_at,
        display_name: normalize_nickname_patch(request.display_name)?,
        email: patch_optional(request.email),
        avatar_url: normalize_avatar_patch(request.avatar_url)?,
        proxy_address_ids: request.proxy_address_ids,
        disabled_by: (request.status == Some(AccountStatus::Disabled)).then(|| AccountActor {
            account_id: session.account.account_id.clone(),
            login_name: session.account.login_name.clone(),
        }),
        changed_by: Some(AccountActor {
            account_id: session.account.account_id.clone(),
            login_name: session.account.login_name.clone(),
        }),
        audit_reason: request.audit_reason,
    };
    // Web 托管账号的四项基础能力是不可撤销的；历史导入 profile 没有
    // Web 账号和可恢复私钥，必须保留其原始权限语义。
    if managed.account.is_some() {
        if update.expires_at == Some(None) {
            return Err(ApiError::bad_request(
                "Web 用户的 expires_at 不能清空；请设置明确的过期时间",
            ));
        }
        if let Some(target_expires_at) = update.expires_at
            && match managed.profile.as_ref() {
                None => true,
                Some(profile) => {
                    let timestamp = current_timestamp();
                    let currently_expired = profile
                        .expires_at
                        .is_some_and(|expires_at| expires_at <= timestamp);
                    let target_is_unexpired =
                        target_expires_at.is_none_or(|expires_at| expires_at > timestamp);
                    currently_expired && target_is_unexpired
                }
            }
        {
            return Err(ApiError::conflict(
                "key_request_required",
                "不能通过修改有效期恢复旧密钥，请由用户提交密钥申请并审批",
            ));
        }
        update.permissions = update.permissions.map(with_required_web_permissions);
    }
    if update.is_empty() {
        return Err(ApiError::bad_request("至少提供一个需要修改的字段"));
    }

    let updated = if let Some(account) = managed.account {
        state
            .accounts
            .update_managed_user(&account.account_id, update)
            .await?
    } else {
        if update.role.is_some()
            || update.status.is_some()
            || update.display_name.is_some()
            || update.email.is_some()
            || update.avatar_url.is_some()
            || update.proxy_address_ids.is_some()
        {
            return Err(ApiError::bad_request(
                "历史 legacy 用户尚未绑定 Web 账号，不能修改账号字段",
            ));
        }
        let profile = managed
            .profile
            .ok_or_else(|| ApiError::not_found("用户不存在"))?;
        let profile = state
            .users
            .update_user(
                &profile.username,
                UserUpdate {
                    public_key_pem: None,
                    permissions: update.permissions,
                    enabled: update.enabled,
                    expires_at: update.expires_at,
                    changed_by: update.changed_by,
                    audit_reason: update.audit_reason,
                },
            )
            .await?;
        ManagedUser {
            account: None,
            profile: Some(profile),
            has_private_key: false,
            providers: Vec::new(),
            assigned_proxy_addresses: Vec::new(),
            selected_proxy_address: None,
        }
    };
    info!(
        admin_account_id = session.account.account_id,
        identifier, "管理员更新用户"
    );
    Ok(Json(updated.into()))
}

#[instrument(skip(state, headers), fields(identifier))]
pub(crate) async fn admin_delete_user(
    State(state): State<AppState>,
    Path(identifier): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    validate_browser_mutation(&headers)?;
    let session = require_admin(&state, &headers).await?;
    state.sessions.require_csrf(&session, &headers)?;
    let managed = resolve_managed_user(&state, &identifier).await?;
    if let Some(account) = managed.account {
        state
            .accounts
            .delete_managed_user(&account.account_id)
            .await?;
    } else if let Some(profile) = managed.profile {
        if profile.enabled {
            return Err(ApiError::conflict(
                "account_not_disabled",
                "只有已停用的用户才能删除",
            ));
        }
        state.users.delete_user(&profile.username).await?;
    } else {
        return Err(ApiError::not_found("用户不存在"));
    }
    info!(
        admin_account_id = session.account.account_id,
        identifier, "管理员删除用户"
    );
    Ok(StatusCode::NO_CONTENT)
}

#[instrument(skip(state, headers, payload), fields(identifier))]
pub(crate) async fn admin_rotate_key(
    State(state): State<AppState>,
    Path(identifier): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<AdminRotateKeyRequest>, JsonRejection>,
) -> Result<Json<AdminKeyRotationResponse>, ApiError> {
    validate_browser_mutation(&headers)?;
    let session = require_admin(&state, &headers).await?;
    state.sessions.require_csrf(&session, &headers)?;
    let Json(payload) = payload.map_err(ApiError::from_json_rejection)?;
    let mut managed = resolve_managed_user(&state, &identifier).await?;
    if managed.account.is_none() {
        return Err(ApiError::bad_request(
            "legacy 用户没有可登录的 Web 账号，不能生成无人可领取的密钥",
        ));
    }
    match key_state(&managed, current_timestamp()) {
        KeyState::Active => {}
        KeyState::Disabled => {
            return Err(ApiError::forbidden("Proxy 用户已停用，不能轮换密钥"));
        }
        KeyState::Missing | KeyState::Expired => {
            return Err(ApiError::conflict(
                "key_request_required",
                "该用户需要先提交密钥申请并由管理员审批",
            ));
        }
    }
    let profile = managed
        .profile
        .take()
        .ok_or_else(|| ApiError::not_found("该账号没有 Proxy 用户配置"))?;
    let updated_profile = rotate_profile_key_for_admin(
        &state,
        profile,
        AccountActor {
            account_id: session.account.account_id.clone(),
            login_name: session.account.login_name.clone(),
        },
        payload.reason,
    )
    .await?;
    let key_version = updated_profile.key_version;
    info!(
        admin_account_id = session.account.account_id,
        username = updated_profile.username,
        "管理员重生成用户 RSA 密钥"
    );
    managed.profile = Some(updated_profile);
    managed.has_private_key = true;
    Ok(Json(AdminKeyRotationResponse {
        user: managed.into(),
        key_version,
    }))
}
