use super::super::*;

pub(crate) async fn get_me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<MeResponse>, ApiError> {
    let session = authenticate(&state, &headers).await?;
    let managed = state
        .accounts
        .get_managed_user(&session.account.account_id)
        .await?
        .ok_or_else(|| ApiError::not_found("账号不存在"))?;
    let pending_request = state
        .accounts
        .get_pending_key_generation_request(&session.account.account_id)
        .await?
        .map(SelfKeyRequestResponse::from_request);
    let key_state = key_state(&managed, current_timestamp());
    let expose_public_key = key_state == KeyState::Active;
    let mut proxy_addresses = managed
        .assigned_proxy_addresses
        .iter()
        .filter(|address| address.enabled)
        .map(|address| address.address.clone())
        .collect::<Vec<_>>();
    proxy_addresses.sort_unstable();
    proxy_addresses.dedup();
    Ok(Json(MeResponse {
        account: session.account,
        profile: managed
            .profile
            .map(|profile| me_profile_response(profile, expose_public_key, proxy_addresses)),
        key_state,
        pending_request,
    }))
}

#[instrument(skip(state, headers, payload))]
pub(crate) async fn change_my_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<ChangePasswordRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    validate_browser_mutation(&headers)?;
    let session = authenticate(&state, &headers).await?;
    state.sessions.require_csrf(&session, &headers)?;
    let Json(request) = payload.map_err(ApiError::from_json_rejection)?;
    let login = state
        .accounts
        .get_login_record(&session.account.login_name)
        .await?
        .filter(|record| record.account.account_id == session.account.account_id)
        .ok_or_else(ApiError::unauthorized)?;
    let current_password_valid = state
        .passwords
        .verify_password(request.current_password, login.password_hash)
        .await
        .map_err(|_| ApiError::internal())?;
    if !current_password_valid {
        return Err(ApiError::invalid_current_password());
    }
    let password_hash = state
        .passwords
        .hash_password(request.new_password)
        .await
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let account = state
        .accounts
        .update_password_hash(
            &session.account.account_id,
            session.account.auth_version,
            password_hash,
        )
        .await?;

    state.sessions.revoke_account(&account.account_id);
    let cookie = state.sessions.clear(&headers);
    let mut response = StatusCode::NO_CONTENT.into_response();
    append_set_cookie(response.headers_mut(), cookie);
    info!(
        account_id = account.account_id,
        auth_version = account.auth_version,
        "用户修改登录密码，旧 Web 会话已撤销"
    );
    Ok(response)
}

pub(crate) async fn get_my_private_key(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<PrivateKeyResponse>, ApiError> {
    let session = authenticate(&state, &headers).await?;
    let profile = require_active_key_profile(&state, &session.account).await?;
    require_profile_permission(&profile, PRIVATE_KEY_READ_PERMISSION)?;
    Ok(Json(load_private_key(&state, profile).await?))
}

#[instrument(skip(state, headers))]
pub(crate) async fn rotate_my_key(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<PrivateKeyResponse>, ApiError> {
    validate_browser_mutation(&headers)?;
    let session = authenticate(&state, &headers).await?;
    state.sessions.require_csrf(&session, &headers)?;
    let profile = require_active_key_profile(&state, &session.account).await?;
    require_profile_permission(&profile, KEY_ROTATE_PERMISSION)?;
    let response = rotate_profile_key(&state, profile).await?;
    info!(username = response.username, "用户重生成自己的 RSA 密钥");
    Ok(Json(response))
}

pub(crate) async fn get_my_key_request(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<MyKeyRequestResponse>, ApiError> {
    let session = authenticate(&state, &headers).await?;
    let request = state
        .accounts
        .get_pending_key_generation_request(&session.account.account_id)
        .await?
        .map(SelfKeyRequestResponse::from_request);
    Ok(Json(MyKeyRequestResponse { request }))
}

#[instrument(skip(state, headers, payload))]
pub(crate) async fn submit_my_key_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Bytes, BytesRejection>,
) -> Result<Response, ApiError> {
    validate_browser_mutation(&headers)?;
    let session = authenticate(&state, &headers).await?;
    state.sessions.require_csrf(&session, &headers)?;
    let request_message = parse_optional_key_request_payload(&headers, payload).await?;

    if let Some(existing) = state
        .accounts
        .get_pending_key_generation_request(&session.account.account_id)
        .await?
    {
        return Ok(Json(SelfKeyRequestResponse::from_request(existing)).into_response());
    }

    let managed = state
        .accounts
        .get_managed_user(&session.account.account_id)
        .await?
        .ok_or_else(|| ApiError::not_found("账号不存在"))?;
    match key_state(&managed, current_timestamp()) {
        KeyState::Active => {
            return Err(ApiError::conflict(
                "key_already_active",
                "现有密钥仍有效，请直接使用自助轮换接口",
            ));
        }
        KeyState::Disabled => {
            return Err(ApiError::forbidden("Proxy 用户已停用，不能申请密钥"));
        }
        KeyState::Missing | KeyState::Expired => {}
    }

    let request = NewKeyGenerationRequest {
        request_id: new_key_request_id(),
        account_id: session.account.account_id.clone(),
        request_message,
    };
    let (status, request) = match state.accounts.submit_key_generation_request(request).await {
        Ok(request) => (StatusCode::CREATED, request),
        Err(UserRepositoryError::PendingKeyRequestConflict { .. }) => {
            let request = state
                .accounts
                .get_pending_key_generation_request(&session.account.account_id)
                .await?
                .ok_or_else(ApiError::internal)?;
            (StatusCode::OK, request)
        }
        Err(error) => return Err(error.into()),
    };
    info!(
        account_id = session.account.account_id,
        request_id = request.request_id,
        kind = request.kind.as_str(),
        "用户提交密钥申请"
    );
    Ok((status, Json(SelfKeyRequestResponse::from_request(request))).into_response())
}

async fn parse_optional_key_request_payload(
    headers: &HeaderMap,
    payload: Result<Bytes, BytesRejection>,
) -> Result<Option<String>, ApiError> {
    let payload = payload.map_err(ApiError::from_bytes_rejection)?;
    if payload.is_empty() {
        return Ok(None);
    }

    let mut request = axum::extract::Request::new(Body::from(payload));
    *request.headers_mut() = headers.clone();
    let Json(payload) = Json::<SubmitKeyRequest>::from_request(request, &())
        .await
        .map_err(ApiError::from_json_rejection)?;
    Ok(payload.message)
}

pub(crate) async fn get_my_access_records(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<AccessRecordsQuery>, QueryRejection>,
) -> Result<Json<AccessRecordsResponse>, ApiError> {
    let session = authenticate(&state, &headers).await?;
    let Query(query) = query.map_err(|_| ApiError::bad_request("访问记录查询参数无效"))?;
    if !(1..=MAX_ACCESS_LOG_QUERY_LIMIT).contains(&query.limit) {
        return Err(ApiError::bad_request(format!(
            "limit 必须在 1..={MAX_ACCESS_LOG_QUERY_LIMIT} 之间"
        )));
    }
    let settings = state.access_logs.get_access_log_settings().await?;
    let retention_since = access_log_cutoff(settings.retention_days);
    let since = query.since.unwrap_or(retention_since).max(retention_since);
    let records = match session.account.linked_username.as_deref() {
        Some(username) => state
            .access_logs
            .list_recent_access(username, since, query.limit)
            .await?
            .into_iter()
            .map(AccessRecordResponse::from)
            .collect(),
        None => Vec::new(),
    };
    Ok(Json(AccessRecordsResponse {
        records,
        retention_days: settings.retention_days,
    }))
}
