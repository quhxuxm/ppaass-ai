use super::super::*;

pub(crate) async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        instance_id: state.instance_id,
    })
}

pub(crate) async fn get_auth_providers(State(state): State<AppState>) -> Json<ProvidersResponse> {
    Json(ProvidersResponse {
        local_registration: state.allow_registration,
    })
}

#[instrument(skip(state, headers, payload))]
pub(crate) async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<RegistrationRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    validate_browser_mutation(&headers)?;
    if !state.allow_registration {
        return Err(ApiError::forbidden("普通用户注册未启用"));
    }
    let Json(request) = payload.map_err(ApiError::from_json_rejection)?;
    let username = normalize_username(&request.username)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let password_hash = state
        .passwords
        .hash_password(request.password)
        .await
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let account = state
        .accounts
        .create_user_account(NewUserAccount {
            account_id: new_account_id(),
            login_name: username.clone(),
            password_hash: Some(password_hash),
            display_name: normalize_nickname(request.display_name)?,
            email: None,
            avatar_url: None,
            external_identity: None,
        })
        .await?;
    info!(
        account_id = account.account_id,
        username, "普通用户账号注册成功，等待提交密钥申请"
    );
    finish_login(&state, account).await
}
#[instrument(skip(state, headers, payload))]
pub(crate) async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<PasswordLoginRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    validate_browser_mutation(&headers)?;
    let Json(request) = payload.map_err(ApiError::from_json_rejection)?;
    let account = authenticate_password_account(&state, request).await?;
    finish_login(&state, account).await
}

pub(crate) async fn authenticate_password_account(
    state: &AppState,
    request: PasswordLoginRequest,
) -> Result<WebAccount, ApiError> {
    let normalized_login_name = normalize_username(&request.username).ok();
    let record = match normalized_login_name {
        Some(login_name) => state.accounts.get_login_record(&login_name).await?,
        None => None,
    };
    let password_hash = record
        .as_ref()
        .and_then(|record| record.password_hash.clone());
    let valid = state
        .passwords
        .verify_password(request.password, password_hash)
        .await
        .map_err(|_| ApiError::internal())?;
    let Some(record) = record.filter(|_| valid) else {
        return Err(ApiError::invalid_credentials());
    };
    if record.account.status != AccountStatus::Active {
        return Err(ApiError::invalid_credentials());
    }
    Ok(record.account)
}

pub(crate) async fn finish_login(
    state: &AppState,
    account: WebAccount,
) -> Result<Response, ApiError> {
    let login_time = OffsetDateTime::now_utc().unix_timestamp();
    state
        .accounts
        .update_last_login(&account.account_id, login_time)
        .await?;
    let (session, cookie) = state.sessions.issue(&account);
    let mut response = Json(AuthenticationResponse {
        registry_instance_id: state.instance_id.clone(),
        account,
        csrf_token: session.csrf_token,
        session_expires_at: session.expires_at,
    })
    .into_response();
    append_set_cookie(response.headers_mut(), cookie);
    Ok(response)
}

#[instrument(skip(state, headers))]
pub(crate) async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    validate_browser_mutation(&headers)?;
    let session = state
        .sessions
        .authenticate(state.accounts.as_ref(), &headers)
        .await?;
    state.sessions.require_csrf(&session, &headers)?;
    let cookie = state.sessions.clear(&headers);
    let mut response = StatusCode::NO_CONTENT.into_response();
    append_set_cookie(response.headers_mut(), cookie);
    Ok(response)
}

pub(crate) async fn get_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let response = match state
        .sessions
        .authenticate(state.accounts.as_ref(), &headers)
        .await
    {
        Ok(session) => SessionResponse {
            registry_instance_id: state.instance_id.clone(),
            authenticated: true,
            account: Some(session.account),
            agent_handoff: session.agent_handoff,
            csrf_token: Some(session.csrf_token),
            expires_at: Some(session.expires_at),
        },
        Err(error) if error.is_unauthorized() => SessionResponse {
            registry_instance_id: state.instance_id.clone(),
            authenticated: false,
            account: None,
            agent_handoff: false,
            csrf_token: None,
            expires_at: None,
        },
        Err(error) => return Err(error),
    };
    Ok(Json(response).into_response())
}
