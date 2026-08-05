use super::super::*;

#[instrument(skip(state, headers, payload))]
pub(crate) async fn start_agent_device_authorization(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<AgentDeviceAuthorizationStartRequest>, JsonRejection>,
) -> Result<Json<AgentDeviceAuthorizationStartResponse>, ApiError> {
    validate_native_agent_request(&headers)?;
    let Json(request) = payload.map_err(ApiError::from_json_rejection)?;
    let platform = normalize_agent_platform(&request.platform)?;
    let client_name = request
        .client_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| match platform.as_str() {
            "android" => "PPAASS Android Agent".to_string(),
            "windows" => "PPAASS Windows Agent".to_string(),
            _ => unreachable!("平台已在上方校验"),
        });
    let created_at = current_timestamp();
    let expires_at = created_at.saturating_add(AGENT_DEVICE_AUTHORIZATION_TTL_SECONDS);

    for _ in 0..3 {
        let device_code = random_token(AGENT_DEVICE_CODE_BYTES);
        let user_code = generate_agent_user_code();
        let create = state
            .device_authorizations
            .create_agent_device_authorization(NewAgentDeviceAuthorization {
                device_code_hash: hash_agent_code(
                    AGENT_DEVICE_CODE_HASH_DOMAIN,
                    device_code.as_bytes(),
                ),
                user_code_hash: hash_agent_code(
                    AGENT_USER_CODE_HASH_DOMAIN,
                    canonical_agent_user_code(&user_code)?.as_bytes(),
                ),
                client_name: client_name.clone(),
                platform: platform.clone(),
                created_at,
                expires_at,
            })
            .await;
        match create {
            Ok(()) => {
                return Ok(Json(AgentDeviceAuthorizationStartResponse {
                    device_code,
                    user_code: user_code.clone(),
                    verification_uri: "/#agent-authorize",
                    verification_uri_complete: format!("/#agent-authorize={user_code}"),
                    expires_in: AGENT_DEVICE_AUTHORIZATION_TTL_SECONDS,
                    interval: AGENT_DEVICE_POLL_INTERVAL_SECONDS,
                }));
            }
            Err(UserRepositoryError::AgentDeviceAuthorizationConflict) => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(ApiError::internal())
}

#[instrument(skip(state, headers, payload))]
pub(crate) async fn inspect_agent_device_authorization(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<AgentUserCodeRequest>, JsonRejection>,
) -> Result<Json<AgentDeviceAuthorizationInspectionResponse>, ApiError> {
    validate_browser_mutation(&headers)?;
    let session = authenticate(&state, &headers).await?;
    state.sessions.require_csrf(&session, &headers)?;
    require_active_agent_account(&session.account)?;
    let Json(request) = payload.map_err(ApiError::from_json_rejection)?;
    let user_code_hash = agent_user_code_hash(&request.user_code)?;
    let authorization = state
        .device_authorizations
        .get_agent_device_authorization_by_user_code(&user_code_hash, current_timestamp())
        .await?
        .ok_or_else(|| ApiError::not_found("设备授权码无效"))?;
    ensure_visible_agent_authorization(&authorization, &session.account)?;
    Ok(Json(AgentDeviceAuthorizationInspectionResponse {
        client_name: authorization.client_name,
        platform: authorization.platform,
        expires_at: authorization.expires_at,
        status: authorization.status,
    }))
}

#[instrument(skip(state, headers, payload))]
pub(crate) async fn approve_agent_device_authorization(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<AgentUserCodeRequest>, JsonRejection>,
) -> Result<Json<AgentDeviceAuthorizationDecisionResponse>, ApiError> {
    validate_browser_mutation(&headers)?;
    let session = authenticate(&state, &headers).await?;
    state.sessions.require_csrf(&session, &headers)?;
    require_active_agent_account(&session.account)?;
    let Json(request) = payload.map_err(ApiError::from_json_rejection)?;
    let user_code_hash = agent_user_code_hash(&request.user_code)?;
    let authorization = state
        .device_authorizations
        .get_agent_device_authorization_by_user_code(&user_code_hash, current_timestamp())
        .await?
        .ok_or_else(|| ApiError::not_found("设备授权码无效"))?;
    ensure_visible_agent_authorization(&authorization, &session.account)?;
    // 在 challenge 进入 authorized 之前验证当前密钥可解密，避免 Agent 领取到
    // 一个已知不可用的授权。
    let (_profile, private_key, _proxy_addresses) =
        load_agent_credentials(&state, &session.account).await?;
    drop(private_key);

    let decision = state
        .device_authorizations
        .authorize_agent_device(
            &user_code_hash,
            &session.account.account_id,
            session.account.auth_version,
            current_timestamp(),
        )
        .await?;
    match decision {
        AgentDeviceAuthorizationDecision::Authorized
        | AgentDeviceAuthorizationDecision::AlreadyAuthorized => {
            info!(
                account_id = session.account.account_id,
                "用户批准 Agent 设备登录"
            );
            Ok(Json(AgentDeviceAuthorizationDecisionResponse {
                status: AgentDeviceAuthorizationStatus::Authorized,
            }))
        }
        AgentDeviceAuthorizationDecision::Expired => Err(agent_device_expired_error()),
        AgentDeviceAuthorizationDecision::Denied
        | AgentDeviceAuthorizationDecision::AlreadyDenied => Err(ApiError::conflict(
            "device_authorization_denied",
            "该设备登录已被拒绝",
        )),
        AgentDeviceAuthorizationDecision::Finalized => Err(ApiError::conflict(
            "device_authorization_finalized",
            "该设备登录已完成，不能重复授权",
        )),
        AgentDeviceAuthorizationDecision::NotFound => Err(ApiError::not_found("设备授权码无效")),
    }
}

#[instrument(skip(state, headers, payload))]
pub(crate) async fn deny_agent_device_authorization(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<AgentUserCodeRequest>, JsonRejection>,
) -> Result<Json<AgentDeviceAuthorizationDecisionResponse>, ApiError> {
    validate_browser_mutation(&headers)?;
    let session = authenticate(&state, &headers).await?;
    state.sessions.require_csrf(&session, &headers)?;
    require_active_agent_account(&session.account)?;
    let Json(request) = payload.map_err(ApiError::from_json_rejection)?;
    let decision = state
        .device_authorizations
        .deny_agent_device(
            &agent_user_code_hash(&request.user_code)?,
            &session.account.account_id,
            current_timestamp(),
        )
        .await?;
    match decision {
        AgentDeviceAuthorizationDecision::Denied
        | AgentDeviceAuthorizationDecision::AlreadyDenied => {
            info!(
                account_id = session.account.account_id,
                "用户拒绝 Agent 设备登录"
            );
            Ok(Json(AgentDeviceAuthorizationDecisionResponse {
                status: AgentDeviceAuthorizationStatus::Denied,
            }))
        }
        AgentDeviceAuthorizationDecision::Expired => Err(agent_device_expired_error()),
        AgentDeviceAuthorizationDecision::Authorized
        | AgentDeviceAuthorizationDecision::AlreadyAuthorized => Err(ApiError::conflict(
            "device_authorization_authorized",
            "该设备登录已经获得授权",
        )),
        AgentDeviceAuthorizationDecision::Finalized => Err(ApiError::conflict(
            "device_authorization_finalized",
            "该设备登录已完成，不能重复操作",
        )),
        AgentDeviceAuthorizationDecision::NotFound => Err(ApiError::not_found("设备授权码无效")),
    }
}

#[instrument(skip(state, headers, payload))]
pub(crate) async fn poll_agent_device_authorization(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<AgentDeviceTokenRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    validate_native_agent_request(&headers)?;
    let Json(request) = payload.map_err(ApiError::from_json_rejection)?;
    let device_code_hash = agent_device_code_hash(&request.device_code)?;
    let poll = state
        .device_authorizations
        .poll_agent_device_authorization(&device_code_hash, current_timestamp())
        .await?;
    let (account_id, expected_auth_version) = match poll {
        AgentDeviceAuthorizationPoll::Pending => {
            return Err(ApiError::device_authorization_error(
                StatusCode::PRECONDITION_REQUIRED,
                "authorization_pending",
                "等待用户在浏览器中确认",
                Some(AGENT_DEVICE_POLL_INTERVAL_SECONDS),
            ));
        }
        AgentDeviceAuthorizationPoll::Denied => {
            return Err(ApiError::device_authorization_error(
                StatusCode::FORBIDDEN,
                "access_denied",
                "用户拒绝了该设备登录",
                None,
            ));
        }
        AgentDeviceAuthorizationPoll::Expired => return Err(agent_device_expired_error()),
        AgentDeviceAuthorizationPoll::NotFound | AgentDeviceAuthorizationPoll::Consumed => {
            return Err(ApiError::device_authorization_error(
                StatusCode::BAD_REQUEST,
                "invalid_device_code",
                "设备码无效或已被使用",
                None,
            ));
        }
        AgentDeviceAuthorizationPoll::Authorized {
            account_id,
            account_auth_version,
        } => (account_id, account_auth_version),
    };

    let account = state
        .accounts
        .get_account_by_id(&account_id)
        .await?
        .ok_or_else(agent_device_authorization_invalidated)?;
    if account.auth_version != expected_auth_version {
        return Err(agent_device_authorization_invalidated());
    }
    if require_active_agent_account(&account).is_err() {
        return Err(agent_device_authorization_invalidated());
    }
    let (profile, private_key, proxy_addresses) =
        load_agent_credentials_for_claim(&state, &account).await?;
    let claim = AgentDeviceAuthorizationClaim {
        device_code_hash,
        account_id: account.account_id.clone(),
        account_auth_version: expected_auth_version,
        username: profile.username.clone(),
        permissions: profile.permissions.clone(),
        key_version: profile.key_version,
        expires_at: profile.expires_at,
        now: current_timestamp(),
    };
    let login_time = current_timestamp();
    state
        .accounts
        .update_last_login(&account.account_id, login_time)
        .await?;
    let (session, cookie) = state.sessions.issue(&account);
    let agent_token = state
        .agent_tokens
        .issue(&account.account_id)
        .map_err(|error| {
            state.sessions.revoke_issued(&session);
            warn!(account_id = account.account_id, %error, "签发 Agent access token 失败");
            ApiError::internal()
        })?;
    let response_body = AgentDeviceTokenResponse {
        account,
        profile: AgentDeviceProfileResponse {
            username: profile.username,
            permissions: profile.permissions,
            proxy_addresses,
            enabled: profile.enabled,
            key_version: profile.key_version,
            expires_at: profile.expires_at,
        },
        public_key_pem: private_key.public_key_pem,
        private_key_pem: private_key.private_key_pem,
        csrf_token: session.csrf_token.clone(),
        session_expires_at: session.expires_at,
        agent_access_token: agent_token.token,
        agent_access_token_expires_at: agent_token.expires_at,
        refresh_after_seconds: crate::agent_tokens::AGENT_PROFILE_REFRESH_SECONDS,
    };
    let mut encoded = match serde_json::to_vec(&response_body) {
        Ok(encoded) => Zeroizing::new(encoded),
        Err(_) => {
            state.sessions.revoke_issued(&session);
            return Err(ApiError::internal());
        }
    };
    if encoded.len() > MAX_AGENT_TOKEN_RESPONSE_BYTES {
        state.sessions.revoke_issued(&session);
        warn!(
            account_id = response_body.account.account_id,
            bytes = encoded.len(),
            "拒绝返回异常大小的 Agent 凭据响应"
        );
        return Err(ApiError::internal());
    }
    let finalize = match state
        .device_authorizations
        .finalize_agent_device_authorization(claim)
        .await
    {
        Ok(finalize) => finalize,
        Err(error) => {
            state.sessions.revoke_issued(&session);
            return Err(error.into());
        }
    };
    match finalize {
        AgentDeviceAuthorizationFinalize::Finalized => {}
        AgentDeviceAuthorizationFinalize::AlreadyFinalized => {
            state.sessions.revoke_issued(&session);
            return Err(ApiError::device_authorization_error(
                StatusCode::BAD_REQUEST,
                "invalid_device_code",
                "设备码无效或已被使用",
                None,
            ));
        }
        AgentDeviceAuthorizationFinalize::Expired => {
            state.sessions.revoke_issued(&session);
            return Err(agent_device_expired_error());
        }
        AgentDeviceAuthorizationFinalize::Invalidated
        | AgentDeviceAuthorizationFinalize::NotFound => {
            state.sessions.revoke_issued(&session);
            return Err(agent_device_authorization_invalidated());
        }
    }
    let encoded = std::mem::take(&mut *encoded);
    let mut response = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        encoded,
    )
        .into_response();
    append_set_cookie(response.headers_mut(), cookie);
    Ok(response)
}
