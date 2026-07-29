use super::super::*;

pub(crate) async fn admin_list_key_requests(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AdminKeyRequestsResponse>, ApiError> {
    require_admin(&state, &headers).await?;
    let requests = state
        .accounts
        .list_pending_key_generation_requests()
        .await?;
    let mut responses = Vec::with_capacity(requests.len());
    for request in requests {
        responses.push(admin_key_request_response(&state, request).await?);
    }
    Ok(Json(AdminKeyRequestsResponse {
        requests: responses,
    }))
}

#[instrument(skip(state, headers, payload), fields(request_id))]
pub(crate) async fn admin_approve_key_request(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<ApproveKeyRequest>, JsonRejection>,
) -> Result<Json<AdminKeyRequestDecisionResponse>, ApiError> {
    validate_browser_mutation(&headers)?;
    let session = require_admin(&state, &headers).await?;
    state.sessions.require_csrf(&session, &headers)?;
    let Json(payload) = payload.map_err(ApiError::from_json_rejection)?;
    let expires_at = parse_future_expiration(payload.expires_at, "key-request")?;
    let request = state
        .accounts
        .get_key_generation_request(&request_id)
        .await?
        .ok_or_else(|| UserRepositoryError::KeyRequestNotFound(request_id.clone()))?;
    if request.status != KeyRequestStatus::Pending {
        return Err(UserRepositoryError::KeyRequestAlreadyReviewed {
            request_id,
            status: request.status,
        }
        .into());
    }

    let managed = state
        .accounts
        .get_managed_user(&request.account_id)
        .await?
        .ok_or_else(|| ApiError::not_found("申请账号不存在"))?;
    let account = managed.account.as_ref().ok_or_else(ApiError::internal)?;
    let material = approved_key_material(&state, &request, &managed, account, expires_at).await?;
    let result = state
        .accounts
        .approve_key_generation_request(KeyRequestApproval {
            request_id: request.request_id,
            reviewer_account_id: session.account.account_id.clone(),
            expires_at,
            material,
        })
        .await?;
    let request_response = admin_key_request_response(&state, result.request).await?;
    info!(
        admin_account_id = session.account.account_id,
        request_id = request_response.request_id,
        account_id = request_response.account.account_id,
        "管理员批准密钥申请"
    );
    Ok(Json(AdminKeyRequestDecisionResponse {
        request: request_response,
        user: Some(result.managed_user.into()),
    }))
}

#[instrument(skip(state, headers), fields(request_id))]
pub(crate) async fn admin_reject_key_request(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<AdminKeyRequestDecisionResponse>, ApiError> {
    validate_browser_mutation(&headers)?;
    let session = require_admin(&state, &headers).await?;
    state.sessions.require_csrf(&session, &headers)?;
    let request = state
        .accounts
        .reject_key_generation_request(&request_id, &session.account.account_id)
        .await?;
    let request = admin_key_request_response(&state, request).await?;
    info!(
        admin_account_id = session.account.account_id,
        request_id = request.request_id,
        account_id = request.account.account_id,
        "管理员拒绝密钥申请"
    );
    Ok(Json(AdminKeyRequestDecisionResponse {
        request,
        user: None,
    }))
}

pub(crate) async fn admin_get_access_log_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AccessLogSettingsResponse>, ApiError> {
    require_admin(&state, &headers).await?;
    let settings = state.access_logs.get_access_log_settings().await?;
    Ok(Json(AccessLogSettingsResponse {
        retention_days: settings.retention_days,
        purged_records: None,
    }))
}

#[instrument(skip(state, headers, payload))]
pub(crate) async fn admin_update_access_log_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<UpdateAccessLogSettingsRequest>, JsonRejection>,
) -> Result<Json<AccessLogSettingsResponse>, ApiError> {
    validate_browser_mutation(&headers)?;
    let session = require_admin(&state, &headers).await?;
    state.sessions.require_csrf(&session, &headers)?;
    let Json(payload) = payload.map_err(ApiError::from_json_rejection)?;
    if !(MIN_ACCESS_LOG_RETENTION_DAYS..=MAX_ACCESS_LOG_RETENTION_DAYS)
        .contains(&payload.retention_days)
    {
        return Err(ApiError::bad_request(format!(
            "retention_days 必须在 {MIN_ACCESS_LOG_RETENTION_DAYS}..={MAX_ACCESS_LOG_RETENTION_DAYS} 之间"
        )));
    }
    let settings = state
        .access_logs
        .set_access_log_retention_days(payload.retention_days)
        .await?;
    let purged_records = state
        .access_logs
        .purge_access_records_before(access_log_cutoff(settings.retention_days))
        .await?;
    info!(
        admin_account_id = session.account.account_id,
        retention_days = settings.retention_days,
        purged_records,
        "管理员更新访问记录保留期并清理过期记录"
    );
    Ok(Json(AccessLogSettingsResponse {
        retention_days: settings.retention_days,
        purged_records: Some(purged_records),
    }))
}

pub(crate) async fn admin_key_request_response(
    state: &AppState,
    request: KeyGenerationRequest,
) -> Result<AdminKeyRequestResponse, ApiError> {
    let account = state
        .accounts
        .get_account_by_id(&request.account_id)
        .await?
        .ok_or_else(|| ApiError::not_found("密钥申请关联的账号不存在"))?;
    Ok(AdminKeyRequestResponse {
        request_id: request.request_id,
        account,
        request_message: request.request_message,
        kind: request.kind,
        status: request.status,
        expected_key_version: request.expected_key_version,
        reviewer_account_id: request.reviewer_account_id,
        requested_at: request.requested_at,
        reviewed_at: request.reviewed_at,
        approved_expires_at: request.approved_expires_at,
    })
}

pub(crate) async fn approved_key_material(
    state: &AppState,
    request: &KeyGenerationRequest,
    managed: &ManagedUser,
    account: &WebAccount,
    expires_at: i64,
) -> Result<ApprovedKeyMaterial, ApiError> {
    match request.kind {
        KeyRequestKind::Initial => {
            if managed.profile.is_some() || account.linked_username.is_some() {
                return Err(ApiError::conflict(
                    "stale_key_request",
                    "账号已经具备 Proxy 用户配置",
                ));
            }
            let generated =
                generate_stored_keys(&state.private_keys, &account.login_name, 1).await?;
            Ok(ApprovedKeyMaterial::Initial {
                profile: NewUser {
                    username: account.login_name.clone(),
                    public_key_pem: generated.public_key_pem,
                    permissions: default_web_permissions(),
                    enabled: true,
                    origin: initial_user_origin(managed),
                    expires_at: Some(expires_at),
                },
                encrypted_private_key: generated.encrypted_private_key,
            })
        }
        KeyRequestKind::Rotate => {
            let profile = managed
                .profile
                .as_ref()
                .ok_or_else(|| ApiError::conflict("stale_key_request", "Proxy 用户配置不存在"))?;
            if !profile.enabled {
                return Err(ApiError::forbidden("Proxy 用户已停用，不能批准密钥申请"));
            }
            let expected = request
                .expected_key_version
                .ok_or_else(ApiError::internal)?;
            let next_version = expected.checked_add(1).ok_or_else(ApiError::internal)?;
            let generated =
                generate_stored_keys(&state.private_keys, &profile.username, next_version).await?;
            Ok(ApprovedKeyMaterial::Rotate {
                public_key_pem: generated.public_key_pem,
                encrypted_private_key: generated.encrypted_private_key,
            })
        }
    }
}
