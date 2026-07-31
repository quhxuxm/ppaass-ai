use super::super::*;

pub(crate) async fn admin_list_proxy_addresses(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ProxyAddressesResponse>, ApiError> {
    require_admin_actor(&state, &headers, false).await?;
    let proxy_addresses = state
        .proxy_addresses
        .list_proxy_addresses()
        .await?
        .into_iter()
        .map(ProxyAddressResponse::from)
        .collect();
    Ok(Json(ProxyAddressesResponse { proxy_addresses }))
}

#[instrument(skip(state, headers, payload))]
pub(crate) async fn admin_create_proxy_address(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<CreateProxyAddressRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<ProxyAddressResponse>), ApiError> {
    validate_browser_mutation(&headers)?;
    let session = require_admin(&state, &headers).await?;
    state.sessions.require_csrf(&session, &headers)?;
    let Json(payload) = payload.map_err(ApiError::from_json_rejection)?;
    let created = state
        .proxy_addresses
        .create_proxy_address(NewProxyAddress {
            proxy_address_id: format!("pxy_{}", random_token(18)),
            label: payload.label.unwrap_or_default(),
            address: payload.address,
            enabled: payload.enabled,
        })
        .await?;
    info!(
        admin_account_id = session.account.account_id,
        proxy_address_id = created.proxy_address_id,
        "管理员创建 Proxy 地址目录项"
    );
    Ok((
        StatusCode::CREATED,
        Json(ProxyAddressResponse::from(created)),
    ))
}

#[instrument(skip(state, headers, payload), fields(proxy_address_id))]
pub(crate) async fn admin_update_proxy_address(
    State(state): State<AppState>,
    Path(proxy_address_id): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<UpdateProxyAddressRequest>, JsonRejection>,
) -> Result<Json<ProxyAddressResponse>, ApiError> {
    validate_browser_mutation(&headers)?;
    let session = require_admin(&state, &headers).await?;
    state.sessions.require_csrf(&session, &headers)?;
    let Json(payload) = payload.map_err(ApiError::from_json_rejection)?;
    let updated = state
        .proxy_addresses
        .update_proxy_address(
            &proxy_address_id,
            ProxyAddressUpdate {
                label: payload.label,
                address: payload.address,
                enabled: payload.enabled,
                changed_by: Some(AccountActor {
                    account_id: session.account.account_id.clone(),
                    login_name: session.account.login_name.clone(),
                }),
                audit_reason: payload.audit_reason,
            },
        )
        .await?;
    info!(
        admin_account_id = session.account.account_id,
        proxy_address_id = updated.proxy_address_id,
        "管理员更新 Proxy 地址目录项"
    );
    Ok(Json(updated.into()))
}

#[instrument(skip(state, headers), fields(proxy_address_id))]
pub(crate) async fn admin_delete_proxy_address(
    State(state): State<AppState>,
    Path(proxy_address_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    validate_browser_mutation(&headers)?;
    let session = require_admin(&state, &headers).await?;
    state.sessions.require_csrf(&session, &headers)?;
    state
        .proxy_addresses
        .delete_proxy_address(&proxy_address_id)
        .await?;
    info!(
        admin_account_id = session.account.account_id,
        proxy_address_id, "管理员删除 Proxy 地址目录项"
    );
    Ok(StatusCode::NO_CONTENT)
}
