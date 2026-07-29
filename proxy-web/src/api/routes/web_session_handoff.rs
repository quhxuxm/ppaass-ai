use super::super::*;

const AGENT_HANDOFF_PATH_PREFIX: &str = "/api/v1/auth/agent-handoff?code=";

#[instrument(skip(state, headers))]
pub(crate) async fn create_agent_web_session_handoff(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AgentWebSessionHandoffResponse>, ApiError> {
    validate_native_agent_request(&headers)?;
    let account = authenticate_agent_token(&state, &headers).await?;
    require_active_agent_account(&account)?;
    let issued = state
        .web_session_handoffs
        .issue(&account)
        .map_err(|error| match error {
            AgentWebSessionHandoffIssueError::Capacity => ApiError::device_authorization_error(
                StatusCode::TOO_MANY_REQUESTS,
                "web_session_handoff_capacity",
                "当前账户管理交接请求过多，请稍后重试",
                Some(30),
            ),
        })?;
    info!(
        account_id = account.account_id,
        expires_at = issued.expires_at,
        "Agent 已创建一次性 Web 会话交接"
    );
    Ok(Json(AgentWebSessionHandoffResponse {
        handoff_path: format!("{AGENT_HANDOFF_PATH_PREFIX}{}", issued.code),
        expires_in: AGENT_WEB_SESSION_HANDOFF_TTL_SECONDS,
    }))
}

#[instrument(skip(state, headers, payload))]
pub(crate) async fn consume_agent_web_session_handoff(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Query<AgentWebSessionHandoffQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    validate_browser_mutation(&headers)?;
    let Query(request) = payload.map_err(ApiError::from_query_rejection)?;
    let claim = state
        .web_session_handoffs
        .consume(&request.code)
        .map_err(|error| {
            match error {
                AgentWebSessionHandoffConsumeError::InvalidOrConsumed => {
                    tracing::debug!("拒绝无效或已使用的 Agent Web 会话交接码");
                }
                AgentWebSessionHandoffConsumeError::Expired => {
                    tracing::debug!("拒绝已过期的 Agent Web 会话交接码");
                }
            }
            ApiError::bad_request("账户管理交接链接无效、已过期或已使用")
        })?;
    let account = state
        .accounts
        .get_account_by_id(&claim.account_id)
        .await?
        .ok_or_else(ApiError::unauthorized)?;
    if account.status != AccountStatus::Active {
        warn!(
            account_id = account.account_id,
            "拒绝为已停用账号建立 Agent Web 会话"
        );
        return Err(ApiError::forbidden("账号已停用"));
    }
    if account.auth_version != claim.account_auth_version {
        warn!(
            account_id = account.account_id,
            "拒绝认证版本已变化的 Agent Web 会话交接"
        );
        return Err(ApiError::unauthorized());
    }

    state
        .accounts
        .update_last_login(&account.account_id, current_timestamp())
        .await?;
    state.sessions.clear(&headers);
    let (_session, cookie) = state.sessions.issue(&account);
    let mut response = StatusCode::SEE_OTHER.into_response();
    response
        .headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static("/"));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    append_set_cookie(response.headers_mut(), cookie);
    info!(
        account_id = account.account_id,
        "Agent 一次性交接已建立 Web 会话"
    );
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handoff_path_is_the_exact_account_management_endpoint() {
        assert_eq!(
            format!("{AGENT_HANDOFF_PATH_PREFIX}{}", "A".repeat(43)),
            format!("/api/v1/auth/agent-handoff?code={}", "A".repeat(43))
        );
    }
}
