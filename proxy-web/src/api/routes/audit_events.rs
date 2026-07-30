use super::super::*;

pub(crate) async fn admin_list_audit_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<AuditEventsQuery>, QueryRejection>,
) -> Result<Json<AuditEventsResponse>, ApiError> {
    require_admin_actor(&state, &headers, false).await?;
    let Query(query) = query.map_err(ApiError::from_query_rejection)?;
    if !(1..=500).contains(&query.limit) {
        return Err(ApiError::bad_request("审计记录 limit 必须在 1..=500 之间"));
    }
    if query.before_audit_id.is_some_and(|value| value <= 0) {
        return Err(ApiError::bad_request(
            "before_audit_id 必须是大于 0 的审计编号",
        ));
    }
    let search = trim_optional(query.search);
    if search
        .as_deref()
        .is_some_and(|value| value.chars().count() > MAX_AUDIT_SEARCH_CHARACTERS)
    {
        return Err(ApiError::bad_request(format!(
            "审计搜索关键字不能超过 {MAX_AUDIT_SEARCH_CHARACTERS} 个字符"
        )));
    }
    let events = state
        .audit_logs
        .list_audit_events(AuditEventQuery {
            before_audit_id: query.before_audit_id,
            limit: query.limit,
            action: query.action,
            search,
        })
        .await?;
    Ok(Json(AuditEventsResponse { events }))
}
