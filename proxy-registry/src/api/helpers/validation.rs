use super::super::*;

pub(crate) fn current_timestamp() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

pub(crate) fn default_access_record_limit() -> u32 {
    DEFAULT_ACCESS_RECORD_LIMIT
}

pub(crate) fn default_audit_event_limit() -> u32 {
    100
}

pub(crate) fn access_log_cutoff(retention_days: u16) -> i64 {
    current_timestamp().saturating_sub(i64::from(retention_days) * SECONDS_PER_DAY)
}

pub(crate) fn enabled_by_default() -> bool {
    true
}

pub(crate) fn trim_optional(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_string())
    })
}

pub(crate) fn serialize_zeroizing_string<S>(
    value: &Zeroizing<String>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(value.as_str())
}

pub(crate) fn patch_optional(value: PatchField<String>) -> Option<Option<String>> {
    match value {
        PatchField::Missing => None,
        PatchField::Null => Some(None),
        PatchField::Value(value) => Some(trim_optional(Some(value))),
    }
}

pub(crate) fn validate_browser_mutation(headers: &HeaderMap) -> Result<(), ApiError> {
    if let Some(site) = headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
        && !matches!(site, "same-origin" | "same-site" | "none")
    {
        return Err(ApiError::forbidden("拒绝跨站修改请求"));
    }
    Ok(())
}

pub(crate) fn validate_browser_navigation(headers: &HeaderMap) -> Result<(), ApiError> {
    if let Some(mode) = headers
        .get("sec-fetch-mode")
        .and_then(|value| value.to_str().ok())
        && mode != "navigate"
    {
        return Err(ApiError::forbidden("账户管理交接只允许浏览器页面导航"));
    }
    if let Some(destination) = headers
        .get("sec-fetch-dest")
        .and_then(|value| value.to_str().ok())
        && destination != "document"
    {
        return Err(ApiError::forbidden("账户管理交接只允许浏览器页面导航"));
    }
    Ok(())
}

pub(crate) fn validate_native_agent_request(headers: &HeaderMap) -> Result<(), ApiError> {
    if headers.contains_key(header::ORIGIN) {
        return Err(ApiError::forbidden(
            "Agent 设备授权接口不接受浏览器跨源请求",
        ));
    }
    if let Some(site) = headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
        && site != "none"
    {
        return Err(ApiError::forbidden(
            "Agent 设备授权接口只接受原生客户端请求",
        ));
    }
    Ok(())
}
