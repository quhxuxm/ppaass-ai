use super::*;
use crate::store::{ProxyEntryRegistration, normalize_proxy_address};
use proxy_control_protocol::{
    CONTROL_PROTOCOL_VERSION, EntryRegistrationRequest, EntryRegistrationResponse,
    MAX_ENTRY_VERSION_BYTES,
};

pub(super) async fn register_entry(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Json(request): Json<EntryRegistrationRequest>,
) -> Result<Json<EntryRegistrationResponse>, ControlApiError> {
    require_control_token(&state, &headers)?;
    validate_safe_identifier("entry_id", &request.entry_id, MAX_ENTRY_ID_BYTES)?;
    validate_entry_version(&request.version)?;
    if request.protocol_version != CONTROL_PROTOCOL_VERSION {
        return Err(ControlApiError::bad_request(format!(
            "控制协议版本不兼容：Entry={}，Registry={CONTROL_PROTOCOL_VERSION}",
            request.protocol_version
        )));
    }
    let advertised_address = normalize_proxy_address(&request.advertised_address)
        .map_err(|error| ControlApiError::bad_request(error.to_string()))?;
    let received_at = OffsetDateTime::now_utc().unix_timestamp();
    state
        .proxy_entries
        .register_proxy_entry(ProxyEntryRegistration {
            entry_id: request.entry_id.clone(),
            version: request.version,
            advertised_address,
            received_at,
        })
        .await?;
    tracing::debug!(
        entry_id = request.entry_id,
        registry_instance_id = %state.instance_id,
        "Proxy Entry 注册心跳已接收"
    );
    Ok(Json(EntryRegistrationResponse {
        registry_instance_id: state.instance_id.to_string(),
        protocol_version: CONTROL_PROTOCOL_VERSION,
        received_at,
    }))
}

fn validate_entry_version(version: &str) -> Result<(), ControlApiError> {
    if version.is_empty()
        || version.len() > MAX_ENTRY_VERSION_BYTES
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+'))
    {
        return Err(ControlApiError::bad_request(format!(
            "version 必须是 1..={MAX_ENTRY_VERSION_BYTES} 字节的安全版本号"
        )));
    }
    Ok(())
}
