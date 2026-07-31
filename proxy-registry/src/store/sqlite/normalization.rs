use super::*;

pub(super) fn normalize_new_user(user: NewUser) -> Result<NewUser> {
    let (username, public_key_pem) = validate_user(&user.username, &user.public_key_pem)?;
    let permissions = normalize_permissions(&user.permissions)?;
    Ok(NewUser {
        username,
        public_key_pem,
        permissions,
        enabled: user.enabled,
        origin: user.origin,
        expires_at: user.expires_at,
    })
}

pub(super) fn encode_permissions(permissions: &[String]) -> String {
    permissions.join(",")
}

pub(super) fn decode_permissions(
    encoded: &str,
) -> std::result::Result<Vec<String>, ValidationError> {
    let permissions = if encoded.is_empty() {
        Vec::new()
    } else {
        encoded.split(',').map(ToString::to_string).collect()
    };
    normalize_permissions(&permissions)
}

pub(super) fn normalize_account_id(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(ValidationError::InvalidAccountField("account_id 不能为空".to_string()).into());
    }
    if value.len() > MAX_ACCOUNT_ID_BYTES {
        return Err(ValidationError::InvalidAccountField(format!(
            "account_id 不能超过 {MAX_ACCOUNT_ID_BYTES} 字节"
        ))
        .into());
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ValidationError::InvalidAccountField(
            "account_id 只能包含 ASCII 字母、数字、点、下划线或连字符".to_string(),
        )
        .into());
    }
    Ok(value.to_string())
}

pub(super) fn normalize_code_hash(field: &str, value: &str) -> Result<String> {
    let expected_bytes = match field {
        "device_code_hash" => DEVICE_CODE_HASH_BYTES,
        "user_code_hash" => USER_CODE_HASH_BYTES,
        _ => {
            return Err(UserRepositoryError::InvalidSchema(
                "未知的 Agent code hash 字段".to_string(),
            ));
        }
    };
    if value.len() != expected_bytes
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ValidationError::InvalidAccountField(format!(
            "{field} 必须是 {expected_bytes} 字节的 base64url SHA-256 摘要"
        ))
        .into());
    }
    Ok(value.to_string())
}

pub(super) fn normalize_agent_client_name(value: &str) -> Result<String> {
    normalize_field("client_name", value, MAX_AGENT_CLIENT_NAME_BYTES)
}

pub(super) fn normalize_agent_platform(value: &str) -> Result<String> {
    normalize_stable_identifier("platform", value, MAX_AGENT_PLATFORM_BYTES)
}

pub(super) fn normalize_request_id(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(ValidationError::InvalidAccountField("request_id 不能为空".to_string()).into());
    }
    if value.len() > MAX_REQUEST_ID_BYTES {
        return Err(ValidationError::InvalidAccountField(format!(
            "request_id 不能超过 {MAX_REQUEST_ID_BYTES} 字节"
        ))
        .into());
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ValidationError::InvalidAccountField(
            "request_id 只能包含 ASCII 字母、数字、点、下划线或连字符".to_string(),
        )
        .into());
    }
    Ok(value.to_string())
}

pub(super) fn normalize_access_target_host(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > MAX_ACCESS_TARGET_HOST_BYTES {
        return Err(ValidationError::InvalidAccountField(format!(
            "target_host 必须为 1..={MAX_ACCESS_TARGET_HOST_BYTES} 字节"
        ))
        .into());
    }
    if value.chars().any(char::is_control) {
        return Err(ValidationError::InvalidAccountField(
            "target_host 不能包含控制字符".to_string(),
        )
        .into());
    }
    Ok(value.to_ascii_lowercase())
}

pub(super) fn validate_retention_days(retention_days: u16) -> Result<()> {
    if !(MIN_ACCESS_LOG_RETENTION_DAYS..=MAX_ACCESS_LOG_RETENTION_DAYS).contains(&retention_days) {
        return Err(ValidationError::InvalidAccountField(format!(
            "访问记录保留天数必须在 {MIN_ACCESS_LOG_RETENTION_DAYS}..={MAX_ACCESS_LOG_RETENTION_DAYS} 范围内"
        ))
        .into());
    }
    Ok(())
}

pub(super) fn parse_retention_days(value: &str) -> Result<u16> {
    let retention_days = value.parse::<u16>().map_err(|_| {
        UserRepositoryError::InvalidSchema(format!(
            "access_log_retention_days 不是有效整数：{value}"
        ))
    })?;
    if !(MIN_ACCESS_LOG_RETENTION_DAYS..=MAX_ACCESS_LOG_RETENTION_DAYS).contains(&retention_days) {
        return Err(UserRepositoryError::InvalidSchema(format!(
            "access_log_retention_days 必须在 {MIN_ACCESS_LOG_RETENTION_DAYS}..={MAX_ACCESS_LOG_RETENTION_DAYS} 范围内，实际为 {retention_days}"
        )));
    }
    Ok(retention_days)
}

pub(super) fn ensure_active_key_account(account: &WebAccount) -> Result<()> {
    if account.status != AccountStatus::Active {
        return Err(UserRepositoryError::KeyRequestNotEligible {
            account_id: account.account_id.clone(),
            reason: "账号已停用".to_string(),
        });
    }
    Ok(())
}

pub(super) fn ensure_active_admin(account: &WebAccount) -> Result<()> {
    if account.role != AccountRole::Admin || account.status != AccountStatus::Active {
        return Err(UserRepositoryError::ReviewerNotActiveAdmin {
            account_id: account.account_id.clone(),
        });
    }
    Ok(())
}

pub(super) fn normalize_provider(value: &str) -> Result<String> {
    normalize_stable_identifier("provider", value, MAX_PROVIDER_BYTES)
}

pub(super) fn normalize_stable_identifier(
    field: &str,
    value: &str,
    max_bytes: usize,
) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(ValidationError::InvalidAccountField(format!("{field} 不能为空")).into());
    }
    if value.len() > max_bytes {
        return Err(ValidationError::InvalidAccountField(format!(
            "{field} 不能超过 {max_bytes} 字节"
        ))
        .into());
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
    }) {
        return Err(ValidationError::InvalidAccountField(format!(
            "{field} 只能包含 ASCII 小写字母、数字、点、下划线或连字符"
        ))
        .into());
    }
    Ok(value.to_string())
}

pub(super) fn normalize_provider_subject(value: &str) -> Result<String> {
    if value.is_empty() {
        return Err(
            ValidationError::InvalidAccountField("外部身份 subject 不能为空".to_string()).into(),
        );
    }
    if value.len() > MAX_PROVIDER_SUBJECT_BYTES {
        return Err(ValidationError::InvalidAccountField(format!(
            "外部身份 subject 不能超过 {MAX_PROVIDER_SUBJECT_BYTES} 字节"
        ))
        .into());
    }
    if value.chars().any(char::is_control) {
        return Err(ValidationError::InvalidAccountField(
            "外部身份 subject 不能包含控制字符".to_string(),
        )
        .into());
    }
    Ok(value.to_string())
}

pub(super) fn normalize_external_identity(identity: ExternalIdentity) -> Result<ExternalIdentity> {
    Ok(ExternalIdentity {
        provider: normalize_provider(&identity.provider)?,
        subject: normalize_provider_subject(&identity.subject)?,
    })
}

pub(super) fn normalize_password_hash(value: Option<String>) -> Result<Option<String>> {
    value
        .map(|value| {
            if value.is_empty() || value.len() > MAX_PASSWORD_HASH_BYTES {
                return Err(ValidationError::InvalidAccountField(format!(
                    "password_hash 必须为 1..={MAX_PASSWORD_HASH_BYTES} 字节"
                ))
                .into());
            }
            if value.chars().any(char::is_control) {
                return Err(ValidationError::InvalidAccountField(
                    "password_hash 不能包含控制字符".to_string(),
                )
                .into());
            }
            Ok(value)
        })
        .transpose()
}

pub(super) fn normalize_optional_field(
    field: &str,
    value: Option<String>,
    max_bytes: usize,
) -> Result<Option<String>> {
    value
        .map(|value| normalize_field(field, &value, max_bytes))
        .transpose()
}

pub(super) fn normalize_field(field: &str, value: &str, max_bytes: usize) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(ValidationError::InvalidAccountField(format!("{field} 不能为空")).into());
    }
    if value.len() > max_bytes {
        return Err(ValidationError::InvalidAccountField(format!(
            "{field} 不能超过 {max_bytes} 字节"
        ))
        .into());
    }
    if value.chars().any(char::is_control) {
        return Err(
            ValidationError::InvalidAccountField(format!("{field} 不能包含控制字符")).into(),
        );
    }
    Ok(value.to_string())
}

pub(super) fn validate_private_key_envelope(value: &[u8]) -> Result<()> {
    if value.is_empty() || value.len() > MAX_PRIVATE_KEY_ENVELOPE_BYTES {
        return Err(ValidationError::InvalidAccountField(format!(
            "encrypted_private_key 必须为 1..={MAX_PRIVATE_KEY_ENVELOPE_BYTES} 字节"
        ))
        .into());
    }
    Ok(())
}

pub(super) fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}
