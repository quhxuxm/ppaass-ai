use super::*;

pub(super) fn row_to_user(row: SqliteRow) -> Result<UserRecord> {
    let username: String = row.try_get("username")?;
    let permissions_encoded: String = row.try_get("permissions")?;
    let permissions = decode_permissions(&permissions_encoded).map_err(|error| {
        UserRepositoryError::InvalidSchema(format!("用户 {username} 的 permissions 无效：{error}"))
    })?;
    let enabled: i64 = row.try_get("enabled")?;
    let enabled = match enabled {
        0 => false,
        1 => true,
        value => {
            return Err(UserRepositoryError::InvalidSchema(format!(
                "用户 {username} 的 enabled 值无效：{value}"
            )));
        }
    };
    let origin_encoded: String = row.try_get("origin")?;
    let origin = UserOrigin::parse(&origin_encoded).ok_or_else(|| {
        UserRepositoryError::InvalidSchema(format!(
            "用户 {username} 的 origin 值无效：{origin_encoded}"
        ))
    })?;
    let key_version: i64 = row.try_get("key_version")?;
    if key_version < 1 {
        return Err(UserRepositoryError::InvalidSchema(format!(
            "用户 {username} 的 key_version 值无效：{key_version}"
        )));
    }
    Ok(UserRecord {
        username,
        public_key_pem: row.try_get("public_key_pem")?,
        permissions,
        enabled,
        origin,
        key_version,
        expires_at: row.try_get("expires_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

pub(super) fn row_to_account(row: SqliteRow) -> Result<WebAccount> {
    let account_id: String = row.try_get("account_id")?;
    let role_encoded: String = row.try_get("role")?;
    let role = AccountRole::parse(&role_encoded).ok_or_else(|| {
        UserRepositoryError::InvalidSchema(format!(
            "账号 {account_id} 的 role 值无效：{role_encoded}"
        ))
    })?;
    let status_encoded: String = row.try_get("status")?;
    let status = AccountStatus::parse(&status_encoded).ok_or_else(|| {
        UserRepositoryError::InvalidSchema(format!(
            "账号 {account_id} 的 status 值无效：{status_encoded}"
        ))
    })?;
    let auth_version: i64 = row.try_get("auth_version")?;
    if auth_version < 1 {
        return Err(UserRepositoryError::InvalidSchema(format!(
            "账号 {account_id} 的 auth_version 值无效：{auth_version}"
        )));
    }
    let avatar_url = decode_avatar_url(&row, &account_id)?;
    Ok(WebAccount {
        account_id,
        login_name: row.try_get("login_name")?,
        role,
        status,
        linked_username: row.try_get("linked_username")?,
        display_name: row.try_get("display_name")?,
        email: row.try_get("email")?,
        avatar_url,
        auth_version,
        last_login_at: row.try_get("last_login_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn decode_avatar_url(row: &SqliteRow, account_id: &str) -> Result<Option<String>> {
    let Some(bytes) = row.try_get::<Option<Vec<u8>>, _>("avatar_url")? else {
        return Ok(None);
    };
    match String::from_utf8(bytes) {
        Ok(value) => Ok(Some(value)),
        Err(error) => {
            warn!(
                account_id,
                valid_bytes = error.utf8_error().valid_up_to(),
                "账号头像包含无效 UTF-8，已忽略损坏的头像数据"
            );
            Ok(None)
        }
    }
}

pub(super) fn row_to_encrypted_private_key(row: SqliteRow) -> Result<EncryptedPrivateKey> {
    Ok(EncryptedPrivateKey {
        username: row.try_get("username")?,
        encrypted_private_key: row.try_get("encrypted_private_key")?,
        key_version: row.try_get("key_version")?,
        updated_at: row.try_get("updated_at")?,
    })
}

pub(super) fn row_to_key_request(row: SqliteRow) -> Result<KeyGenerationRequest> {
    let request_id: String = row.try_get("request_id")?;
    let kind_encoded: String = row.try_get("kind")?;
    let kind = KeyRequestKind::parse(&kind_encoded).ok_or_else(|| {
        UserRepositoryError::InvalidSchema(format!(
            "密钥申请 {request_id} 的 kind 值无效：{kind_encoded}"
        ))
    })?;
    let status_encoded: String = row.try_get("status")?;
    let status = KeyRequestStatus::parse(&status_encoded).ok_or_else(|| {
        UserRepositoryError::InvalidSchema(format!(
            "密钥申请 {request_id} 的 status 值无效：{status_encoded}"
        ))
    })?;
    let expected_key_version: Option<i64> = row.try_get("expected_key_version")?;
    let valid_expected_version = match kind {
        KeyRequestKind::Initial => expected_key_version.is_none(),
        KeyRequestKind::Rotate => expected_key_version.is_some_and(|version| version >= 1),
    };
    if !valid_expected_version {
        return Err(UserRepositoryError::InvalidSchema(format!(
            "密钥申请 {request_id} 的 expected_key_version 与 kind 不一致"
        )));
    }
    let reviewer_account_id: Option<String> = row.try_get("reviewer_account_id")?;
    let reviewer_login_name: Option<String> = row.try_get("reviewer_login_name")?;
    let rejection_reason: Option<String> = row.try_get("rejection_reason")?;
    let reviewed_at: Option<i64> = row.try_get("reviewed_at")?;
    let approved_expires_at: Option<i64> = row.try_get("approved_expires_at")?;
    let valid_decision = match status {
        KeyRequestStatus::Pending => {
            reviewer_account_id.is_none()
                && reviewer_login_name.is_none()
                && rejection_reason.is_none()
                && reviewed_at.is_none()
                && approved_expires_at.is_none()
        }
        KeyRequestStatus::Approved => {
            reviewer_account_id.is_some()
                && rejection_reason.is_none()
                && reviewed_at.is_some()
                && approved_expires_at.is_some()
        }
        KeyRequestStatus::Rejected => {
            reviewer_account_id.is_some() && reviewed_at.is_some() && approved_expires_at.is_none()
        }
    };
    let valid_reviewer_name = reviewer_login_name.as_deref().is_none_or(|value| {
        !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
    });
    let valid_rejection_reason = rejection_reason.as_deref().is_none_or(|value| {
        !value.is_empty()
            && value.chars().count() <= 500
            && !value
                .chars()
                .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    });
    if !valid_decision || !valid_reviewer_name || !valid_rejection_reason {
        return Err(UserRepositoryError::InvalidSchema(format!(
            "密钥申请 {request_id} 的审批审计字段不一致"
        )));
    }
    Ok(KeyGenerationRequest {
        request_id,
        account_id: row.try_get("account_id")?,
        request_message: row.try_get("request_message")?,
        kind,
        status,
        expected_key_version,
        reviewer_account_id,
        reviewer_login_name,
        rejection_reason,
        requested_at: row.try_get("requested_at")?,
        reviewed_at,
        approved_expires_at,
    })
}

pub(super) fn row_to_access_record(row: SqliteRow) -> Result<AccessRecord> {
    let record_id: i64 = row.try_get("record_id")?;
    let protocol_encoded: String = row.try_get("protocol")?;
    let protocol = AccessProtocol::parse(&protocol_encoded).ok_or_else(|| {
        UserRepositoryError::InvalidSchema(format!(
            "访问记录 {record_id} 的 protocol 值无效：{protocol_encoded}"
        ))
    })?;
    let target_port: i64 = row.try_get("target_port")?;
    let target_port = u16::try_from(target_port)
        .ok()
        .filter(|port| *port > 0)
        .ok_or_else(|| {
            UserRepositoryError::InvalidSchema(format!(
                "访问记录 {record_id} 的 target_port 值无效：{target_port}"
            ))
        })?;
    Ok(AccessRecord {
        record_id,
        username: row.try_get("username")?,
        protocol,
        target_host: row.try_get("target_host")?,
        target_port,
        access_count: u64::try_from(row.try_get::<i64, _>("access_count")?)
            .ok()
            .filter(|count| *count > 0)
            .ok_or_else(|| {
                UserRepositoryError::InvalidSchema(format!(
                    "访问记录 {record_id} 的 access_count 无效"
                ))
            })?,
        accessed_at: row.try_get("accessed_at")?,
    })
}

pub(super) fn row_to_agent_device_authorization(
    row: SqliteRow,
) -> Result<AgentDeviceAuthorization> {
    let device_code_hash: String = row.try_get("device_code_hash")?;
    let status_encoded: String = row.try_get("status")?;
    let status = AgentDeviceAuthorizationStatus::parse(&status_encoded).ok_or_else(|| {
        UserRepositoryError::InvalidSchema(format!(
            "Agent challenge {device_code_hash} 的 status 值无效：{status_encoded}"
        ))
    })?;
    let authorization = AgentDeviceAuthorization {
        device_code_hash,
        user_code_hash: row.try_get("user_code_hash")?,
        client_name: row.try_get("client_name")?,
        platform: row.try_get("platform")?,
        status,
        authorized_account_id: row.try_get("authorized_account_id")?,
        authorized_auth_version: row.try_get("authorized_auth_version")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        authorized_at: row.try_get("authorized_at")?,
        consumed_at: row.try_get("consumed_at")?,
        last_polled_at: row.try_get("last_polled_at")?,
    };
    let valid = match authorization.status {
        AgentDeviceAuthorizationStatus::Pending => {
            authorization.authorized_account_id.is_none()
                && authorization.authorized_auth_version.is_none()
                && authorization.authorized_at.is_none()
                && authorization.consumed_at.is_none()
        }
        AgentDeviceAuthorizationStatus::Authorized => {
            authorization.authorized_account_id.is_some()
                && authorization
                    .authorized_auth_version
                    .is_some_and(|version| version >= 1)
                && authorization.authorized_at.is_some()
                && authorization.consumed_at.is_none()
        }
        AgentDeviceAuthorizationStatus::Denied => {
            authorization.authorized_account_id.is_some()
                && authorization.authorized_auth_version.is_none()
                && authorization.authorized_at.is_some()
                && authorization.consumed_at.is_none()
        }
        AgentDeviceAuthorizationStatus::Consumed => {
            authorization.authorized_account_id.is_some()
                && authorization
                    .authorized_auth_version
                    .is_some_and(|version| version >= 1)
                && authorization.authorized_at.is_some()
                && authorization.consumed_at.is_some()
        }
    };
    if !valid || authorization.expires_at <= authorization.created_at {
        return Err(UserRepositoryError::InvalidSchema(
            "Agent challenge 状态字段不一致".to_string(),
        ));
    }
    Ok(authorization)
}

pub(super) fn non_pending_device_authorization_poll(
    authorization: &AgentDeviceAuthorization,
    now: i64,
) -> Result<Option<AgentDeviceAuthorizationPoll>> {
    if authorization.expires_at <= now {
        return Ok(Some(AgentDeviceAuthorizationPoll::Expired));
    }
    let result = match authorization.status {
        AgentDeviceAuthorizationStatus::Pending => return Ok(None),
        AgentDeviceAuthorizationStatus::Authorized => {
            let account_id = authorization.authorized_account_id.clone().ok_or_else(|| {
                UserRepositoryError::InvalidSchema("已授权的 Agent challenge 缺少账号".to_string())
            })?;
            let account_auth_version = authorization.authorized_auth_version.ok_or_else(|| {
                UserRepositoryError::InvalidSchema(
                    "已授权的 Agent challenge 缺少账号版本".to_string(),
                )
            })?;
            AgentDeviceAuthorizationPoll::Authorized {
                account_id,
                account_auth_version,
            }
        }
        AgentDeviceAuthorizationStatus::Denied => AgentDeviceAuthorizationPoll::Denied,
        AgentDeviceAuthorizationStatus::Consumed => AgentDeviceAuthorizationPoll::Consumed,
    };
    Ok(Some(result))
}
