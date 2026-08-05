use protocol::RsaKeyPair;
use rsa::traits::PublicKeyParts;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const MAX_USERNAME_BYTES: usize = 128;
pub const MAX_PUBLIC_KEY_PEM_BYTES: usize = 16 * 1024;
pub const MAX_PERMISSIONS: usize = 32;
pub const MAX_PERMISSION_CODE_BYTES: usize = 64;
pub const MAX_KEY_REQUEST_MESSAGE_CHARS: usize = 500;
pub const MAX_KEY_REQUEST_REJECTION_REASON_CHARS: usize = 500;
pub const MAX_AUDIT_REASON_CHARS: usize = 500;
pub const MAX_PROXY_ADDRESS_BYTES: usize = 512;
pub const MAX_PROXY_ADDRESS_LABEL_BYTES: usize = 128;
pub const MAX_PROXY_ADDRESSES_PER_ACCOUNT: usize = 32;
const MIN_RSA_BITS: usize = 2048;

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("用户名不能为空")]
    EmptyUsername,

    #[error("用户名不能超过 {MAX_USERNAME_BYTES} 字节")]
    UsernameTooLong,

    #[error("用户名包含非法字符")]
    InvalidUsername,

    #[error("RSA 公钥不能为空")]
    EmptyPublicKey,

    #[error("RSA 公钥不能超过 {MAX_PUBLIC_KEY_PEM_BYTES} 字节")]
    PublicKeyTooLong,

    #[error("RSA 公钥格式无效：{0}")]
    InvalidPublicKey(String),

    #[error("RSA 公钥强度不足，至少需要 {MIN_RSA_BITS} 位")]
    WeakPublicKey,

    #[error("至少提供一个需要修改的用户字段")]
    EmptyUpdate,

    #[error("权限项不能超过 {MAX_PERMISSIONS} 个")]
    TooManyPermissions,

    #[error("权限 code 不能为空")]
    EmptyPermission,

    #[error("权限 code 不能超过 {MAX_PERMISSION_CODE_BYTES} 字节：{0}")]
    PermissionTooLong(String),

    #[error("权限 code 只能包含 ASCII 小写字母、数字、点、下划线或连字符：{0}")]
    InvalidPermission(String),

    #[error("密钥申请留言不能超过 {MAX_KEY_REQUEST_MESSAGE_CHARS} 个字符")]
    KeyRequestMessageTooLong,

    #[error("密钥申请留言包含不允许的控制字符")]
    InvalidKeyRequestMessage,

    #[error("密钥申请拒绝理由不能超过 {MAX_KEY_REQUEST_REJECTION_REASON_CHARS} 个字符")]
    KeyRequestRejectionReasonTooLong,

    #[error("密钥申请拒绝理由包含不允许的控制字符")]
    InvalidKeyRequestRejectionReason,

    #[error("操作原因不能为空")]
    EmptyAuditReason,

    #[error("操作原因不能超过 {MAX_AUDIT_REASON_CHARS} 个字符")]
    AuditReasonTooLong,

    #[error("操作原因包含不允许的控制字符")]
    InvalidAuditReason,

    #[error("Proxy 地址 ID 无效")]
    InvalidProxyAddressId,

    #[error("Proxy 地址名称必须为 1..={MAX_PROXY_ADDRESS_LABEL_BYTES} 字节且不能包含控制字符")]
    InvalidProxyAddressLabel,

    #[error("Proxy 地址必须为 hostname:port、IPv4:port 或 [IPv6]:port，不能包含 URL、路径或空白")]
    InvalidProxyAddress,

    #[error("每个账号必须分配 1..={MAX_PROXY_ADDRESSES_PER_ACCOUNT} 个 Proxy 地址")]
    InvalidProxyAddressCount,

    #[error("Proxy 地址分配不能包含重复 ID")]
    DuplicateProxyAddressId,

    #[error("账号字段无效：{0}")]
    InvalidAccountField(String),

    #[error("用户 {username} 的 expires_at 不能为空；不需要过期时间时请删除该字段")]
    EmptyExpiresAt { username: String },

    #[error("用户 {username} 的 expires_at 格式无效：{value}，请使用 RFC3339 或 Unix 秒级时间戳")]
    InvalidExpiresAt { username: String, value: String },
}

pub fn normalize_username(username: &str) -> std::result::Result<String, ValidationError> {
    let username = username.trim();
    if username.is_empty() {
        return Err(ValidationError::EmptyUsername);
    }
    if username.len() > MAX_USERNAME_BYTES {
        return Err(ValidationError::UsernameTooLong);
    }
    if username.contains(['/', '\\', ':', '*', '?', '"', '<', '>', '|'])
        || username.contains("..")
        || username.chars().any(char::is_control)
    {
        return Err(ValidationError::InvalidUsername);
    }
    Ok(username.to_string())
}

pub fn normalize_audit_reason(reason: &str) -> std::result::Result<String, ValidationError> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(ValidationError::EmptyAuditReason);
    }
    if reason.chars().count() > MAX_AUDIT_REASON_CHARS {
        return Err(ValidationError::AuditReasonTooLong);
    }
    if reason
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(ValidationError::InvalidAuditReason);
    }
    Ok(reason.to_string())
}

pub fn normalize_public_key_pem(
    public_key_pem: &str,
) -> std::result::Result<String, ValidationError> {
    let public_key_pem = public_key_pem.trim();
    if public_key_pem.is_empty() {
        return Err(ValidationError::EmptyPublicKey);
    }
    if public_key_pem.len() > MAX_PUBLIC_KEY_PEM_BYTES {
        return Err(ValidationError::PublicKeyTooLong);
    }

    let public_key = RsaKeyPair::from_public_key_pem(public_key_pem)
        .map_err(|error| ValidationError::InvalidPublicKey(error.to_string()))?;
    if public_key.size() * 8 < MIN_RSA_BITS {
        return Err(ValidationError::WeakPublicKey);
    }

    Ok(public_key_pem.to_string())
}

pub fn parse_expires_at(
    username: &str,
    expires_at: &str,
) -> std::result::Result<i64, ValidationError> {
    let expires_at = expires_at.trim();
    if expires_at.is_empty() {
        return Err(ValidationError::EmptyExpiresAt {
            username: username.to_string(),
        });
    }

    if let Ok(timestamp) = expires_at.parse::<i64>() {
        return Ok(timestamp);
    }

    OffsetDateTime::parse(expires_at, &Rfc3339)
        .map(|datetime| datetime.unix_timestamp())
        .map_err(|_| ValidationError::InvalidExpiresAt {
            username: username.to_string(),
            value: expires_at.to_string(),
        })
}

pub fn validate_user(
    username: &str,
    public_key_pem: &str,
) -> std::result::Result<(String, String), ValidationError> {
    Ok((
        normalize_username(username)?,
        normalize_public_key_pem(public_key_pem)?,
    ))
}

/// 校验权限 code，并返回排序、去重后的稳定表示。
pub fn normalize_permissions(
    permissions: &[String],
) -> std::result::Result<Vec<String>, ValidationError> {
    if permissions.len() > MAX_PERMISSIONS {
        return Err(ValidationError::TooManyPermissions);
    }

    let mut normalized = Vec::with_capacity(permissions.len());
    for permission in permissions {
        if permission.is_empty() {
            return Err(ValidationError::EmptyPermission);
        }
        if permission.len() > MAX_PERMISSION_CODE_BYTES {
            return Err(ValidationError::PermissionTooLong(permission.clone()));
        }
        if !permission.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        }) {
            return Err(ValidationError::InvalidPermission(permission.clone()));
        }
        normalized.push(permission.clone());
    }
    normalized.sort_unstable();
    normalized.dedup();
    Ok(normalized)
}

pub fn normalize_proxy_address_id(
    proxy_address_id: &str,
) -> std::result::Result<String, ValidationError> {
    let value = proxy_address_id.trim();
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ValidationError::InvalidProxyAddressId);
    }
    Ok(value.to_string())
}

pub fn normalize_proxy_address_label(label: &str) -> std::result::Result<String, ValidationError> {
    let label = label.trim();
    if label.is_empty()
        || label.len() > MAX_PROXY_ADDRESS_LABEL_BYTES
        || label.chars().any(char::is_control)
    {
        return Err(ValidationError::InvalidProxyAddressLabel);
    }
    Ok(label.to_string())
}

pub fn normalize_proxy_address(address: &str) -> std::result::Result<String, ValidationError> {
    use std::{net::SocketAddr, str::FromStr};

    if address.is_empty()
        || address.len() > MAX_PROXY_ADDRESS_BYTES
        || address.chars().any(char::is_whitespace)
        || address.contains(['/', '\\', '?', '#', '@'])
        || address.contains("://")
    {
        return Err(ValidationError::InvalidProxyAddress);
    }
    if let Ok(socket_address) = SocketAddr::from_str(address) {
        if socket_address.port() == 0 {
            return Err(ValidationError::InvalidProxyAddress);
        }
        return Ok(socket_address.to_string());
    }

    let (host, port_text) = address
        .rsplit_once(':')
        .ok_or(ValidationError::InvalidProxyAddress)?;
    let port = port_text
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(ValidationError::InvalidProxyAddress)?;
    if host.is_empty() || host.len() > 253 || host.contains(':') || !host.is_ascii() {
        return Err(ValidationError::InvalidProxyAddress);
    }
    if !host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
    }) {
        return Err(ValidationError::InvalidProxyAddress);
    }
    Ok(format!("{}:{port}", host.to_ascii_lowercase()))
}

pub fn normalize_proxy_address_ids(
    proxy_address_ids: &[String],
) -> std::result::Result<Vec<String>, ValidationError> {
    if proxy_address_ids.is_empty() || proxy_address_ids.len() > MAX_PROXY_ADDRESSES_PER_ACCOUNT {
        return Err(ValidationError::InvalidProxyAddressCount);
    }
    let mut normalized = proxy_address_ids
        .iter()
        .map(|value| normalize_proxy_address_id(value))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    normalized.sort_unstable();
    let original_len = normalized.len();
    normalized.dedup();
    if normalized.len() != original_len {
        return Err(ValidationError::DuplicateProxyAddressId);
    }
    Ok(normalized)
}

/// 规范化用户给管理员的密钥申请留言。
///
/// 换行和制表符属于正常的文本排版；其余控制字符会被拒绝。仅含空白的留言
/// 归一化为 `None`，让所有 DAO 实现共享相同语义。
pub fn normalize_key_request_message(
    message: Option<String>,
) -> std::result::Result<Option<String>, ValidationError> {
    let Some(message) = message else {
        return Ok(None);
    };
    let message = message.trim();
    if message.is_empty() {
        return Ok(None);
    }
    if message.chars().count() > MAX_KEY_REQUEST_MESSAGE_CHARS {
        return Err(ValidationError::KeyRequestMessageTooLong);
    }
    if message
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(ValidationError::InvalidKeyRequestMessage);
    }
    Ok(Some(message.to_string()))
}

/// 规范化管理员提供给申请人的拒绝理由。
pub fn normalize_key_request_rejection_reason(
    reason: Option<String>,
) -> std::result::Result<Option<String>, ValidationError> {
    let Some(reason) = reason else {
        return Ok(None);
    };
    let reason = reason.trim();
    if reason.is_empty() {
        return Ok(None);
    }
    if reason.chars().count() > MAX_KEY_REQUEST_REJECTION_REASON_CHARS {
        return Err(ValidationError::KeyRequestRejectionReasonTooLong);
    }
    if reason
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(ValidationError::InvalidKeyRequestRejectionReason);
    }
    Ok(Some(reason.to_string()))
}
