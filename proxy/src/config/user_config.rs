use crate::error::{ProxyError, Result};

pub const PERMISSION_PROXY_CONNECT_TCP: &str = "proxy.connect.tcp";
pub const PERMISSION_PROXY_CONNECT_UDP: &str = "proxy.connect.udp";

#[cfg(test)]
fn default_proxy_permissions() -> Vec<String> {
    vec![
        PERMISSION_PROXY_CONNECT_TCP.to_string(),
        PERMISSION_PROXY_CONNECT_UDP.to_string(),
    ]
}

#[derive(Debug, Clone)]
pub struct UserConfig {
    /// SQLite 用户记录中的认证用户名。
    pub username: String,

    /// proxy 用该公钥解开 agent 发来的会话密钥。
    pub public_key_pem: String,

    /// 绝对过期时间；不配置表示永不过期。支持 RFC3339 或 Unix 秒级时间戳。
    pub expires_at: Option<String>,

    /// 允许该用户使用的代理传输能力。
    pub permissions: Vec<String>,

    /// 数据库账号可由管理端停用。
    pub enabled: bool,

    /// SQLite 运行时用户记录的不可回退密钥版本。
    pub key_version: Option<i64>,
}

impl UserConfig {
    pub fn expires_at_unix_timestamp(&self) -> Result<Option<i64>> {
        self.expires_at
            .as_deref()
            .map(|expires_at| parse_expires_at(&self.username, expires_at))
            .transpose()
    }

    pub fn is_expired_at(&self, current_timestamp: i64) -> Result<bool> {
        Ok(self
            .expires_at_unix_timestamp()?
            .is_some_and(|expires_at| current_timestamp >= expires_at))
    }

    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions
            .iter()
            .any(|candidate| candidate == permission)
    }
}

fn parse_expires_at(username: &str, expires_at: &str) -> Result<i64> {
    proxy_user_store::parse_expires_at(username, expires_at)
        .map_err(|error| ProxyError::Configuration(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{UserConfig, default_proxy_permissions};

    fn user_with_expiry(expires_at: Option<&str>) -> UserConfig {
        UserConfig {
            username: "user1".to_string(),
            public_key_pem: "public-key".to_string(),
            expires_at: expires_at.map(str::to_string),
            permissions: default_proxy_permissions(),
            enabled: true,
            key_version: None,
        }
    }

    #[test]
    fn missing_expires_at_never_expires() {
        let user = user_with_expiry(None);

        assert!(!user.is_expired_at(i64::MAX).unwrap());
    }

    #[test]
    fn expires_when_current_time_reaches_configured_time() {
        let user = user_with_expiry(Some("2030-01-01T00:00:00Z"));

        assert!(!user.is_expired_at(1_893_455_999).unwrap());
        assert!(user.is_expired_at(1_893_456_000).unwrap());
    }

    #[test]
    fn rejects_invalid_expires_at() {
        let user = user_with_expiry(Some("2030-01-01 00:00:00"));

        assert!(user.expires_at_unix_timestamp().is_err());
    }
}
