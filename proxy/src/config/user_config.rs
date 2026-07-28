use crate::error::{ProxyError, Result};
use serde::{Deserialize, Deserializer, Serialize, de};

pub const PERMISSION_PROXY_CONNECT_TCP: &str = "proxy.connect.tcp";
pub const PERMISSION_PROXY_CONNECT_UDP: &str = "proxy.connect.udp";

fn default_proxy_permissions() -> Vec<String> {
    vec![
        PERMISSION_PROXY_CONNECT_TCP.to_string(),
        PERMISSION_PROXY_CONNECT_UDP.to_string(),
    ]
}

const fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    /// 认证用户名，必须与 users.toml 中的表键一致。
    pub username: String,

    /// proxy 用该公钥解开 agent 发来的会话密钥。
    pub public_key_pem: String,

    /// 绝对过期时间；不配置表示永不过期。支持 RFC3339 或 Unix 秒级时间戳。
    #[serde(
        default,
        alias = "expire_at",
        deserialize_with = "deserialize_expires_at"
    )]
    pub expires_at: Option<String>,

    /// 允许该用户使用的代理传输能力。旧 users.toml 未配置时保持 TCP/UDP 全部可用。
    #[serde(default = "default_proxy_permissions")]
    pub permissions: Vec<String>,

    /// 数据库账号可由管理端停用；旧 users.toml 未配置时默认启用。
    #[serde(default = "default_enabled")]
    pub enabled: bool,
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

fn deserialize_expires_at<'de, D>(deserializer: D) -> std::result::Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(value) = Option::<toml::Value>::deserialize(deserializer)? else {
        return Ok(None);
    };

    match value {
        toml::Value::String(expires_at) => Ok(Some(expires_at)),
        toml::Value::Datetime(expires_at) => Ok(Some(expires_at.to_string())),
        toml::Value::Integer(expires_at) => Ok(Some(expires_at.to_string())),
        _ => Err(de::Error::custom(
            "expires_at must be a RFC3339 datetime string or Unix timestamp",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PERMISSION_PROXY_CONNECT_TCP, PERMISSION_PROXY_CONNECT_UDP, UserConfig,
        default_proxy_permissions,
    };

    fn user_with_expiry(expires_at: Option<&str>) -> UserConfig {
        UserConfig {
            username: "user1".to_string(),
            public_key_pem: "public-key".to_string(),
            expires_at: expires_at.map(str::to_string),
            permissions: default_proxy_permissions(),
            enabled: true,
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

    #[test]
    fn parses_toml_datetime_expires_at() {
        let user: UserConfig = toml::from_str(
            r#"
username = "user1"
public_key_pem = "public-key"
expires_at = 2030-01-01T00:00:00Z
"#,
        )
        .unwrap();

        assert_eq!(
            user.expires_at_unix_timestamp().unwrap(),
            Some(1_893_456_000)
        );
    }

    #[test]
    fn parses_unix_timestamp_expires_at() {
        let user: UserConfig = toml::from_str(
            r#"
username = "user1"
public_key_pem = "public-key"
expires_at = 1893456000
"#,
        )
        .unwrap();

        assert_eq!(
            user.expires_at_unix_timestamp().unwrap(),
            Some(1_893_456_000)
        );
    }

    #[test]
    fn legacy_toml_defaults_to_enabled_tcp_and_udp() {
        let user: UserConfig = toml::from_str(
            r#"
username = "user1"
public_key_pem = "public-key"
"#,
        )
        .unwrap();

        assert!(user.enabled);
        assert!(user.has_permission(PERMISSION_PROXY_CONNECT_TCP));
        assert!(user.has_permission(PERMISSION_PROXY_CONNECT_UDP));
    }
}
