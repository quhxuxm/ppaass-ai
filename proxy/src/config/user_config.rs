use serde::{Deserialize, Deserializer, Serialize, de};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::error::{ProxyError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    /// 认证用户名，必须与 users.toml 中的表键一致。
    pub username: String,

    /// proxy 用该公钥解开 agent 发来的会话密钥。
    pub public_key_pem: String,

    /// 为空表示不限速；有值时作为 Mbps 级别的软上限观测。
    /// proxy 会继续记录流量并输出告警，但不在新建连接/子流时硬拒绝，
    /// 避免 HLS 视频分片这类短时突发流量被误杀。
    #[serde(default)]
    pub bandwidth_limit_mbps: Option<u64>,

    /// 绝对过期时间；不配置表示永不过期。支持 RFC3339 或 Unix 秒级时间戳。
    #[serde(
        default,
        alias = "expire_at",
        deserialize_with = "deserialize_expires_at"
    )]
    pub expires_at: Option<String>,
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
}

fn parse_expires_at(username: &str, expires_at: &str) -> Result<i64> {
    let expires_at = expires_at.trim();
    if expires_at.is_empty() {
        return Err(ProxyError::Configuration(format!(
            "用户 {username} 的 expires_at 不能为空；不需要过期时间时请删除该字段"
        )));
    }

    if let Ok(timestamp) = expires_at.parse::<i64>() {
        return Ok(timestamp);
    }

    OffsetDateTime::parse(expires_at, &Rfc3339)
        .map(|datetime| datetime.unix_timestamp())
        .map_err(|e| {
            ProxyError::Configuration(format!(
                "用户 {username} 的 expires_at 格式无效：{expires_at}，请使用 RFC3339，例如 2026-12-31T23:59:59Z，或 Unix 秒级时间戳：{e}"
            ))
        })
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
    use super::UserConfig;

    fn user_with_expiry(expires_at: Option<&str>) -> UserConfig {
        UserConfig {
            username: "user1".to_string(),
            public_key_pem: "public-key".to_string(),
            bandwidth_limit_mbps: None,
            expires_at: expires_at.map(str::to_string),
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
}
