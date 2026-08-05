use crate::error::{ProxyError, Result};

pub const PERMISSION_PROXY_CONNECT_TCP: &str = "proxy.connect.tcp";
pub const PERMISSION_PROXY_CONNECT_UDP: &str = "proxy.connect.udp";

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
    use time::{OffsetDateTime, format_description::well_known::Rfc3339};

    let expires_at = expires_at.trim();
    if expires_at.is_empty() {
        return Err(ProxyError::Configuration(format!(
            "用户 {username} 的 expires_at 不能为空"
        )));
    }
    if let Ok(timestamp) = expires_at.parse::<i64>() {
        return Ok(timestamp);
    }
    OffsetDateTime::parse(expires_at, &Rfc3339)
        .map(|datetime| datetime.unix_timestamp())
        .map_err(|_| {
            ProxyError::Configuration(format!("用户 {username} 的 expires_at 无效：{expires_at}"))
        })
}
