use serde::{Deserialize, Serialize};

pub const PROXY_CONNECT_TCP_PERMISSION: &str = "proxy.connect.tcp";
pub const PROXY_CONNECT_UDP_PERMISSION: &str = "proxy.connect.udp";
pub const PRIVATE_KEY_READ_PERMISSION: &str = "key.private.read";
pub const KEY_ROTATE_PERMISSION: &str = "key.rotate";
pub const AGENT_PACKET_CAPTURE_PERMISSION: &str = "agent.packet_capture";
pub const AGENT_EGRESS_EDIT_PERMISSION: &str = "agent.egress.edit";
pub const AGENT_RUNTIME_THREADS_EDIT_PERMISSION: &str = "agent.runtime_threads.edit";
pub const DEPRECATED_AGENT_CONFIG_VIEW_PERMISSION: &str = "agent.config.view";

pub fn default_proxy_permissions() -> Vec<String> {
    vec![
        PROXY_CONNECT_TCP_PERMISSION.to_string(),
        PROXY_CONNECT_UDP_PERMISSION.to_string(),
    ]
}

pub const DEFAULT_ACCESS_LOG_RETENTION_DAYS: u16 = 7;
pub const MIN_ACCESS_LOG_RETENTION_DAYS: u16 = 1;
pub const MAX_ACCESS_LOG_RETENTION_DAYS: u16 = 365;
pub const MAX_ACCESS_LOG_QUERY_LIMIT: u32 = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserOrigin {
    Local,
    Google,
    Wechat,
    Admin,
    Legacy,
}

impl UserOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Google => "google",
            Self::Wechat => "wechat",
            Self::Admin => "admin",
            Self::Legacy => "legacy",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "local" => Some(Self::Local),
            "google" => Some(Self::Google),
            "wechat" => Some(Self::Wechat),
            "admin" => Some(Self::Admin),
            "legacy" => Some(Self::Legacy),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserRecord {
    pub username: String,
    pub public_key_pem: String,
    pub permissions: Vec<String>,
    pub enabled: bool,
    pub origin: UserOrigin,
    pub key_version: i64,
    pub expires_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewUser {
    pub username: String,
    pub public_key_pem: String,
    pub permissions: Vec<String>,
    pub enabled: bool,
    pub origin: UserOrigin,
    pub expires_at: Option<i64>,
}

impl NewUser {
    pub fn new(
        username: impl Into<String>,
        public_key_pem: impl Into<String>,
        origin: UserOrigin,
    ) -> Self {
        Self {
            username: username.into(),
            public_key_pem: public_key_pem.into(),
            permissions: default_proxy_permissions(),
            enabled: true,
            origin,
            expires_at: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UserUpdate {
    pub public_key_pem: Option<String>,
    pub permissions: Option<Vec<String>>,
    pub enabled: Option<bool>,
    /// `None` 表示不修改，`Some(None)` 表示清除过期时间。
    pub expires_at: Option<Option<i64>>,
}

impl UserUpdate {
    pub fn is_empty(&self) -> bool {
        self.public_key_pem.is_none()
            && self.permissions.is_none()
            && self.enabled.is_none()
            && self.expires_at.is_none()
    }
}
