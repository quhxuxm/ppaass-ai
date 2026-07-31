use serde::{Deserialize, Serialize};

use super::DEFAULT_ACCESS_LOG_RETENTION_DAYS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessProtocol {
    Tcp,
    Udp,
}

impl AccessProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAccessRecord {
    pub username: String,
    pub protocol: AccessProtocol,
    pub target_host: String,
    pub target_port: u16,
    pub accessed_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessRecord {
    pub record_id: i64,
    pub username: String,
    pub protocol: AccessProtocol,
    pub target_host: String,
    pub target_port: u16,
    pub access_count: u64,
    pub accessed_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessLogSettings {
    pub retention_days: u16,
}

impl Default for AccessLogSettings {
    fn default() -> Self {
        Self {
            retention_days: DEFAULT_ACCESS_LOG_RETENTION_DAYS,
        }
    }
}
