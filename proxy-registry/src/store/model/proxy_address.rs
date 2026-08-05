use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyAddress {
    pub proxy_address_id: String,
    pub label: String,
    pub address: String,
    pub enabled: bool,
    pub created_at: i64,
    pub updated_at: i64,
    pub entry_id: Option<String>,
    pub entry_version: Option<String>,
    pub entry_first_registered_at: Option<i64>,
    pub entry_last_heartbeat_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewProxyAddress {
    pub proxy_address_id: String,
    pub label: String,
    pub address: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProxyAddressUpdate {
    pub label: Option<String>,
    pub address: Option<String>,
    pub enabled: Option<bool>,
    /// 修改服务器启用状态的管理员。
    pub changed_by: Option<super::AccountActor>,
    pub audit_reason: Option<String>,
}

impl ProxyAddressUpdate {
    pub fn is_empty(&self) -> bool {
        self.label.is_none() && self.address.is_none() && self.enabled.is_none()
    }
}
