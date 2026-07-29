use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyAddress {
    pub proxy_address_id: String,
    pub label: String,
    pub address: String,
    pub enabled: bool,
    pub created_at: i64,
    pub updated_at: i64,
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
}

impl ProxyAddressUpdate {
    pub fn is_empty(&self) -> bool {
        self.label.is_none() && self.address.is_none() && self.enabled.is_none()
    }
}
