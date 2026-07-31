use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AgentAdminKeyRequest {
    pub request_id: String,
    pub username: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub email: Option<String>,
    pub request_message: Option<String>,
    pub kind: String,
    pub requested_at: i64,
    pub proxy_address_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AgentAdminProxyAddress {
    pub proxy_address_id: String,
    pub label: String,
    pub address: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct AgentAdminKeyRequestInbox {
    pub requests: Vec<AgentAdminKeyRequest>,
    pub proxy_addresses: Vec<AgentAdminProxyAddress>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AgentAdminKeyRequestUpdate {
    pub inbox: AgentAdminKeyRequestInbox,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentAdminKeyRequestApproval {
    pub request_id: String,
    pub expires_at: i64,
    pub proxy_address_ids: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentAdminKeyRequestRejection {
    pub request_id: String,
    pub reason: String,
}
