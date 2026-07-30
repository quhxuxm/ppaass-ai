use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct AgentAdminKeyRequest {
    pub(crate) request_id: String,
    pub(crate) username: String,
    pub(crate) display_name: Option<String>,
    pub(crate) avatar_url: Option<String>,
    pub(crate) email: Option<String>,
    pub(crate) request_message: Option<String>,
    pub(crate) kind: String,
    pub(crate) requested_at: i64,
    pub(crate) proxy_address_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct AgentAdminProxyAddress {
    pub(crate) proxy_address_id: String,
    pub(crate) label: String,
    pub(crate) address: String,
    pub(crate) enabled: bool,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub(crate) struct AgentAdminKeyRequestInbox {
    pub(crate) requests: Vec<AgentAdminKeyRequest>,
    pub(crate) proxy_addresses: Vec<AgentAdminProxyAddress>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct AgentAdminKeyRequestUpdate {
    pub(crate) inbox: AgentAdminKeyRequestInbox,
    pub(crate) error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AgentAdminKeyRequestApproval {
    pub(crate) request_id: String,
    pub(crate) expires_at: i64,
    pub(crate) proxy_address_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AgentAdminKeyRequestRejection {
    pub(crate) request_id: String,
    pub(crate) reason: Option<String>,
}
