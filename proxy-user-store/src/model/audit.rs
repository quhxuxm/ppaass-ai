use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    KeyRequestApproved,
    KeyRequestRejected,
    KeyRegenerated,
    ProxyAccessEnabled,
    ProxyAccessDisabled,
    WebLoginEnabled,
    WebLoginDisabled,
    ProxyServerEnabled,
    ProxyServerDisabled,
    PermissionsUpdated,
}

impl AuditAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KeyRequestApproved => "key_request_approved",
            Self::KeyRequestRejected => "key_request_rejected",
            Self::KeyRegenerated => "key_regenerated",
            Self::ProxyAccessEnabled => "proxy_access_enabled",
            Self::ProxyAccessDisabled => "proxy_access_disabled",
            Self::WebLoginEnabled => "web_login_enabled",
            Self::WebLoginDisabled => "web_login_disabled",
            Self::ProxyServerEnabled => "proxy_server_enabled",
            Self::ProxyServerDisabled => "proxy_server_disabled",
            Self::PermissionsUpdated => "permissions_updated",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "key_request_approved" => Some(Self::KeyRequestApproved),
            "key_request_rejected" => Some(Self::KeyRequestRejected),
            "key_regenerated" => Some(Self::KeyRegenerated),
            "proxy_access_enabled" => Some(Self::ProxyAccessEnabled),
            "proxy_access_disabled" => Some(Self::ProxyAccessDisabled),
            "web_login_enabled" => Some(Self::WebLoginEnabled),
            "web_login_disabled" => Some(Self::WebLoginDisabled),
            "proxy_server_enabled" => Some(Self::ProxyServerEnabled),
            "proxy_server_disabled" => Some(Self::ProxyServerDisabled),
            "permissions_updated" => Some(Self::PermissionsUpdated),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditTargetKind {
    User,
    ProxyServer,
}

impl AuditTargetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::ProxyServer => "proxy_server",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "user" => Some(Self::User),
            "proxy_server" => Some(Self::ProxyServer),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub audit_id: i64,
    pub action: AuditAction,
    pub actor_account_id: String,
    pub actor_login_name: String,
    pub target_kind: AuditTargetKind,
    pub target_id: String,
    pub target_name: String,
    pub context_id: Option<String>,
    pub reason: Option<String>,
    pub previous_value: Option<String>,
    pub new_value: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NewAuditEvent {
    pub action: AuditAction,
    pub actor_account_id: String,
    pub actor_login_name: String,
    pub target_kind: AuditTargetKind,
    pub target_id: String,
    pub target_name: String,
    pub context_id: Option<String>,
    pub reason: Option<String>,
    pub previous_value: Option<String>,
    pub new_value: Option<String>,
    pub created_at: i64,
}
