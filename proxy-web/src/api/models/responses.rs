use super::super::*;

#[derive(Debug, Serialize)]
pub(crate) struct HealthResponse {
    pub(crate) status: &'static str,
    pub(crate) version: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct ProvidersResponse {
    pub(crate) local_registration: bool,
}

#[derive(Serialize)]
pub(crate) struct SessionResponse {
    pub(crate) authenticated: bool,
    pub(crate) account: Option<WebAccount>,
    pub(crate) agent_handoff: bool,
    pub(crate) csrf_token: Option<String>,
    pub(crate) expires_at: Option<i64>,
}

#[derive(Serialize)]
pub(crate) struct AuthenticationResponse {
    pub(crate) account: WebAccount,
    pub(crate) csrf_token: String,
    pub(crate) session_expires_at: i64,
}

#[derive(Serialize)]
pub(crate) struct AgentDeviceAuthorizationStartResponse {
    pub(crate) device_code: String,
    pub(crate) user_code: String,
    pub(crate) verification_uri: &'static str,
    pub(crate) verification_uri_complete: String,
    pub(crate) expires_in: i64,
    pub(crate) interval: u32,
}

#[derive(Debug, Serialize)]
pub(crate) struct AgentDeviceAuthorizationInspectionResponse {
    pub(crate) client_name: String,
    pub(crate) platform: String,
    pub(crate) expires_at: i64,
    pub(crate) status: AgentDeviceAuthorizationStatus,
}

#[derive(Debug, Serialize)]
pub(crate) struct AgentDeviceAuthorizationDecisionResponse {
    pub(crate) status: AgentDeviceAuthorizationStatus,
}

#[derive(Serialize)]
pub(crate) struct AgentDeviceTokenResponse {
    pub(crate) account: WebAccount,
    pub(crate) profile: AgentDeviceProfileResponse,
    pub(crate) public_key_pem: String,
    pub(crate) proxy_identity_public_key_pem: Arc<str>,
    #[serde(serialize_with = "serialize_zeroizing_string")]
    pub(crate) private_key_pem: Zeroizing<String>,
    pub(crate) csrf_token: String,
    pub(crate) session_expires_at: i64,
    pub(crate) agent_access_token: String,
    pub(crate) agent_access_token_expires_at: i64,
    pub(crate) refresh_after_seconds: u32,
}

#[derive(Debug, Serialize)]
pub(crate) struct AgentDeviceProfileResponse {
    pub(crate) username: String,
    pub(crate) permissions: Vec<String>,
    pub(crate) proxy_addresses: Vec<String>,
    pub(crate) enabled: bool,
    pub(crate) key_version: i64,
    pub(crate) expires_at: Option<i64>,
}

#[derive(Serialize)]
pub(crate) struct AgentCredentialResponse {
    pub(crate) account: WebAccount,
    pub(crate) profile: AgentDeviceProfileResponse,
    pub(crate) public_key_pem: String,
    pub(crate) proxy_identity_public_key_pem: Arc<str>,
    #[serde(serialize_with = "serialize_zeroizing_string")]
    pub(crate) private_key_pem: Zeroizing<String>,
    pub(crate) agent_access_token: String,
    pub(crate) agent_access_token_expires_at: i64,
    pub(crate) refresh_after_seconds: u32,
}

#[derive(Serialize)]
pub(crate) struct AgentWebSessionHandoffResponse {
    pub(crate) handoff_path: String,
    pub(crate) expires_in: i64,
}

#[derive(Serialize)]
pub(crate) struct AgentProfileSyncResponse {
    pub(crate) account: WebAccount,
    pub(crate) profile: Option<AgentDeviceProfileResponse>,
    pub(crate) key_state: KeyState,
    pub(crate) agent_access_token: String,
    pub(crate) agent_access_token_expires_at: i64,
    pub(crate) refresh_after_seconds: u32,
}

#[derive(Debug, Serialize)]
pub(crate) struct MeResponse {
    pub(crate) account: WebAccount,
    pub(crate) profile: Option<MeProfileResponse>,
    pub(crate) key_state: KeyState,
    pub(crate) pending_request: Option<SelfKeyRequestResponse>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum KeyState {
    Missing,
    Active,
    Expired,
    Disabled,
}

#[derive(Debug, Serialize)]
pub(crate) struct MeProfileResponse {
    pub(crate) username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) public_key_pem: Option<String>,
    pub(crate) permissions: Vec<String>,
    pub(crate) proxy_addresses: Vec<String>,
    pub(crate) enabled: bool,
    pub(crate) origin: UserOrigin,
    pub(crate) key_version: i64,
    pub(crate) expires_at: Option<i64>,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
}

#[derive(Debug, Serialize)]
pub(crate) struct SelfKeyRequestResponse {
    pub(crate) request_id: String,
    pub(crate) request_message: Option<String>,
    pub(crate) kind: KeyRequestKind,
    pub(crate) status: KeyRequestStatus,
    pub(crate) requested_at: i64,
    pub(crate) reviewed_at: Option<i64>,
    pub(crate) approved_expires_at: Option<i64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct MyKeyRequestResponse {
    pub(crate) request: Option<SelfKeyRequestResponse>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminKeyRequestResponse {
    pub(crate) request_id: String,
    pub(crate) account: WebAccount,
    pub(crate) request_message: Option<String>,
    pub(crate) kind: KeyRequestKind,
    pub(crate) status: KeyRequestStatus,
    pub(crate) expected_key_version: Option<i64>,
    pub(crate) reviewer_account_id: Option<String>,
    pub(crate) requested_at: i64,
    pub(crate) reviewed_at: Option<i64>,
    pub(crate) approved_expires_at: Option<i64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminKeyRequestsResponse {
    pub(crate) requests: Vec<AdminKeyRequestResponse>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminKeyRequestDecisionResponse {
    pub(crate) request: AdminKeyRequestResponse,
    pub(crate) user: Option<AdminManagedUserResponse>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AccessRecordsResponse {
    pub(crate) records: Vec<AccessRecordResponse>,
    pub(crate) retention_days: u16,
}

#[derive(Debug, Serialize)]
pub(crate) struct AccessRecordResponse {
    pub(crate) target_host: String,
    pub(crate) target_port: u16,
    pub(crate) protocol: AccessProtocol,
    pub(crate) access_count: u64,
    pub(crate) accessed_at: i64,
}

#[derive(Debug, Serialize)]
pub(crate) struct AccessLogSettingsResponse {
    pub(crate) retention_days: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) purged_records: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ManagedUsersResponse {
    pub(crate) users: Vec<AdminManagedUserResponse>,
}

/// 管理员专用的用户视图。这里故意不复用 `UserRecord`，避免未来给
/// `UserRecord` 增加字段时意外把密钥材料暴露到管理员 API。
#[derive(Debug, Serialize)]
pub(crate) struct AdminManagedUserResponse {
    pub(crate) account: Option<WebAccount>,
    pub(crate) profile: Option<AdminUserProfileResponse>,
    pub(crate) has_private_key: bool,
    pub(crate) providers: Vec<ExternalIdentity>,
    pub(crate) proxy_addresses: Vec<ProxyAddressResponse>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminUserProfileResponse {
    pub(crate) username: String,
    pub(crate) permissions: Vec<String>,
    pub(crate) enabled: bool,
    pub(crate) origin: UserOrigin,
    pub(crate) key_version: i64,
    pub(crate) expires_at: Option<i64>,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
}

#[derive(Debug, Serialize)]
pub(crate) struct ProxyAddressResponse {
    pub(crate) proxy_address_id: String,
    pub(crate) label: String,
    pub(crate) address: String,
    pub(crate) enabled: bool,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
}

#[derive(Debug, Serialize)]
pub(crate) struct ProxyAddressesResponse {
    pub(crate) proxy_addresses: Vec<ProxyAddressResponse>,
}

#[derive(Serialize)]
pub(crate) struct PrivateKeyResponse {
    pub(crate) username: String,
    pub(crate) public_key_pem: String,
    pub(crate) proxy_identity_public_key_pem: Arc<str>,
    #[serde(serialize_with = "serialize_zeroizing_string")]
    pub(crate) private_key_pem: Zeroizing<String>,
    pub(crate) key_version: i64,
}

#[derive(Debug, Serialize)]
pub(crate) struct CreatedManagedUserResponse {
    pub(crate) user: AdminManagedUserResponse,
}

#[derive(Debug, Serialize)]
pub(crate) struct AdminKeyRotationResponse {
    pub(crate) user: AdminManagedUserResponse,
    pub(crate) key_version: i64,
}

impl From<ManagedUser> for AdminManagedUserResponse {
    fn from(user: ManagedUser) -> Self {
        let proxy_addresses = user
            .assigned_proxy_addresses
            .into_iter()
            .map(ProxyAddressResponse::from)
            .collect();
        Self {
            account: user.account,
            profile: user.profile.map(AdminUserProfileResponse::from),
            has_private_key: user.has_private_key,
            providers: user.providers,
            proxy_addresses,
        }
    }
}

impl From<ProxyAddress> for ProxyAddressResponse {
    fn from(address: ProxyAddress) -> Self {
        Self {
            proxy_address_id: address.proxy_address_id,
            label: address.label,
            address: address.address,
            enabled: address.enabled,
            created_at: address.created_at,
            updated_at: address.updated_at,
        }
    }
}

impl From<UserRecord> for AdminUserProfileResponse {
    fn from(profile: UserRecord) -> Self {
        let UserRecord {
            username,
            public_key_pem: _,
            permissions,
            enabled,
            origin,
            key_version,
            expires_at,
            created_at,
            updated_at,
        } = profile;
        Self {
            username,
            permissions,
            enabled,
            origin,
            key_version,
            expires_at,
            created_at,
            updated_at,
        }
    }
}

impl SelfKeyRequestResponse {
    pub(crate) fn from_request(request: KeyGenerationRequest) -> Self {
        Self {
            request_id: request.request_id,
            request_message: request.request_message,
            kind: request.kind,
            status: request.status,
            requested_at: request.requested_at,
            reviewed_at: request.reviewed_at,
            approved_expires_at: request.approved_expires_at,
        }
    }
}

impl From<AccessRecord> for AccessRecordResponse {
    fn from(record: AccessRecord) -> Self {
        Self {
            target_host: record.target_host,
            target_port: record.target_port,
            protocol: record.protocol,
            access_count: record.access_count,
            accessed_at: record.accessed_at,
        }
    }
}
