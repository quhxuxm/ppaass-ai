use serde::{Deserialize, Serialize};

mod admin_key_requests;
pub(crate) use admin_key_requests::*;

pub(crate) const AGENT_PACKET_CAPTURE_PERMISSION: &str = "agent.packet_capture";
pub(crate) const AGENT_EGRESS_EDIT_PERMISSION: &str = "agent.egress.edit";
pub(crate) const AGENT_RUNTIME_THREADS_EDIT_PERMISSION: &str = "agent.runtime_threads.edit";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AgentLoginRequest {
    pub(crate) username: String,
    pub(crate) password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AgentKeyRotationRequest {
    pub(crate) password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct AgentAuthAccount {
    pub(crate) username: String,
    #[serde(default = "default_agent_account_role")]
    pub(crate) role: String,
    #[serde(default = "default_agent_account_permissions")]
    pub(crate) permissions: Vec<String>,
    pub(crate) key_version: i64,
    pub(crate) expires_at: Option<i64>,
}

fn default_agent_account_role() -> String {
    "user".to_string()
}

fn default_agent_account_permissions() -> Vec<String> {
    vec!["key.rotate".to_string()]
}

impl AgentAuthAccount {
    pub(crate) fn unverified_cache_projection(self) -> Self {
        Self {
            role: "user".to_string(),
            permissions: Vec::new(),
            ..self
        }
    }

    pub(crate) fn has_permission(&self, permission: &str) -> bool {
        self.role == "admin"
            || self
                .permissions
                .iter()
                .any(|candidate| candidate == permission)
    }

    pub(crate) fn require_permission(&self, permission: &str) -> Result<(), String> {
        self.has_permission(permission)
            .then_some(())
            .ok_or_else(|| format!("当前账号缺少权限：{permission}"))
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AgentAuthAccountStatus {
    #[default]
    Active,
    Expired,
    Disabled,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AgentAuthState {
    pub(crate) authenticated: bool,
    pub(crate) account: Option<AgentAuthAccount>,
    pub(crate) account_status: Option<AgentAuthAccountStatus>,
    pub(crate) permission_sync_error: Option<String>,
    pub(crate) config: Option<LoadedAgentConfig>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AgentDeviceLoginProgress {
    pub(crate) status: String,
    pub(crate) user_code: String,
    pub(crate) expires_at: i64,
    pub(crate) retry_after_seconds: u32,
    pub(crate) auth_state: Option<AgentAuthState>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct LoadedAgentConfig {
    pub(crate) path: String,
    pub(crate) raw: String,
    pub(crate) summary: AgentConfigSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AgentState {
    pub(crate) running: bool,
    pub(crate) managed: bool,
    pub(crate) pid: Option<u32>,
    pub(crate) config_path: Option<String>,
    pub(crate) binary_path: Option<String>,
    pub(crate) logs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PacketCaptureRuntimeStatus {
    pub(crate) available: bool,
    pub(crate) enabled: bool,
    pub(crate) file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub(crate) struct AgentConfigSummary {
    pub(crate) listen_addr: String,
    #[serde(default, skip_serializing)]
    pub(crate) username: String,
    #[serde(default, skip_serializing)]
    pub(crate) private_key_path: String,
    pub(crate) transport_mode: String,
    pub(crate) udp_session_pool_size: usize,
    pub(crate) connect_timeout_secs: u64,
    pub(crate) compression_mode: String,
    pub(crate) log_level: String,
    pub(crate) log_dir: Option<String>,
    pub(crate) log_file: String,
    pub(crate) runtime_threads: Option<usize>,
    pub(crate) effective_runtime_threads: usize,
    pub(crate) udp_yamux_sessions: usize,
    pub(crate) udp_yamux_max_streams_per_session: usize,
    pub(crate) udp_yamux_open_stream_timeout_secs: u64,
    pub(crate) udp_yamux_keepalive_interval_secs: u64,
    pub(crate) udp_yamux_connection_write_timeout_secs: u64,
    pub(crate) udp_yamux_stream_window_size_kb: usize,
    pub(crate) tun_enabled: bool,
    pub(crate) tun_name: String,
    pub(crate) tun_ipv4: String,
    pub(crate) tun_mtu: u64,
    pub(crate) tun_proxy_udp: bool,
    pub(crate) tun_proxy_dns: bool,
    pub(crate) tun_quic_policy: String,
    pub(crate) tun_packet_capture_file: String,
    pub(crate) direct_mode: String,
    pub(crate) direct_rules: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ConnectivityReport {
    pub(crate) listen_addr: String,
    pub(crate) tun_enabled: bool,
    pub(crate) tun_name: String,
    pub(crate) tun_ready: bool,
    pub(crate) tun_status: String,
    pub(crate) agent_reachable: bool,
    pub(crate) generated_at_ms: u128,
    pub(crate) results: Vec<ConnectivityCheck>,
    pub(crate) tun_results: Vec<ConnectivityCheck>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ConnectivityCheck {
    pub(crate) target: String,
    pub(crate) protocol: String,
    pub(crate) url: String,
    pub(crate) proxy_url: String,
    pub(crate) success: bool,
    pub(crate) http_code: Option<u16>,
    pub(crate) duration_ms: u128,
    pub(crate) error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct NetworkTrafficSnapshot {
    pub(crate) sampled_at_ms: u128,
    pub(crate) total_received_bytes: u64,
    pub(crate) total_transmitted_bytes: u64,
    pub(crate) interfaces: Vec<NetworkInterfaceTraffic>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct NetworkInterfaceTraffic {
    pub(crate) name: String,
    pub(crate) received_bytes: u64,
    pub(crate) transmitted_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
#[cfg(windows)]
pub(crate) enum ServiceRequest {
    Start { config_path: String },
    Stop,
    State,
    Traffic,
    DnsRecords,
    SetLogLevel { log_level: String },
    PacketCaptureStatus,
    SetPacketCapture { enabled: bool },
    ClearPacketCapture { config_path: Option<String> },
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg(windows)]
pub(crate) struct ServiceResponse {
    pub(crate) ok: bool,
    pub(crate) state: Option<AgentState>,
    pub(crate) traffic: Option<NetworkTrafficSnapshot>,
    pub(crate) dns_records: Option<Vec<desktop_agent_be::telemetry::DnsResolutionRecord>>,
    pub(crate) packet_capture: Option<PacketCaptureRuntimeStatus>,
    #[serde(default)]
    pub(crate) auth_status: Option<VerifiedProxyAuthStatus>,
    pub(crate) error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg(windows)]
pub(crate) struct VerifiedProxyAuthStatus {
    pub(crate) username: String,
    pub(crate) status: AgentAuthAccountStatus,
}

#[cfg(test)]
mod tests {
    use super::{
        AgentAdminKeyRequestApproval, AgentAdminKeyRequestRejection, AgentAuthAccount,
        AgentAuthAccountStatus, AgentAuthState, AgentDeviceLoginProgress, AgentKeyRotationRequest,
        AgentLoginRequest, AGENT_PACKET_CAPTURE_PERMISSION,
    };

    #[test]
    fn agent_login_request_rejects_frontend_endpoint_override() {
        let accepted = serde_json::from_value::<AgentLoginRequest>(serde_json::json!({
            "username": "alice",
            "password": "password"
        }));
        assert!(accepted.is_ok());

        let rejected = serde_json::from_value::<AgentLoginRequest>(serde_json::json!({
            "username": "alice",
            "password": "password",
            "proxyWebUrl": "https://attacker.example.com"
        }));
        assert!(rejected.is_err());
    }

    #[test]
    fn key_rotation_request_only_accepts_a_password() {
        let accepted = serde_json::from_value::<AgentKeyRotationRequest>(serde_json::json!({
            "password": "password"
        }));
        assert!(accepted.is_ok());

        let rejected = serde_json::from_value::<AgentKeyRotationRequest>(serde_json::json!({
            "password": "password",
            "username": "attacker",
            "proxyWebUrl": "https://attacker.example.com"
        }));
        assert!(rejected.is_err());
    }

    #[test]
    fn admin_key_request_commands_reject_unknown_or_missing_fields() {
        let approval = serde_json::json!({
            "requestId": "kreq_1",
            "expiresAt": 4_000_000_000_i64,
            "proxyAddressIds": ["pxy_1"]
        });
        assert!(serde_json::from_value::<AgentAdminKeyRequestApproval>(approval.clone()).is_ok());
        let mut unexpected = approval;
        unexpected["agentAccessToken"] = serde_json::json!("must-stay-in-rust");
        assert!(serde_json::from_value::<AgentAdminKeyRequestApproval>(unexpected).is_err());
        assert!(serde_json::from_value::<AgentAdminKeyRequestRejection>(
            serde_json::json!({"requestId": "kreq_1"})
        )
        .is_ok());
        assert!(serde_json::from_value::<AgentAdminKeyRequestRejection>(
            serde_json::json!({"requestId": "kreq_1", "username": "alice"})
        )
        .is_err());
    }

    #[test]
    fn legacy_persisted_account_gets_safe_role_and_permission_defaults() {
        let account = serde_json::from_value::<AgentAuthAccount>(serde_json::json!({
            "username": "alice",
            "key_version": 7,
            "expires_at": null
        }))
        .unwrap();

        assert_eq!(account.role, "user");
        assert_eq!(account.permissions, ["key.rotate"]);
    }

    #[test]
    fn agent_permissions_are_fail_closed_for_users_and_implicit_for_admins() {
        let mut user = AgentAuthAccount {
            username: "alice".to_string(),
            role: "user".to_string(),
            permissions: Vec::new(),
            key_version: 1,
            expires_at: None,
        };
        assert!(user
            .require_permission(AGENT_PACKET_CAPTURE_PERMISSION)
            .is_err());
        user.permissions
            .push(AGENT_PACKET_CAPTURE_PERMISSION.to_string());
        assert!(user
            .require_permission(AGENT_PACKET_CAPTURE_PERMISSION)
            .is_ok());

        user.role = "admin".to_string();
        user.permissions.clear();
        assert!(user
            .require_permission(AGENT_PACKET_CAPTURE_PERMISSION)
            .is_ok());
    }

    #[test]
    fn auth_state_does_not_serialize_control_plane_endpoint() {
        let state = AgentAuthState {
            authenticated: true,
            account: Some(AgentAuthAccount {
                username: "alice".to_string(),
                role: "user".to_string(),
                permissions: vec!["key.rotate".to_string()],
                key_version: 1,
                expires_at: Some(1_800_000_000),
            }),
            account_status: Some(AgentAuthAccountStatus::Active),
            permission_sync_error: None,
            config: None,
        };

        let serialized = serde_json::to_string(&state).unwrap();
        assert!(!serialized.contains("proxy_web"));
        assert!(!serialized.contains("attacker.example.com"));
    }

    #[test]
    fn device_login_progress_never_serializes_device_or_private_credentials() {
        let progress = AgentDeviceLoginProgress {
            status: "authorization_pending".to_string(),
            user_code: "ABCD-EFGH-JKMN".to_string(),
            expires_at: 1_800_000_000,
            retry_after_seconds: 5,
            auth_state: None,
        };

        let serialized = serde_json::to_string(&progress).unwrap();
        assert!(serialized.contains("ABCD-EFGH-JKMN"));
        for secret_field in [
            "device_code",
            "private_key",
            "proxy_web",
            "verification_uri",
        ] {
            assert!(!serialized.contains(secret_field));
        }
    }
}
