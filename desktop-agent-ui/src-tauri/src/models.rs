use serde::{Deserialize, Serialize};

mod admin_key_requests;
pub use admin_key_requests::*;

pub const AGENT_PACKET_CAPTURE_PERMISSION: &str = "agent.packet_capture";
pub const AGENT_EGRESS_EDIT_PERMISSION: &str = "agent.egress.edit";
pub const AGENT_RUNTIME_THREADS_EDIT_PERMISSION: &str = "agent.runtime_threads.edit";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentLoginRequest {
    pub username: String,
    pub(crate) password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentKeyRotationRequest {
    pub(crate) password: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentAuthAccount {
    pub username: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub avatar_url: Option<String>,
    #[serde(default = "default_agent_account_role")]
    pub role: String,
    #[serde(default = "default_agent_account_permissions")]
    pub permissions: Vec<String>,
    pub key_version: i64,
    pub expires_at: Option<i64>,
}

fn default_agent_account_role() -> String {
    "user".to_string()
}

fn default_agent_account_permissions() -> Vec<String> {
    vec!["key.rotate".to_string()]
}

impl AgentAuthAccount {
    pub fn unverified_cache_projection(self) -> Self {
        Self {
            role: "user".to_string(),
            permissions: Vec::new(),
            ..self
        }
    }

    pub fn has_permission(&self, permission: &str) -> bool {
        self.role == "admin"
            || self
                .permissions
                .iter()
                .any(|candidate| candidate == permission)
    }

    pub fn require_permission(&self, permission: &str) -> Result<(), String> {
        self.has_permission(permission)
            .then_some(())
            .ok_or_else(|| format!("当前账号缺少权限：{permission}"))
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentAuthAccountStatus {
    #[default]
    Active,
    Expired,
    Disabled,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentAuthState {
    pub authenticated: bool,
    pub account: Option<AgentAuthAccount>,
    pub account_status: Option<AgentAuthAccountStatus>,
    pub permission_sync_error: Option<String>,
    pub config: Option<LoadedAgentConfig>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentDeviceLoginProgress {
    pub status: String,
    pub user_code: String,
    pub expires_at: i64,
    pub retry_after_seconds: u32,
    pub auth_state: Option<AgentAuthState>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoadedAgentConfig {
    pub path: String,
    pub raw: String,
    pub summary: AgentConfigSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentState {
    pub running: bool,
    pub managed: bool,
    pub pid: Option<u32>,
    pub config_path: Option<String>,
    pub binary_path: Option<String>,
    pub logs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketCaptureRuntimeStatus {
    pub available: bool,
    pub enabled: bool,
    pub file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct AgentConfigSummary {
    pub listen_addr: String,
    #[serde(default, skip_serializing)]
    pub username: String,
    #[serde(default, skip_serializing)]
    pub private_key_path: String,
    pub transport_mode: String,
    pub udp_session_pool_size: usize,
    pub connect_timeout_secs: u64,
    pub compression_mode: String,
    pub log_level: String,
    pub log_dir: Option<String>,
    pub log_file: String,
    pub runtime_threads: Option<usize>,
    pub effective_runtime_threads: usize,
    pub udp_yamux_sessions: usize,
    pub udp_yamux_max_streams_per_session: usize,
    pub udp_yamux_open_stream_timeout_secs: u64,
    pub udp_yamux_keepalive_interval_secs: u64,
    pub udp_yamux_connection_write_timeout_secs: u64,
    pub udp_yamux_stream_window_size_kb: usize,
    pub tun_enabled: bool,
    pub tun_name: String,
    pub tun_ipv4: String,
    pub tun_mtu: u64,
    pub tun_proxy_udp: bool,
    pub tun_proxy_dns: bool,
    pub tun_quic_policy: String,
    pub tun_packet_capture_file: String,
    pub direct_mode: String,
    pub direct_rules: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ConnectivityReport {
    pub listen_addr: String,
    pub tun_enabled: bool,
    pub tun_name: String,
    pub tun_ready: bool,
    pub tun_status: String,
    pub agent_reachable: bool,
    pub generated_at_ms: u128,
    pub results: Vec<ConnectivityCheck>,
    pub tun_results: Vec<ConnectivityCheck>,
}

#[derive(Debug, Serialize)]
pub struct ConnectivityCheck {
    pub target: String,
    pub protocol: String,
    pub url: String,
    pub proxy_url: String,
    pub success: bool,
    pub http_code: Option<u16>,
    pub duration_ms: u128,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkTrafficSnapshot {
    pub sampled_at_ms: u128,
    pub total_received_bytes: u64,
    pub total_transmitted_bytes: u64,
    pub interfaces: Vec<NetworkInterfaceTraffic>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkInterfaceTraffic {
    pub name: String,
    pub received_bytes: u64,
    pub transmitted_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
#[cfg(windows)]
pub enum ServiceRequest {
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
pub struct ServiceResponse {
    pub ok: bool,
    pub state: Option<AgentState>,
    pub traffic: Option<NetworkTrafficSnapshot>,
    pub dns_records: Option<Vec<desktop_agent_be::telemetry::DnsResolutionRecord>>,
    pub packet_capture: Option<PacketCaptureRuntimeStatus>,
    #[serde(default)]
    pub auth_status: Option<VerifiedProxyAuthStatus>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg(windows)]
pub struct VerifiedProxyAuthStatus {
    pub username: String,
    pub status: AgentAuthAccountStatus,
}
