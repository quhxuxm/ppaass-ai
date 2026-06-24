use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct AgentConfigSummary {
    pub(crate) listen_addr: String,
    pub(crate) proxy_addrs: Vec<String>,
    pub(crate) username: String,
    pub(crate) private_key_path: String,
    pub(crate) tcp_pool_size: usize,
    pub(crate) udp_pool_size: usize,
    pub(crate) connect_timeout_secs: u64,
    pub(crate) tcp_relay_buffer_size_kb: usize,
    pub(crate) compression_mode: String,
    pub(crate) log_level: String,
    pub(crate) log_dir: Option<String>,
    pub(crate) log_file: String,
    pub(crate) runtime_threads: Option<usize>,
    pub(crate) effective_runtime_threads: usize,
    pub(crate) tcp_mode: String,
    pub(crate) udp_mode: String,
    pub(crate) tcp_yamux_sessions: usize,
    pub(crate) udp_yamux_sessions: usize,
    pub(crate) tcp_yamux_max_streams_per_session: usize,
    pub(crate) udp_yamux_max_streams_per_session: usize,
    pub(crate) tcp_yamux_open_stream_timeout_secs: u64,
    pub(crate) udp_yamux_open_stream_timeout_secs: u64,
    pub(crate) tcp_yamux_keepalive_interval_secs: u64,
    pub(crate) udp_yamux_keepalive_interval_secs: u64,
    pub(crate) tcp_yamux_connection_write_timeout_secs: u64,
    pub(crate) udp_yamux_connection_write_timeout_secs: u64,
    pub(crate) tcp_yamux_stream_window_size_kb: usize,
    pub(crate) udp_yamux_stream_window_size_kb: usize,
    pub(crate) tun_enabled: bool,
    pub(crate) tun_name: String,
    pub(crate) tun_ipv4: String,
    pub(crate) tun_mtu: u64,
    pub(crate) tun_proxy_dns: bool,
    pub(crate) tun_quic_policy: String,
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

#[cfg(target_os = "macos")]
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum MacosTunHelperProbeResponse {
    Pong,
    Error { message: String },
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
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg(windows)]
pub(crate) struct ServiceResponse {
    pub(crate) ok: bool,
    pub(crate) state: Option<AgentState>,
    pub(crate) traffic: Option<NetworkTrafficSnapshot>,
    pub(crate) dns_records: Option<Vec<desktop_agent_be::telemetry::DnsResolutionRecord>>,
    pub(crate) error: Option<String>,
}
