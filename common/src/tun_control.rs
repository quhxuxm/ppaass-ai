use crate::BindInterface;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const DEFAULT_TUN_HELPER_SOCKET_PATH: &str = "/var/run/ppaass-ai/tun-helper.sock";
pub const TUN_HELPER_ROUTE_STATE_FILE_NAME: &str = "tun-routes.json";
pub const TUN_HELPER_DNS_STATE_FILE_NAME: &str = "tun-dns.json";
/// Increment when the installed privileged helper must be upgraded before it
/// can safely serve the current Agent. Version 4 confines privileged route and
/// DNS state to the root-owned helper socket directory instead of trusting
/// caller-provided filesystem paths.
pub const TUN_HELPER_PROTOCOL_VERSION: u32 = 4;

pub fn tun_helper_route_state_path(socket_path: &Path) -> PathBuf {
    tun_helper_state_path(socket_path, TUN_HELPER_ROUTE_STATE_FILE_NAME)
}

pub fn tun_helper_dns_state_path(socket_path: &Path) -> PathBuf {
    tun_helper_state_path(socket_path, TUN_HELPER_DNS_STATE_FILE_NAME)
}

fn tun_helper_state_path(socket_path: &Path, file_name: &str) -> PathBuf {
    socket_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join(file_name)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TunHelperRequest {
    Ping,
    GetHelperInfo,
    StartTun(TunStartRequest),
    StopTun {
        lease_id: String,
        /// State paths remain on the wire for diagnostics. Current helpers
        /// treat durable lease metadata as authoritative and never authorize
        /// cleanup from these caller-controlled hints.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        route_state_file: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dns_state_file: Option<String>,
    },
    CleanupStale {
        route_state_file: Option<String>,
        dns_state_file: Option<String>,
    },
    RefreshMacosScopedDefaultBypass,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunStartRequest {
    pub name: String,
    pub ipv4: String,
    pub ipv6: Option<String>,
    pub mtu: u16,
    pub proxy_addrs: Vec<String>,
    pub proxy_dns: bool,
    pub proxy_bind_interface: Option<BindInterface>,
    pub route_state_file: Option<String>,
    pub dns_state_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TunHelperResponse {
    Pong,
    HelperInfo { protocol_version: u32 },
    TunStarted(TunStartedResponse),
    Ok,
    Error { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunStartedResponse {
    pub lease_id: String,
    pub name: String,
    pub if_index: u32,
}
