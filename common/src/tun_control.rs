use crate::BindInterface;
use serde::{Deserialize, Serialize};

pub const DEFAULT_TUN_HELPER_SOCKET_PATH: &str = "/var/run/ppaass-ai/tun-helper.sock";
pub const TUN_HELPER_ROUTE_STATE_FILE_NAME: &str = "tun-routes.json";
pub const TUN_HELPER_DNS_STATE_FILE_NAME: &str = "tun-dns.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TunHelperRequest {
    Ping,
    StartTun(TunStartRequest),
    StopTun {
        lease_id: String,
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
