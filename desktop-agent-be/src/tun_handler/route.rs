#[cfg(target_os = "macos")]
use super::dns::SystemDnsServer;
use super::dns::{flush_system_dns_cache, system_dns_servers};
use super::network::parse_cidr_v6;
use crate::error::{AgentError, Result};
use common::BindInterface;
use route_manager::{Route, RouteManager};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

mod cleanup;
mod dns_capture;
pub mod guard;
#[cfg(target_os = "macos")]
pub mod macos_dns;
mod probe;
mod state;

const ROUTE_STATE_VERSION: u8 = 1;
const ROUTE_STATE_FILE_NAME: &str = "tun-routes.json";
#[cfg(target_os = "macos")]
const PF_DNS_ANCHOR: &str = "com.apple/ppaass-ai-tun-dns";

use cleanup::{cleanup_existing_tun_split_routes, delete_recorded_route};
#[cfg(target_os = "macos")]
pub use cleanup::{macos_route_delete_command, should_delete_recorded_route};
use dns_capture::{DnsCaptureRouteContext, install_dns_capture_routes};
pub use dns_capture::{
    dns_capture_route_targets_default_gateway, should_capture_default_gateway_dns_route,
    should_install_dns_capture_host_routes,
};
pub use guard::RouteGuard;
#[cfg(target_os = "macos")]
pub(super) use guard::RouteGuardInstall;
#[cfg(target_os = "macos")]
pub(super) use macos_dns::cleanup_macos_pf_dns_capture_with_token;
#[cfg(target_os = "macos")]
pub use macos_dns::macos_pf_dns_rules;
#[cfg(target_os = "macos")]
use macos_dns::{MacosPfDnsGuard, command_output_message, macos_default_dns_interfaces};
use probe::find_default_route;
#[cfg(target_os = "macos")]
use probe::interface_name_for_index;
#[cfg(target_os = "macos")]
pub use probe::parse_macos_route_get_next_hop;
#[cfg(not(target_os = "macos"))]
use probe::route_next_hop;
pub use probe::{
    ProxyRoute, detect_default_route_interface, detect_proxy_route,
    resolve_proxy_endpoints_checked, resolve_proxy_ips_checked,
};
pub(super) use state::cleanup_stale_routes;
#[cfg(target_os = "macos")]
pub(super) use state::cleanup_stale_routes_checked;
use state::is_unspecified_gateway;
#[cfg(target_os = "macos")]
use state::now_unix_secs;
pub use state::{RouteKind, RouteLease, RouteRecord, RouteState};

pub(super) fn refresh_macos_scoped_default_bypass() {
    guard::refresh_macos_scoped_default_bypass();
}
