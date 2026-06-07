#[cfg(target_os = "macos")]
use super::dns::SystemDnsServer;
use super::dns::{flush_system_dns_cache, system_dns_servers};
use super::network::parse_cidr_v6;
use crate::error::{AgentError, Result};
use common::BindInterface;
use route_manager::{Route, RouteManager};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

mod cleanup;
mod dns_capture;
mod guard;
#[cfg(target_os = "macos")]
mod macos_dns;
mod probe;
mod state;
#[cfg(test)]
mod tests;

const ROUTE_STATE_VERSION: u8 = 1;
const ROUTE_STATE_FILE_NAME: &str = "tun-routes.json";
#[cfg(target_os = "macos")]
const PF_DNS_ANCHOR: &str = "com.apple/ppaass-ai-tun-dns";

use cleanup::{cleanup_existing_tun_split_routes, delete_recorded_route};
#[cfg(all(test, target_os = "macos"))]
use cleanup::{macos_route_delete_command, should_delete_recorded_route};
use dns_capture::should_install_dns_capture_host_routes;
use dns_capture::{DnsCaptureRouteContext, install_dns_capture_routes};
#[cfg(test)]
use dns_capture::{
    dns_capture_route_targets_default_gateway, should_capture_default_gateway_dns_route,
};
pub(super) use guard::RouteGuard;
#[cfg(all(test, target_os = "macos"))]
use macos_dns::macos_pf_dns_rules;
#[cfg(target_os = "macos")]
use macos_dns::{MacosPfDnsGuard, command_output_message, macos_default_dns_interfaces};
#[cfg(target_os = "macos")]
use probe::interface_name_for_index;
#[cfg(all(test, target_os = "macos"))]
use probe::parse_macos_route_get_next_hop;
pub(super) use probe::{
    ProxyRoute, detect_default_route_interface, detect_proxy_route, resolve_proxy_ips,
};
use probe::{find_default_route, route_next_hop};
pub(super) use state::cleanup_stale_routes;
#[cfg(target_os = "macos")]
use state::now_unix_secs;
use state::{RouteKind, RouteLease, RouteRecord, is_unspecified_gateway};

pub(super) fn refresh_macos_scoped_default_bypass() {
    guard::refresh_macos_scoped_default_bypass();
}
