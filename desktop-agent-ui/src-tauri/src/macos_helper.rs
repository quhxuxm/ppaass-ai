#![cfg(target_os = "macos")]

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use common::tun_control::{
    tun_helper_dns_state_path, tun_helper_route_state_path, TunHelperRequest, TunHelperResponse,
    TUN_HELPER_PROTOCOL_VERSION,
};

use crate::config::locate_config_path;
use crate::logging::{normalize_log_level, UiLogBuffer};
use crate::network::probe_tun_ready;
use crate::process_util::current_time_millis;

pub(crate) const TUN_HELPER_SERVICE_ARG: &str = "--tun-helper-service";
const TUN_HELPER_SOCKET_ARG: &str = "--tun-helper-socket";
const TUN_HELPER_ALLOWED_UID_ARG: &str = "--tun-helper-allowed-uid";
const TUN_HELPER_LOG_LEVEL_ARG: &str = "--log-level";
const TUN_HELPER_INSTALL_PATH: &str = "/usr/local/libexec/ppaass-desktop-agent";
const TUN_HELPER_LEGACY_INSTALL_PATH: &str = "/usr/local/libexec/ppaass-tun-helper";
const TUN_HELPER_SOCKET_PATH: &str = "/var/run/ppaass-ai/tun-helper.sock";
const TUN_HELPER_PLIST_ID: &str = "com.ppaass.ai.desktop-agent.tun-helper";
const TUN_HELPER_LEGACY_PLIST_ID: &str = "com.ppaass.ai.tun-helper";
const TUN_HELPER_PLIST_PATH: &str =
    "/Library/LaunchDaemons/com.ppaass.ai.desktop-agent.tun-helper.plist";
const TUN_HELPER_LEGACY_PLIST_PATH: &str = "/Library/LaunchDaemons/com.ppaass.ai.tun-helper.plist";
const TUN_HELPER_LEASE_STATE_SUFFIX: &str = ".leases.json";
const TUN_HELPER_CONTROL_TIMEOUT: Duration = Duration::from_secs(4);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum MacosTunHelperStatus {
    Current,
    Missing,
    Outdated,
    NeedsRestart,
}

#[derive(Debug, Clone)]
pub struct MacosTunHelperStatePaths {
    pub route: PathBuf,
    pub dns: PathBuf,
    pub lease: PathBuf,
}

mod installation;
mod protocol;
mod replacement;
mod service;
mod startup;

pub use installation::*;
pub use protocol::*;
pub use replacement::*;
pub(crate) use service::*;
pub use startup::*;
