use std::fs;
use std::path::{Path, PathBuf};
#[cfg(target_os = "windows")]
use std::process::Command;
#[cfg(target_os = "windows")]
use std::process::Stdio;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use common::tun_control::{TUN_HELPER_DNS_STATE_FILE_NAME, TUN_HELPER_ROUTE_STATE_FILE_NAME};
use desktop_agent_be::PacketCaptureController;
use tokio_util::sync::CancellationToken;

use crate::config::{
    load_config_from_path, locate_config_path, make_absolute_path, summarize_config,
    validate_config_candidate_against_trusted_baseline,
};
use crate::logging::UiLogBuffer;
#[cfg(target_os = "macos")]
use crate::macos_helper::ensure_macos_tun_helper_for_config;
#[cfg(windows)]
use crate::models::ServiceRequest;
use crate::models::{AgentState, PacketCaptureRuntimeStatus};
use crate::network::connect_addr;
#[cfg(target_os = "windows")]
use crate::process_util::hide_child_console;
use crate::runtime::{AgentRuntime, EmbeddedAgent};
#[cfg(windows)]
use crate::windows_service::{
    send_service_request, start_agent_via_windows_service, stop_agent_via_windows_service,
    trusted_windows_wintun_path, windows_service_is_running, windows_service_matches_current_exe,
    windows_service_state,
};

#[cfg(windows)]
use windows_sys::Win32::UI::Shell::IsUserAnAdmin;

const AGENT_STOP_TIMEOUT: Duration = Duration::from_secs(6);
const AGENT_STOP_POLL_INTERVAL: Duration = Duration::from_millis(100);

mod capture;
mod lifecycle;
mod paths;
mod shutdown;

pub(crate) use capture::*;
pub(crate) use lifecycle::*;
pub(crate) use paths::*;
pub(crate) use shutdown::*;

#[cfg(test)]
mod tests;
