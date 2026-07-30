use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tauri::{Emitter, Manager};
use tracing::{info, warn};

use crate::agent::{
    apply_ui_log_level, clear_packet_capture_runtime, get_agent_state_inner,
    packet_capture_runtime_status, resolve_agent_output_path,
    restart_agent_after_managed_config_update, set_packet_capture_runtime_enabled,
    start_agent_command, stop_agent_inner_command,
};
use crate::auth::{
    account_management_page_url, apply_permission_snapshot, approve_agent_admin_key_request,
    authenticate_and_download, authenticate_rotate_and_download, cleanup_old_managed_private_keys,
    destroy_managed_private_key, destroy_managed_proxy_identity_public_key,
    destroy_persisted_agent_login, fetch_agent_admin_key_request_inbox,
    fetch_agent_permission_snapshot, load_persisted_agent_login, open_system_browser,
    persist_agent_login, persist_unassigned_agent_login, poll_device_authorization,
    reject_agent_admin_key_request, request_account_management_handoff, start_device_authorization,
    write_managed_private_key, write_managed_proxy_identity_public_key, DeviceAuthorizationPoll,
    DownloadedCredential,
};
use crate::config::{
    apply_managed_credentials_to_config, clear_managed_credentials_from_config,
    enforce_config_path_for_account, enforce_loaded_config_for_account,
    enforce_managed_config_path_for_account, enforce_managed_identity,
    install_bundled_agent_assets, load_config_from_path, load_default_config,
    loaded_config_from_raw, locate_config_path, make_absolute_path, merge_config_summary,
    prepare_config_for_account, primary_agent_config_path, proxy_web_url_from_config,
    remember_trusted_config_baseline, validate_config_candidate_against_trusted_baseline,
    write_config_file,
};
use crate::diagnostics::run_connectivity_tests_blocking;
#[cfg(target_os = "macos")]
use crate::macos_helper::{
    check_macos_tun_helper_on_startup, run_macos_tun_helper_service_from_args,
    TUN_HELPER_SERVICE_ARG,
};
#[cfg(windows)]
use crate::models::ServiceRequest;
use crate::models::{
    AgentAdminKeyRequestApproval, AgentAdminKeyRequestInbox, AgentAdminKeyRequestRejection,
    AgentAdminKeyRequestUpdate, AgentAuthAccount, AgentAuthAccountStatus, AgentAuthState,
    AgentConfigSummary, AgentDeviceLoginProgress, AgentKeyRotationRequest, AgentLoginRequest,
    AgentState, ConnectivityReport, LoadedAgentConfig, NetworkTrafficSnapshot,
    PacketCaptureRuntimeStatus, AGENT_PACKET_CAPTURE_PERMISSION,
};
use crate::packet_capture::{read_packet_capture, PacketCaptureReport};
use crate::process_util::run_blocking;
use crate::runtime::{
    AgentPermissionTrust, AgentRuntime, AgentSessionCredentials, AuthenticatedAgentSession,
};
use crate::telemetry::{get_dns_resolution_records_inner, get_network_traffic_snapshot_inner};
use crate::tray::restore_main_window;
#[cfg(any(windows, target_os = "macos"))]
use crate::tray::{
    hide_window_to_tray, hide_window_to_tray_after_minimize, setup_system_tray,
    sync_tray_tun_checked,
};
#[cfg(windows)]
use crate::windows_service::{
    activate_windows_service_session, install_and_start_windows_service,
    invalidate_windows_service_session, run_windows_service, send_service_request,
    service_config_root_from_args, windows_service_auth_status, INSTALL_SERVICE_ARG, SERVICE_ARG,
};

mod admin_key_requests;
mod bootstrap;
mod config_commands;
mod login_commands;
mod permission_sync;
mod provisioning;
mod state;
mod telemetry_commands;

pub(crate) use admin_key_requests::*;
pub(crate) use bootstrap::*;
pub(crate) use config_commands::*;
pub(crate) use login_commands::*;
pub(crate) use permission_sync::*;
pub(crate) use provisioning::*;
pub(crate) use state::*;
pub(crate) use telemetry_commands::*;

#[cfg(test)]
mod tests;
