use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(windows)]
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use protocol::RsaKeyPair;
use reqwest::{redirect::Policy, Client, ClientBuilder, Response, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::Manager;
use tempfile::Builder;
use tracing::{info, instrument, warn};
use url::Url;
#[cfg(windows)]
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use zeroize::Zeroizing;

use crate::models::{
    AgentAuthAccount, AgentAuthAccountStatus, AgentProxyEntry, AgentProxyEntrySelection,
};

const CREDENTIALS_DIR: &str = "credentials";
pub const PERSISTED_AGENT_LOGIN_FILE: &str = "agent-login.json";
const PERSISTED_AGENT_LOGIN_VERSION: u8 = 2;
const MAX_PERSISTED_AGENT_LOGIN_BYTES: u64 = 2 * 1024 * 1024;
const MAX_NORMAL_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_PRIVATE_KEY_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_DEVICE_AUTHORIZATION_SECONDS: i64 = 60 * 60;
const MAX_DEVICE_POLL_SECONDS: u32 = 120;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub struct DownloadedCredential {
    pub account: AgentAuthAccount,
    pub proxy_addresses: Vec<String>,
    pub(crate) private_key_pem: Zeroizing<String>,
    pub proxy_registry_url: String,
    pub agent_access_token: Option<AgentAccessToken>,
}

impl DownloadedCredential {
    pub fn has_validated_private_key(&self) -> bool {
        !self.private_key_pem.is_empty()
    }
}

#[derive(Clone)]
pub struct AgentAccessToken {
    pub(crate) value: Zeroizing<String>,
    pub expires_at: i64,
    pub refresh_after_seconds: u64,
}

impl AgentAccessToken {
    pub fn matches_value(&self, expected: &str) -> bool {
        self.value.as_str() == expected
    }
}

pub struct PersistedAgentLogin {
    pub account: AgentAuthAccount,
    pub account_status: AgentAuthAccountStatus,
    pub proxy_addresses: Vec<String>,
    pub proxy_assignment_missing: bool,
    pub resume_after_proxy_assignment: bool,
    pub private_key_path: PathBuf,
    pub agent_access_token: Option<AgentAccessToken>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedAgentLoginRecord {
    version: u8,
    account: AgentAuthAccount,
    proxy_addresses: Vec<String>,
    #[serde(default)]
    proxy_assignment_missing: bool,
    #[serde(default)]
    resume_after_proxy_assignment: bool,
    #[serde(default)]
    account_status: AgentAuthAccountStatus,
    #[serde(default)]
    agent_access_token: Option<String>,
    #[serde(default)]
    agent_access_token_expires_at: Option<i64>,
    #[serde(default)]
    refresh_after_seconds: Option<u64>,
}

pub struct StartedDeviceAuthorization {
    pub(crate) device_code: Zeroizing<String>,
    pub user_code: String,
    pub verification_url: Url,
    pub expires_at: i64,
    pub interval_seconds: u32,
    pub proxy_registry_url: String,
}

impl StartedDeviceAuthorization {
    pub fn device_code_matches(&self, expected: &str) -> bool {
        self.device_code.as_str() == expected
    }
}

pub enum DeviceAuthorizationPoll {
    Pending {
        slow_down: bool,
        retry_after_seconds: u32,
    },
    Authorized(Box<DownloadedCredential>),
}

#[derive(Serialize)]
struct LoginPayload<'a> {
    username: &'a str,
    password: &'a str,
}

#[derive(Serialize)]
struct RotateKeyPayload<'a> {
    reason: &'a str,
}

#[derive(Deserialize)]
struct AuthenticationResponse {
    account: AuthenticationAccount,
    csrf_token: String,
    #[serde(rename = "session_expires_at")]
    _session_expires_at: i64,
}

#[derive(Deserialize)]
pub struct AuthenticationAccount {
    pub role: String,
    pub status: String,
    pub linked_username: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub avatar_url: Option<String>,
}

#[derive(Deserialize)]
struct AgentLoginResponse {
    account: AuthenticationAccount,
    profile: AgentDeviceProfile,
    public_key_pem: String,
    private_key_pem: String,
    agent_access_token: String,
    agent_access_token_expires_at: i64,
    refresh_after_seconds: u64,
}

#[derive(Deserialize)]
pub struct MeResponse {
    pub profile: Option<MeProfile>,
    pub key_state: String,
    pending_request: Option<PendingKeyRequest>,
}

#[derive(Deserialize)]
pub struct MeProfile {
    pub username: String,
    pub permissions: Vec<String>,
    pub proxy_addresses: Option<Vec<String>>,
    pub enabled: bool,
    pub key_version: i64,
    pub expires_at: Option<i64>,
}

#[derive(Deserialize)]
struct PendingKeyRequest {
    status: String,
}

#[derive(Deserialize)]
struct PrivateKeyResponse {
    username: String,
    public_key_pem: String,
    private_key_pem: String,
    key_version: i64,
}

#[derive(Serialize)]
struct AgentDeviceAuthorizationStartPayload<'a> {
    platform: &'a str,
    client_name: &'a str,
}

#[derive(Deserialize)]
struct AgentDeviceAuthorizationStartResponse {
    device_code: String,
    user_code: String,
    #[serde(rename = "verification_uri")]
    _verification_uri: String,
    verification_uri_complete: String,
    expires_in: i64,
    interval: u32,
}

#[derive(Serialize)]
struct AgentDeviceTokenPayload<'a> {
    device_code: &'a str,
}

#[derive(Deserialize)]
pub(crate) struct AgentDeviceTokenResponse {
    account: AuthenticationAccount,
    profile: AgentDeviceProfile,
    public_key_pem: String,
    private_key_pem: String,
    #[serde(default)]
    csrf_token: String,
    #[serde(rename = "session_expires_at")]
    #[serde(default)]
    _session_expires_at: Option<i64>,
    agent_access_token: String,
    agent_access_token_expires_at: i64,
    refresh_after_seconds: u64,
}

#[derive(Deserialize)]
pub struct AgentDeviceProfile {
    pub username: String,
    pub permissions: Vec<String>,
    pub proxy_addresses: Option<Vec<String>>,
    #[serde(default)]
    pub proxy_entries: Option<Vec<AgentProxyEntry>>,
    #[serde(default)]
    pub selected_proxy_entry_ids: Option<Vec<String>>,
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    pub key_version: i64,
    pub expires_at: Option<i64>,
}

fn enabled_by_default() -> bool {
    true
}

#[derive(Deserialize)]
struct ErrorEnvelope {
    error: ErrorDetail,
}

#[derive(Deserialize)]
pub struct ErrorDetail {
    pub code: String,
    #[serde(rename = "message")]
    pub _message: String,
}

mod admin_key_requests;
mod credential_store;
mod device_login;
mod http;
mod key_store;
mod password_login;
mod permission_sync;
mod profile_identity;
mod proxy_addresses;
mod server_events;
mod web_handoff;

pub use admin_key_requests::*;
pub use credential_store::*;
pub use device_login::*;
pub use http::*;
pub use key_store::*;
pub use password_login::*;
pub use permission_sync::*;
pub use profile_identity::*;
pub use proxy_addresses::*;
pub use server_events::*;
pub use web_handoff::*;
