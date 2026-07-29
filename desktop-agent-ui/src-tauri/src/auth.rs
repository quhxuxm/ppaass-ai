use std::fs;
use std::io::Write;
use std::net::IpAddr;
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

use protocol::{crypto::validate_rsa_public_key_size, RsaKeyPair};
use reqwest::{redirect::Policy, Client, Response, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::Manager;
use tempfile::Builder;
use tracing::{info, instrument, warn};
use url::Url;
#[cfg(windows)]
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use zeroize::Zeroizing;

use crate::models::{AgentAuthAccount, AgentAuthAccountStatus};

const CREDENTIALS_DIR: &str = "credentials";
const PERSISTED_AGENT_LOGIN_FILE: &str = "agent-login.json";
const PERSISTED_AGENT_LOGIN_VERSION: u8 = 1;
const MAX_PERSISTED_AGENT_LOGIN_BYTES: u64 = 16 * 1024;
const PROXY_IDENTITY_PUBLIC_KEY_FILE: &str = "proxy-identity-public.pem";
const MAX_NORMAL_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_PRIVATE_KEY_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_DEVICE_AUTHORIZATION_SECONDS: i64 = 60 * 60;
const MAX_DEVICE_POLL_SECONDS: u32 = 120;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub(crate) struct DownloadedCredential {
    pub(crate) account: AgentAuthAccount,
    pub(crate) private_key_pem: Zeroizing<String>,
    pub(crate) proxy_identity_public_key_pem: String,
    pub(crate) proxy_web_url: String,
}

#[derive(Debug)]
pub(crate) struct PersistedAgentLogin {
    pub(crate) account: AgentAuthAccount,
    pub(crate) account_status: AgentAuthAccountStatus,
    pub(crate) private_key_path: PathBuf,
    pub(crate) proxy_identity_public_key_path: PathBuf,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedAgentLoginRecord {
    version: u8,
    account: AgentAuthAccount,
    #[serde(default)]
    account_status: AgentAuthAccountStatus,
}

pub(crate) struct StartedDeviceAuthorization {
    pub(crate) device_code: Zeroizing<String>,
    pub(crate) user_code: String,
    pub(crate) verification_url: Url,
    pub(crate) expires_at: i64,
    pub(crate) interval_seconds: u32,
    pub(crate) proxy_web_url: String,
}

pub(crate) enum DeviceAuthorizationPoll {
    Pending {
        slow_down: bool,
        retry_after_seconds: u32,
    },
    Authorized(DownloadedCredential),
}

#[derive(Serialize)]
struct LoginPayload<'a> {
    username: &'a str,
    password: &'a str,
}

#[derive(Deserialize)]
struct AuthenticationResponse {
    account: AuthenticationAccount,
    csrf_token: String,
    #[serde(rename = "session_expires_at")]
    _session_expires_at: i64,
}

#[derive(Deserialize)]
struct AuthenticationAccount {
    role: String,
    status: String,
    linked_username: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct MeResponse {
    profile: Option<MeProfile>,
    key_state: String,
    pending_request: Option<PendingKeyRequest>,
}

#[derive(Deserialize)]
pub(crate) struct MeProfile {
    username: String,
    permissions: Vec<String>,
    enabled: bool,
    key_version: i64,
    expires_at: Option<i64>,
}

#[derive(Deserialize)]
struct PendingKeyRequest {
    status: String,
}

#[derive(Deserialize)]
struct PrivateKeyResponse {
    username: String,
    public_key_pem: String,
    proxy_identity_public_key_pem: String,
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
    proxy_identity_public_key_pem: String,
    private_key_pem: String,
    csrf_token: String,
    #[serde(rename = "session_expires_at")]
    _session_expires_at: i64,
}

#[derive(Deserialize)]
struct AgentDeviceProfile {
    username: String,
    permissions: Vec<String>,
    key_version: i64,
    expires_at: Option<i64>,
}

#[derive(Deserialize)]
struct ErrorEnvelope {
    error: ErrorDetail,
}

#[derive(Deserialize)]
pub(crate) struct ErrorDetail {
    code: String,
    #[serde(rename = "message")]
    _message: String,
}

mod credential_store;
mod device_login;
mod http;
mod key_store;
mod password_login;

pub(crate) use credential_store::*;
pub(crate) use device_login::*;
pub(crate) use http::*;
pub(crate) use key_store::*;
pub(crate) use password_login::*;

#[cfg(test)]
mod tests;
