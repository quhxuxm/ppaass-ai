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
struct MeResponse {
    profile: Option<MeProfile>,
    key_state: String,
    pending_request: Option<PendingKeyRequest>,
}

#[derive(Deserialize)]
struct MeProfile {
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
struct AgentDeviceTokenResponse {
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
struct ErrorDetail {
    code: String,
    #[serde(rename = "message")]
    _message: String,
}

#[instrument(skip_all, fields(username = %username))]
pub(crate) async fn authenticate_and_download(
    proxy_web_url: &str,
    username: &str,
    password: &str,
) -> Result<DownloadedCredential, String> {
    let base_url = normalize_proxy_web_url(proxy_web_url)
        .map_err(|_| "Agent 认证服务配置无效，请联系管理员".to_string())?;
    let normalized_url = base_url.as_str().trim_end_matches('/').to_string();
    let username = username.trim().to_string();
    if username.is_empty() {
        return Err("请输入用户名".to_string());
    }
    if password.len() < 8 {
        return Err("请输入密码".to_string());
    }
    let client = build_proxy_web_client()?;

    info!("开始通过配置的认证服务验证 Agent 用户");
    let login_response = client
        .post(endpoint(&base_url, "api/v1/auth/login")?)
        .json(&LoginPayload {
            username: &username,
            password,
        })
        .send()
        .await
        .map_err(map_request_error)?;
    let login =
        decode_json_response::<AuthenticationResponse>(login_response, MAX_NORMAL_RESPONSE_BYTES)
            .await?;
    let csrf_token = Zeroizing::new(login.csrf_token);

    if login.account.role != "user" {
        best_effort_logout(&client, &base_url, &csrf_token).await;
        return Err("管理员账号不能用于 Agent，请使用普通用户账号登录".to_string());
    }
    if login.account.status != "active" {
        best_effort_logout(&client, &base_url, &csrf_token).await;
        return Err("账号已停用".to_string());
    }

    let me_response = match client.get(endpoint(&base_url, "api/v1/me")?).send().await {
        Ok(response) => response,
        Err(error) => {
            best_effort_logout(&client, &base_url, &csrf_token).await;
            return Err(map_request_error(error));
        }
    };
    let me = match decode_json_response::<MeResponse>(me_response, MAX_NORMAL_RESPONSE_BYTES).await
    {
        Ok(me) => me,
        Err(error) => {
            best_effort_logout(&client, &base_url, &csrf_token).await;
            return Err(error);
        }
    };
    let profile = match require_active_profile(&me) {
        Ok(profile) => profile,
        Err(error) => {
            best_effort_logout(&client, &base_url, &csrf_token).await;
            return Err(error);
        }
    };

    if let Some(linked_username) = login.account.linked_username.as_deref() {
        if linked_username != profile.username {
            best_effort_logout(&client, &base_url, &csrf_token).await;
            return Err("账号与 Proxy 用户绑定关系不一致，请联系管理员".to_string());
        }
    }
    if !profile.enabled {
        best_effort_logout(&client, &base_url, &csrf_token).await;
        return Err("Proxy 用户已停用".to_string());
    }
    if !profile
        .permissions
        .iter()
        .any(|permission| permission == "key.private.read")
    {
        best_effort_logout(&client, &base_url, &csrf_token).await;
        return Err("当前账号没有读取私钥的权限".to_string());
    }
    if profile
        .expires_at
        .is_some_and(|expires_at| expires_at <= current_timestamp())
    {
        best_effort_logout(&client, &base_url, &csrf_token).await;
        return Err("密钥已经过期，请先申请新密钥并等待管理员批准".to_string());
    }

    let private_key_response = match client
        .get(endpoint(&base_url, "api/v1/me/private-key")?)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            best_effort_logout(&client, &base_url, &csrf_token).await;
            return Err(map_request_error(error));
        }
    };
    let private_key = match decode_json_response::<PrivateKeyResponse>(
        private_key_response,
        MAX_PRIVATE_KEY_RESPONSE_BYTES,
    )
    .await
    {
        Ok(private_key) => private_key,
        Err(error) => {
            best_effort_logout(&client, &base_url, &csrf_token).await;
            return Err(error);
        }
    };
    best_effort_logout(&client, &base_url, &csrf_token).await;

    if private_key.username != profile.username || private_key.key_version != profile.key_version {
        return Err("Proxy Web 返回的密钥与当前账号版本不一致".to_string());
    }
    let private_key_pem = Zeroizing::new(private_key.private_key_pem);
    validate_key_pair(&private_key_pem, &private_key.public_key_pem)?;
    validate_proxy_identity_public_key(&private_key.proxy_identity_public_key_pem)?;

    info!(
        username = %profile.username,
        key_version = profile.key_version,
        "Agent 用户认证和私钥校验成功"
    );
    Ok(DownloadedCredential {
        account: AgentAuthAccount {
            username: profile.username.clone(),
            key_version: profile.key_version,
            expires_at: profile.expires_at,
        },
        private_key_pem,
        proxy_identity_public_key_pem: private_key.proxy_identity_public_key_pem,
        proxy_web_url: normalized_url,
    })
}

#[instrument(skip_all)]
pub(crate) async fn start_device_authorization(
    proxy_web_url: &str,
) -> Result<StartedDeviceAuthorization, String> {
    let base_url = normalize_proxy_web_url(proxy_web_url)
        .map_err(|_| "Agent 认证服务配置无效，请联系管理员".to_string())?;
    let normalized_url = base_url.as_str().trim_end_matches('/').to_string();
    let client = build_proxy_web_client()?;
    let response = client
        .post(endpoint(&base_url, "api/v1/agent/device-authorizations")?)
        .json(&AgentDeviceAuthorizationStartPayload {
            platform: "windows",
            client_name: "PPAASS Windows Agent",
        })
        .send()
        .await
        .map_err(map_request_error)?;
    let response = decode_json_response::<AgentDeviceAuthorizationStartResponse>(
        response,
        MAX_NORMAL_RESPONSE_BYTES,
    )
    .await?;

    let device_code = Zeroizing::new(response.device_code);
    validate_device_code(&device_code)?;
    validate_user_code(&response.user_code)?;
    if !(1..=MAX_DEVICE_AUTHORIZATION_SECONDS).contains(&response.expires_in) {
        return Err("Proxy Web 返回的设备登录有效期无效".to_string());
    }
    if !(1..=MAX_DEVICE_POLL_SECONDS).contains(&response.interval) {
        return Err("Proxy Web 返回的设备登录轮询间隔无效".to_string());
    }
    let verification_url = device_verification_url(&base_url, &response.verification_uri_complete)?;
    let expires_at = current_timestamp().saturating_add(response.expires_in);
    info!(
        expires_at,
        interval_seconds = response.interval,
        "已创建 Windows Agent 浏览器设备登录"
    );
    Ok(StartedDeviceAuthorization {
        device_code,
        user_code: response.user_code,
        verification_url,
        expires_at,
        interval_seconds: response.interval,
        proxy_web_url: normalized_url,
    })
}

#[instrument(skip_all)]
pub(crate) async fn poll_device_authorization(
    proxy_web_url: &str,
    device_code: &str,
    default_interval_seconds: u32,
) -> Result<DeviceAuthorizationPoll, String> {
    validate_device_code(device_code)?;
    let base_url = normalize_proxy_web_url(proxy_web_url)
        .map_err(|_| "Agent 认证服务配置无效，请联系管理员".to_string())?;
    let normalized_url = base_url.as_str().trim_end_matches('/').to_string();
    let client = build_proxy_web_client()?;
    let response = client
        .post(endpoint(
            &base_url,
            "api/v1/agent/device-authorizations/token",
        )?)
        .json(&AgentDeviceTokenPayload { device_code })
        .send()
        .await
        .map_err(map_request_error)?;

    if !response.status().is_success() {
        return decode_device_authorization_error(response, default_interval_seconds).await;
    }

    let mut token =
        decode_json_response::<AgentDeviceTokenResponse>(response, MAX_PRIVATE_KEY_RESPONSE_BYTES)
            .await?;
    let csrf_token = Zeroizing::new(std::mem::take(&mut token.csrf_token));
    let downloaded = validate_device_token(token, normalized_url);
    best_effort_logout(&client, &base_url, &csrf_token).await;
    let downloaded = downloaded?;
    info!(
        username = %downloaded.account.username,
        key_version = downloaded.account.key_version,
        "Windows Agent 浏览器设备登录授权成功"
    );
    Ok(DeviceAuthorizationPoll::Authorized(downloaded))
}

pub(crate) fn open_system_browser(url: &Url) -> Result<(), String> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err("设备登录地址无效".to_string());
    }

    #[cfg(windows)]
    {
        let operation = std::ffi::OsStr::new("open")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let target = std::ffi::OsStr::new(url.as_str())
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        // SAFETY: both UTF-16 strings are NUL-terminated and remain alive for the call.
        let result = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                operation.as_ptr(),
                target.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
            )
        };
        if result as isize <= 32 {
            return Err("无法打开系统默认浏览器，请检查 Windows 默认浏览器设置".to_string());
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(url.as_str())
            .spawn()
            .map_err(|_| "无法打开系统默认浏览器".to_string())?;
        Ok(())
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Command::new("xdg-open")
            .arg(url.as_str())
            .spawn()
            .map_err(|_| "无法打开系统默认浏览器".to_string())?;
        Ok(())
    }
}

fn validate_device_token(
    token: AgentDeviceTokenResponse,
    proxy_web_url: String,
) -> Result<DownloadedCredential, String> {
    let AgentDeviceTokenResponse {
        account,
        profile,
        public_key_pem,
        proxy_identity_public_key_pem,
        private_key_pem,
        csrf_token: _,
        _session_expires_at: _,
    } = token;
    let private_key_pem = Zeroizing::new(private_key_pem);
    if account.role != "user" {
        return Err("管理员账号不能用于 Agent，请使用普通用户账号登录".to_string());
    }
    if account.status != "active" {
        return Err("账号已停用".to_string());
    }
    if let Some(linked_username) = account.linked_username.as_deref() {
        if linked_username != profile.username {
            return Err("账号与 Proxy 用户绑定关系不一致，请联系管理员".to_string());
        }
    }
    if !profile
        .permissions
        .iter()
        .any(|permission| permission == "key.private.read")
    {
        return Err("当前账号没有读取私钥的权限".to_string());
    }
    if profile
        .expires_at
        .is_some_and(|expires_at| expires_at <= current_timestamp())
    {
        return Err("密钥已经过期，请先申请新密钥并等待管理员批准".to_string());
    }
    validate_key_pair(&private_key_pem, &public_key_pem)?;
    validate_proxy_identity_public_key(&proxy_identity_public_key_pem)?;
    Ok(DownloadedCredential {
        account: AgentAuthAccount {
            username: profile.username,
            key_version: profile.key_version,
            expires_at: profile.expires_at,
        },
        private_key_pem,
        proxy_identity_public_key_pem,
        proxy_web_url,
    })
}

async fn decode_device_authorization_error(
    response: Response,
    default_interval_seconds: u32,
) -> Result<DeviceAuthorizationPoll, String> {
    let status = response.status();
    let retry_after_seconds = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| (1..=MAX_DEVICE_POLL_SECONDS).contains(value))
        .unwrap_or_else(|| default_interval_seconds.clamp(1, MAX_DEVICE_POLL_SECONDS));
    let bytes = response
        .bytes()
        .await
        .map_err(|_| "读取认证服务响应失败".to_string())?;
    if bytes.len() > MAX_NORMAL_RESPONSE_BYTES {
        return Err("Proxy Web 响应过大，已拒绝处理".to_string());
    }
    let envelope = serde_json::from_slice::<ErrorEnvelope>(&bytes)
        .map_err(|_| format!("Proxy Web 返回 HTTP {}", status.as_u16()))?;
    match envelope.error.code.as_str() {
        "authorization_pending" => Ok(DeviceAuthorizationPoll::Pending {
            slow_down: false,
            retry_after_seconds,
        }),
        "slow_down" | "rate_limited" => Ok(DeviceAuthorizationPoll::Pending {
            slow_down: true,
            retry_after_seconds,
        }),
        "access_denied" => Err("你已在浏览器中拒绝这次设备登录".to_string()),
        "expired_token" => Err("设备登录已过期，请重新开始".to_string()),
        "invalid_device_code" => Err("设备登录码无效或已经使用，请重新开始".to_string()),
        "authorization_invalidated" => Err("账号状态已变化，请重新开始设备登录".to_string()),
        _ => Err(map_api_error(status, envelope.error)),
    }
}

fn validate_device_code(value: &str) -> Result<(), String> {
    if value.len() != 43
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("Proxy Web 返回的设备登录码格式无效".to_string());
    }
    Ok(())
}

fn validate_user_code(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err("Proxy Web 返回的设备授权短码格式无效".to_string());
    }
    Ok(())
}

fn device_verification_url(base_url: &Url, value: &str) -> Result<Url, String> {
    if value.is_empty() || value.len() > 2048 {
        return Err("Proxy Web 返回的设备登录地址无效".to_string());
    }
    let url = base_url
        .join(value)
        .map_err(|_| "Proxy Web 返回的设备登录地址无效".to_string())?;
    if url.origin() != base_url.origin()
        || !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("Proxy Web 返回的设备登录地址不可信".to_string());
    }
    Ok(url)
}

fn build_proxy_web_client() -> Result<Client, String> {
    Client::builder()
        // Proxy Web is the control plane that provisions this Agent. Routing its
        // login or private-key requests through the Agent's own data-plane proxy
        // would create a dependency loop when HTTP_PROXY points at this Agent.
        .no_proxy()
        .cookie_store(true)
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(8))
        .timeout(Duration::from_secs(20))
        .user_agent(concat!("ppaass-desktop-agent/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| format!("初始化 Proxy Web 客户端失败：{error}"))
}

pub(crate) fn write_managed_private_key(
    app: &tauri::AppHandle,
    username: &str,
    key_version: i64,
    private_key_pem: &str,
) -> Result<PathBuf, String> {
    let credentials_dir = managed_credentials_dir(app)?;
    let file_name = managed_private_key_file_name(username, key_version);
    write_private_key_to_dir(&credentials_dir, &file_name, private_key_pem)
}

pub(crate) fn write_managed_proxy_identity_public_key(
    app: &tauri::AppHandle,
    public_key_pem: &str,
) -> Result<PathBuf, String> {
    validate_proxy_identity_public_key(public_key_pem)?;
    let credentials_dir = managed_credentials_dir(app)?;
    write_private_key_to_dir(
        &credentials_dir,
        PROXY_IDENTITY_PUBLIC_KEY_FILE,
        public_key_pem,
    )
}

pub(crate) fn persist_agent_login(
    app: &tauri::AppHandle,
    account: &AgentAuthAccount,
    account_status: AgentAuthAccountStatus,
) -> Result<(), String> {
    persist_agent_login_to_dir(&managed_credentials_dir(app)?, account, account_status)
}

pub(crate) fn load_persisted_agent_login(
    app: &tauri::AppHandle,
) -> Result<Option<PersistedAgentLogin>, String> {
    load_persisted_agent_login_from_dir(&managed_credentials_dir(app)?)
}

pub(crate) fn destroy_persisted_agent_login(app: &tauri::AppHandle) -> Result<(), String> {
    let path = managed_credentials_dir(app)?.join(PERSISTED_AGENT_LOGIN_FILE);
    match fs::remove_file(&path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                if let Ok(directory) = fs::File::open(parent) {
                    let _ = directory.sync_all();
                }
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("删除 Agent 持久登录记录失败：{error}")),
    }
}

fn managed_credentials_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    #[cfg(windows)]
    let app_data_dir = app
        .path()
        .app_local_data_dir()
        .map_err(|error| format!("定位 Agent 本地数据目录失败：{error}"))?;
    #[cfg(not(windows))]
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("定位 Agent 数据目录失败：{error}"))?;
    Ok(app_data_dir.join(CREDENTIALS_DIR))
}

fn persist_agent_login_to_dir(
    credentials_dir: &Path,
    account: &AgentAuthAccount,
    account_status: AgentAuthAccountStatus,
) -> Result<(), String> {
    validate_persisted_account(account)?;
    fs::create_dir_all(credentials_dir)
        .map_err(|error| format!("创建 Agent 登录记录目录失败：{error}"))?;
    #[cfg(unix)]
    fs::set_permissions(credentials_dir, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("设置 Agent 登录记录目录权限失败：{error}"))?;
    #[cfg(windows)]
    set_windows_restricted_acl(credentials_dir, true)?;

    let record = PersistedAgentLoginRecord {
        version: PERSISTED_AGENT_LOGIN_VERSION,
        account: account.clone(),
        account_status,
    };
    let serialized =
        serde_json::to_vec(&record).map_err(|error| format!("编码 Agent 登录记录失败：{error}"))?;
    let destination = credentials_dir.join(PERSISTED_AGENT_LOGIN_FILE);
    let mut temporary = Builder::new()
        .prefix(".agent-login-")
        .tempfile_in(credentials_dir)
        .map_err(|error| format!("创建 Agent 登录记录临时文件失败：{error}"))?;
    #[cfg(unix)]
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("设置 Agent 登录记录权限失败：{error}"))?;
    temporary
        .write_all(&serialized)
        .map_err(|error| format!("写入 Agent 登录记录失败：{error}"))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| format!("同步 Agent 登录记录失败：{error}"))?;
    temporary
        .persist(&destination)
        .map_err(|error| format!("保存 Agent 登录记录失败：{}", error.error))?;
    #[cfg(unix)]
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("设置 Agent 登录记录权限失败：{error}"))?;
    #[cfg(windows)]
    set_windows_restricted_acl(&destination, false)?;
    if let Ok(directory) = fs::File::open(credentials_dir) {
        let _ = directory.sync_all();
    }
    Ok(())
}

pub(crate) fn load_persisted_agent_login_from_dir(
    credentials_dir: &Path,
) -> Result<Option<PersistedAgentLogin>, String> {
    let record_path = credentials_dir.join(PERSISTED_AGENT_LOGIN_FILE);
    let metadata = match fs::symlink_metadata(&record_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("读取 Agent 登录记录元数据失败：{error}")),
    };
    if !metadata.file_type().is_file() || metadata.len() > MAX_PERSISTED_AGENT_LOGIN_BYTES {
        return Err("Agent 登录记录文件无效".to_string());
    }
    let record = serde_json::from_slice::<PersistedAgentLoginRecord>(
        &fs::read(&record_path).map_err(|error| format!("读取 Agent 登录记录失败：{error}"))?,
    )
    .map_err(|_| "Agent 登录记录格式无效".to_string())?;
    if record.version != PERSISTED_AGENT_LOGIN_VERSION {
        return Err("Agent 登录记录版本无效".to_string());
    }
    validate_persisted_account(&record.account)?;

    let private_key_path = credentials_dir.join(managed_private_key_file_name(
        &record.account.username,
        record.account.key_version,
    ));
    let proxy_identity_public_key_path = credentials_dir.join(PROXY_IDENTITY_PUBLIC_KEY_FILE);
    validate_persisted_credential_file(&private_key_path, MAX_PRIVATE_KEY_RESPONSE_BYTES as u64)?;
    validate_persisted_credential_file(
        &proxy_identity_public_key_path,
        MAX_PRIVATE_KEY_RESPONSE_BYTES as u64,
    )?;
    let private_key_pem = fs::read_to_string(&private_key_path)
        .map_err(|error| format!("读取持久登录私钥失败：{error}"))?;
    RsaKeyPair::from_private_key_pem(&private_key_pem)
        .map_err(|_| "持久登录私钥格式无效".to_string())?;
    let proxy_identity_public_key_pem = fs::read_to_string(&proxy_identity_public_key_path)
        .map_err(|error| format!("读取持久登录 Proxy 身份公钥失败：{error}"))?;
    validate_proxy_identity_public_key(&proxy_identity_public_key_pem)?;

    Ok(Some(PersistedAgentLogin {
        account: record.account,
        account_status: record.account_status,
        private_key_path,
        proxy_identity_public_key_path,
    }))
}

fn validate_persisted_account(account: &AgentAuthAccount) -> Result<(), String> {
    if account.username.trim().is_empty() || account.key_version < 1 {
        return Err("Agent 登录记录中的账号信息无效".to_string());
    }
    // `expires_at` is display-only local metadata. It must never be compared
    // with the local clock to revoke a long-running Agent session.
    Ok(())
}

fn validate_persisted_credential_file(path: &Path, maximum_bytes: u64) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "Agent 持久登录凭据缺失，请重新登录".to_string())?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum_bytes {
        return Err("Agent 持久登录凭据文件无效，请重新登录".to_string());
    }
    Ok(())
}

pub(crate) fn destroy_managed_private_key(path: &Path) -> Result<(), String> {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "托管私钥文件名无效".to_string())?;
    if !file_name.starts_with("managed-") || !file_name.ends_with(".pem") {
        return Err("拒绝删除非托管私钥文件".to_string());
    }
    if !path.exists() {
        return Ok(());
    }

    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|error| format!("清空托管私钥失败：{error}"))?;
    file.flush()
        .map_err(|error| format!("清空托管私钥失败：{error}"))?;
    file.sync_all()
        .map_err(|error| format!("同步托管私钥清理失败：{error}"))?;
    drop(file);
    fs::remove_file(path).map_err(|error| format!("删除托管私钥失败：{error}"))
}

pub(crate) fn destroy_managed_proxy_identity_public_key(path: &Path) -> Result<(), String> {
    if path.file_name().and_then(|value| value.to_str()) != Some(PROXY_IDENTITY_PUBLIC_KEY_FILE) {
        return Err("拒绝删除非托管 Proxy 身份公钥文件".to_string());
    }
    if path.exists() {
        fs::remove_file(path).map_err(|error| format!("删除 Proxy 身份公钥失败：{error}"))?;
    }
    Ok(())
}

fn require_active_profile(me: &MeResponse) -> Result<&MeProfile, String> {
    if me.key_state == "active" {
        return me
            .profile
            .as_ref()
            .ok_or_else(|| "当前账号没有可用的 Proxy 用户配置".to_string());
    }
    match me.key_state.as_str() {
        "missing" | "expired" => {
            if me
                .pending_request
                .as_ref()
                .is_some_and(|request| request.status == "pending")
            {
                Err("密钥申请正在等待管理员审批".to_string())
            } else {
                Err("当前没有可用密钥，请先在用户中心提交申请并等待管理员批准".to_string())
            }
        }
        "disabled" => Err("Proxy 用户已停用".to_string()),
        _ => Err("Proxy Web 返回了未知的密钥状态".to_string()),
    }
}

pub(crate) fn registration_page_url(value: &str) -> Result<Url, String> {
    let mut url = normalize_proxy_web_url(value)?;
    url.query_pairs_mut().append_pair("mode", "register");
    Ok(url)
}

fn normalize_proxy_web_url(value: &str) -> Result<Url, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("请输入 Proxy Web 地址".to_string());
    }
    let mut url = Url::parse(value).map_err(|_| "Proxy Web 地址格式无效".to_string())?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("Proxy Web 地址只支持 HTTP 或 HTTPS".to_string());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("Proxy Web 地址不能包含用户名或密码".to_string());
    }
    if url.query().is_some() || url.fragment().is_some() || !matches!(url.path(), "" | "/") {
        return Err("Proxy Web 地址只能填写服务根地址，不能包含路径、查询参数或片段".to_string());
    }
    let host = url
        .host_str()
        .ok_or_else(|| "Proxy Web 地址缺少主机名".to_string())?;
    if url.scheme() == "http" && !is_loopback_host(host) {
        return Err("远程 Proxy Web 必须使用 HTTPS；HTTP 仅允许本机回环地址".to_string());
    }
    url.set_path("/");
    Ok(url)
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .map(|address| address.is_loopback())
            .unwrap_or(false)
}

fn endpoint(base_url: &Url, path: &str) -> Result<Url, String> {
    base_url
        .join(path)
        .map_err(|_| "构造 Proxy Web API 地址失败".to_string())
}

async fn decode_json_response<T>(response: Response, maximum_bytes: usize) -> Result<T, String>
where
    T: DeserializeOwned,
{
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|_| "读取认证服务响应失败".to_string())?;
    if bytes.len() > maximum_bytes {
        return Err("Proxy Web 响应过大，已拒绝处理".to_string());
    }
    if !status.is_success() {
        if let Ok(envelope) = serde_json::from_slice::<ErrorEnvelope>(&bytes) {
            return Err(map_api_error(status, envelope.error));
        }
        return Err(format!("Proxy Web 返回 HTTP {}", status.as_u16()));
    }
    serde_json::from_slice(&bytes).map_err(|_| "Proxy Web 响应格式无效".to_string())
}

fn map_api_error(status: StatusCode, error: ErrorDetail) -> String {
    match error.code.as_str() {
        "invalid_credentials" => "用户名或密码错误".to_string(),
        "key_request_required" => {
            "当前没有可用密钥，请先在用户中心提交申请并等待管理员批准".to_string()
        }
        "unauthorized" => "Proxy Web 会话已失效，请重新登录".to_string(),
        _ => format!("认证服务返回 HTTP {}", status.as_u16()),
    }
}

fn map_request_error(error: reqwest::Error) -> String {
    if error.is_timeout() {
        "连接认证服务超时，请稍后重试".to_string()
    } else if error.is_connect() {
        "无法连接认证服务，请联系管理员检查 Agent 配置和服务状态".to_string()
    } else {
        "认证服务请求失败，请稍后重试".to_string()
    }
}

async fn best_effort_logout(client: &Client, base_url: &Url, csrf_token: &str) {
    let Ok(logout_url) = endpoint(base_url, "api/v1/auth/logout") else {
        return;
    };
    match client
        .post(logout_url)
        .header("x-csrf-token", csrf_token)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {}
        Ok(response) => {
            warn!(
                status = response.status().as_u16(),
                "清理 Proxy Web 临时会话失败"
            );
        }
        Err(_) => warn!("清理 Proxy Web 临时会话失败"),
    }
}

fn validate_key_pair(private_key_pem: &str, public_key_pem: &str) -> Result<(), String> {
    let key_pair = RsaKeyPair::from_private_key_pem(private_key_pem)
        .map_err(|_| "Proxy Web 返回的私钥格式无效".to_string())?;
    RsaKeyPair::from_public_key_pem(public_key_pem)
        .map_err(|_| "Proxy Web 返回的公钥格式无效".to_string())?;
    let derived_public_key = key_pair
        .public_key_to_pem()
        .map_err(|_| "无法从下载的私钥派生公钥".to_string())?;
    if normalize_pem(&derived_public_key) != normalize_pem(public_key_pem) {
        return Err("Proxy Web 返回的公钥和私钥不匹配".to_string());
    }
    Ok(())
}

fn validate_proxy_identity_public_key(public_key_pem: &str) -> Result<(), String> {
    if public_key_pem.len() > 64 * 1024 {
        return Err("Proxy Web 返回的 Proxy 身份公钥过大".to_string());
    }
    let public_key = RsaKeyPair::from_public_key_pem(public_key_pem)
        .map_err(|_| "Proxy Web 返回的 Proxy 身份公钥格式无效".to_string())?;
    validate_rsa_public_key_size(&public_key)
        .map_err(|_| "Proxy Web 返回的 Proxy 身份公钥强度无效".to_string())
}

fn normalize_pem(value: &str) -> String {
    value
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}

fn managed_private_key_file_name(username: &str, key_version: i64) -> String {
    let username_digest = Sha256::digest(username.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("managed-{username_digest}-v{key_version}.pem")
}

fn write_private_key_to_dir(
    credentials_dir: &Path,
    file_name: &str,
    private_key_pem: &str,
) -> Result<PathBuf, String> {
    fs::create_dir_all(credentials_dir).map_err(|error| format!("创建私钥目录失败：{error}"))?;
    #[cfg(unix)]
    fs::set_permissions(credentials_dir, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("设置私钥目录权限失败：{error}"))?;
    #[cfg(windows)]
    set_windows_restricted_acl(credentials_dir, true)?;

    let destination = credentials_dir.join(file_name);
    let mut temporary = Builder::new()
        .prefix(".managed-private-key-")
        .tempfile_in(credentials_dir)
        .map_err(|error| format!("创建私钥临时文件失败：{error}"))?;
    #[cfg(unix)]
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("设置私钥临时文件权限失败：{error}"))?;
    temporary
        .write_all(private_key_pem.as_bytes())
        .map_err(|error| format!("写入私钥失败：{error}"))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| format!("同步私钥到磁盘失败：{error}"))?;
    temporary
        .persist(&destination)
        .map_err(|error| format!("保存私钥失败：{}", error.error))?;
    #[cfg(unix)]
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("设置私钥权限失败：{error}"))?;
    #[cfg(windows)]
    set_windows_restricted_acl(&destination, false)?;
    if let Ok(directory) = fs::File::open(credentials_dir) {
        let _ = directory.sync_all();
    }
    Ok(destination)
}

pub(crate) fn cleanup_old_managed_private_keys(current_private_key: &Path) {
    let Some(credentials_dir) = current_private_key.parent() else {
        return;
    };
    let Some(current_file_name) = current_private_key
        .file_name()
        .and_then(|value| value.to_str())
    else {
        return;
    };
    remove_other_managed_private_keys(credentials_dir, current_file_name);
}

fn remove_other_managed_private_keys(credentials_dir: &Path, current_file_name: &str) {
    let Ok(entries) = fs::read_dir(credentials_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        if file_name.starts_with("managed-")
            && file_name.ends_with(".pem")
            && file_name != current_file_name
        {
            let _ = fs::remove_file(entry.path());
        }
    }
}

#[cfg(windows)]
pub(crate) fn set_windows_restricted_acl(path: &Path, directory: bool) -> Result<(), String> {
    let user_sid = windows_current_user_sid()?;
    let user_permission = if directory {
        format!("*{user_sid}:(OI)(CI)F")
    } else {
        format!("*{user_sid}:F")
    };
    let system_permission = if directory {
        "*S-1-5-18:(OI)(CI)F"
    } else {
        "*S-1-5-18:F"
    };
    let output = Command::new("icacls.exe")
        .arg(path)
        .args(["/inheritance:r", "/grant:r"])
        .arg(user_permission)
        .arg(system_permission)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|error| format!("设置 Windows 私钥 ACL 失败：{error}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "设置 Windows 私钥 ACL 失败：{}",
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

#[cfg(windows)]
fn windows_current_user_sid() -> Result<String, String> {
    let output = Command::new("whoami.exe")
        .args(["/user", "/fo", "csv", "/nh"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|error| format!("读取当前 Windows 用户 SID 失败：{error}"))?;
    if !output.status.success() {
        return Err("读取当前 Windows 用户 SID 失败".to_string());
    }
    let line = String::from_utf8_lossy(&output.stdout);
    let sid = line
        .trim()
        .rsplit(',')
        .next()
        .map(|value| value.trim().trim_matches('"'))
        .filter(|value| value.starts_with("S-1-"))
        .ok_or_else(|| "当前 Windows 用户 SID 格式无效".to_string())?;
    Ok(sid.to_string())
}

fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    use protocol::RsaKeyPair;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::timeout;

    use super::{
        build_proxy_web_client, device_verification_url, load_persisted_agent_login_from_dir,
        managed_private_key_file_name, normalize_proxy_web_url, persist_agent_login_to_dir,
        poll_device_authorization, registration_page_url, remove_other_managed_private_keys,
        start_device_authorization, validate_device_code, validate_key_pair,
        validate_proxy_identity_public_key, write_private_key_to_dir, DeviceAuthorizationPoll,
        PROXY_IDENTITY_PUBLIC_KEY_FILE,
    };
    use crate::models::{AgentAuthAccount, AgentAuthAccountStatus};

    struct ProxyEnvironmentGuard {
        previous: Vec<(&'static str, Option<OsString>)>,
    }

    impl ProxyEnvironmentGuard {
        fn install(proxy_url: &str) -> Self {
            let variables = ["HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"];
            let previous = variables
                .iter()
                .map(|name| (*name, std::env::var_os(name)))
                .collect();
            std::env::set_var("HTTP_PROXY", proxy_url);
            std::env::set_var("http_proxy", proxy_url);
            std::env::remove_var("NO_PROXY");
            std::env::remove_var("no_proxy");
            Self { previous }
        }
    }

    impl Drop for ProxyEnvironmentGuard {
        fn drop(&mut self) {
            for (name, value) in self.previous.drain(..) {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }

    async fn respond_once(listener: TcpListener, body: &'static str) {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 4096];
        let request_bytes = stream.read(&mut request).await.unwrap();
        assert!(request_bytes > 0);
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    }

    async fn read_http_request(stream: &mut TcpStream) -> String {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 2048];
        loop {
            let bytes = stream.read(&mut buffer).await.unwrap();
            assert!(bytes > 0, "connection closed before request was complete");
            request.extend_from_slice(&buffer[..bytes]);
            let Some(header_end) = request.windows(4).position(|value| value == b"\r\n\r\n") else {
                continue;
            };
            let header_end = header_end + 4;
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            if request.len() >= header_end + content_length {
                return String::from_utf8(request).unwrap();
            }
        }
    }

    async fn write_http_response(
        stream: &mut TcpStream,
        status: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) {
        let extra_headers = headers
            .iter()
            .map(|(name, value)| format!("{name}: {value}\r\n"))
            .collect::<String>();
        let response = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n{extra_headers}connection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn proxy_web_client_ignores_http_proxy_environment() {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target_listener.local_addr().unwrap();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy_listener.local_addr().unwrap();
        let target_task = tokio::spawn(respond_once(target_listener, "proxy-web"));
        let proxy_task = tokio::spawn(respond_once(proxy_listener, "environment-proxy"));

        let environment = ProxyEnvironmentGuard::install(&format!("http://{proxy_address}"));
        let client = build_proxy_web_client().unwrap();
        drop(environment);

        let response = timeout(
            Duration::from_secs(3),
            client
                .get(format!("http://{target_address}/healthz"))
                .send(),
        )
        .await
        .expect("Proxy Web request timed out")
        .unwrap();
        assert_eq!(response.text().await.unwrap(), "proxy-web");
        target_task.await.unwrap();
        proxy_task.abort();
        let _ = proxy_task.await;
    }

    #[test]
    fn proxy_web_url_only_allows_loopback_http() {
        assert!(normalize_proxy_web_url("http://127.0.0.1:8787").is_ok());
        assert!(normalize_proxy_web_url("http://localhost:8787/").is_ok());
        assert!(normalize_proxy_web_url("http://[::1]:8787").is_ok());
        assert!(normalize_proxy_web_url("https://proxy.example.com").is_ok());
        assert!(normalize_proxy_web_url("http://proxy.example.com").is_err());
        assert!(normalize_proxy_web_url("https://proxy.example.com/path").is_err());
        assert!(normalize_proxy_web_url("file:///tmp/proxy").is_err());
    }

    #[test]
    fn registration_page_url_uses_the_validated_proxy_web_root() {
        let url = registration_page_url("http://127.0.0.1:8787").unwrap();
        assert_eq!(url.as_str(), "http://127.0.0.1:8787/?mode=register");

        assert!(registration_page_url("http://proxy.example.com").is_err());
        assert!(registration_page_url("https://proxy.example.com/path").is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn starts_windows_device_authorization_without_exposing_endpoint_overrides() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_http_request(&mut stream).await;
            assert!(request.starts_with("POST /api/v1/agent/device-authorizations HTTP/1.1"));
            assert!(request.contains(r#""platform":"windows""#));
            assert!(request.contains(r#""client_name":"PPAASS Windows Agent""#));
            let body = serde_json::json!({
                "device_code": "A".repeat(43),
                "user_code": "ABCD-EFGH-JKMN",
                "verification_uri": "/#agent-authorize",
                "verification_uri_complete": "/#agent-authorize=ABCD-EFGH-JKMN",
                "expires_in": 600,
                "interval": 5
            })
            .to_string();
            write_http_response(&mut stream, "200 OK", &[], &body).await;
        });

        let started = start_device_authorization(&format!("http://{address}"))
            .await
            .unwrap();
        assert_eq!(started.device_code.as_str(), "A".repeat(43));
        assert_eq!(started.user_code, "ABCD-EFGH-JKMN");
        assert_eq!(started.interval_seconds, 5);
        assert_eq!(
            started.verification_url.as_str(),
            format!("http://{address}/#agent-authorize=ABCD-EFGH-JKMN")
        );
        server.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn device_authorization_poll_honors_pending_and_slow_down_retry_after() {
        for (status, code, retry_after, expected_slow_down) in [
            (
                "428 Precondition Required",
                "authorization_pending",
                "7",
                false,
            ),
            ("429 Too Many Requests", "slow_down", "11", true),
            ("429 Too Many Requests", "rate_limited", "13", true),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = read_http_request(&mut stream).await;
                assert!(
                    request.starts_with("POST /api/v1/agent/device-authorizations/token HTTP/1.1")
                );
                let body = serde_json::json!({
                    "error": {
                        "code": code,
                        "message": "waiting"
                    }
                })
                .to_string();
                write_http_response(&mut stream, status, &[("retry-after", retry_after)], &body)
                    .await;
            });

            let result =
                poll_device_authorization(&format!("http://{address}"), &"A".repeat(43), 5)
                    .await
                    .unwrap();
            match result {
                DeviceAuthorizationPoll::Pending {
                    slow_down,
                    retry_after_seconds,
                } => {
                    assert_eq!(slow_down, expected_slow_down);
                    assert_eq!(retry_after_seconds, retry_after.parse::<u32>().unwrap());
                }
                DeviceAuthorizationPoll::Authorized(_) => {
                    panic!("pending response must not authorize the Agent")
                }
            }
            server.await.unwrap();
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn device_authorization_poll_handles_all_terminal_errors() {
        for (status, code, expected_message) in [
            ("403 Forbidden", "access_denied", "拒绝"),
            ("400 Bad Request", "expired_token", "过期"),
            ("400 Bad Request", "invalid_device_code", "无效"),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let _request = read_http_request(&mut stream).await;
                let body = serde_json::json!({
                    "error": {
                        "code": code,
                        "message": "terminal"
                    }
                })
                .to_string();
                write_http_response(&mut stream, status, &[], &body).await;
            });

            let error = poll_device_authorization(&format!("http://{address}"), &"A".repeat(43), 5)
                .await
                .err()
                .expect("terminal response must fail");
            assert!(error.contains(expected_message), "{error}");
            server.await.unwrap();
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn device_authorization_validates_key_pair_and_logs_out_temporary_session() {
        let pair = RsaKeyPair::generate(2048).unwrap();
        let private_key = pair.private_key_to_pem().unwrap();
        let public_key = pair.public_key_to_pem().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut token_stream, _) = listener.accept().await.unwrap();
            let token_request = read_http_request(&mut token_stream).await;
            assert!(token_request
                .starts_with("POST /api/v1/agent/device-authorizations/token HTTP/1.1"));
            let body = serde_json::json!({
                "account": {
                    "role": "user",
                    "status": "active",
                    "linked_username": "alice"
                },
                "profile": {
                    "username": "alice",
                    "permissions": ["key.private.read"],
                    "key_version": 9,
                    "expires_at": 4_000_000_000_i64
                },
                "public_key_pem": public_key.clone(),
                "proxy_identity_public_key_pem": public_key,
                "private_key_pem": private_key,
                "csrf_token": "csrf-device-token",
                "session_expires_at": 4_000_000_000_i64
            })
            .to_string();
            write_http_response(
                &mut token_stream,
                "200 OK",
                &[(
                    "set-cookie",
                    "ppaass_session=device-session; Path=/; HttpOnly; SameSite=Lax",
                )],
                &body,
            )
            .await;

            let (mut logout_stream, _) = listener.accept().await.unwrap();
            let logout_request = read_http_request(&mut logout_stream).await;
            assert!(logout_request.starts_with("POST /api/v1/auth/logout HTTP/1.1"));
            assert!(logout_request
                .to_ascii_lowercase()
                .contains("cookie: ppaass_session=device-session"));
            assert!(logout_request
                .to_ascii_lowercase()
                .contains("x-csrf-token: csrf-device-token"));
            write_http_response(&mut logout_stream, "204 No Content", &[], "").await;
        });

        let result = poll_device_authorization(&format!("http://{address}"), &"A".repeat(43), 5)
            .await
            .unwrap();
        match result {
            DeviceAuthorizationPoll::Authorized(downloaded) => {
                assert_eq!(downloaded.account.username, "alice");
                assert_eq!(downloaded.account.key_version, 9);
                assert!(downloaded.private_key_pem.contains("BEGIN PRIVATE KEY"));
            }
            DeviceAuthorizationPoll::Pending { .. } => {
                panic!("authorized response must deliver credentials")
            }
        }
        server.await.unwrap();
    }

    #[test]
    fn device_authorization_rejects_malformed_codes_and_cross_origin_verification_urls() {
        assert!(validate_device_code(&"A".repeat(43)).is_ok());
        assert!(validate_device_code("../not-a-device-code").is_err());
        let base = normalize_proxy_web_url("https://proxy.example.com").unwrap();
        assert!(device_verification_url(&base, "/#agent-authorize=ABCD").is_ok());
        assert!(device_verification_url(
            &base,
            "https://attacker.example.com/#agent-authorize=ABCD"
        )
        .is_err());
    }

    #[test]
    fn validates_matching_key_pair_and_rejects_mismatch() {
        let pair = RsaKeyPair::generate(2048).unwrap();
        let private_key = pair.private_key_to_pem().unwrap();
        let public_key = pair.public_key_to_pem().unwrap();
        assert!(validate_key_pair(&private_key, &public_key).is_ok());

        let other = RsaKeyPair::generate(2048).unwrap();
        assert!(validate_key_pair(&private_key, &other.public_key_to_pem().unwrap()).is_err());
    }

    #[test]
    fn validates_proxy_identity_public_key_strength() {
        let valid = RsaKeyPair::generate(2048)
            .unwrap()
            .public_key_to_pem()
            .unwrap();
        assert!(validate_proxy_identity_public_key(&valid).is_ok());
        let weak = RsaKeyPair::generate(1024)
            .unwrap()
            .public_key_to_pem()
            .unwrap();
        assert!(validate_proxy_identity_public_key(&weak).is_err());
        assert!(validate_proxy_identity_public_key("not a key").is_err());
    }

    #[test]
    fn managed_key_filename_cannot_escape_credentials_directory() {
        let name = managed_private_key_file_name("../用户/name", 7);
        assert!(!name.contains('/'));
        assert!(!name.contains('\\'));
        assert!(name.ends_with("-v7.pem"));
        assert_eq!(name.len(), "managed-".len() + 64 + "-v7.pem".len());
    }

    #[test]
    fn managed_key_filename_is_bounded_for_maximum_length_username() {
        let username = "x".repeat(128);
        let name = managed_private_key_file_name(&username, i64::MAX);
        assert!(name.len() < 255);
        assert!(!name.contains(&username));
        assert_eq!(name, managed_private_key_file_name(&username, i64::MAX));
    }

    #[test]
    fn cleanup_removes_legacy_username_encoded_managed_keys() {
        let directory = tempfile::tempdir().unwrap();
        let current = managed_private_key_file_name("alice", 2);
        let legacy = "managed-616c696365-v1.pem";
        fs::write(directory.path().join(&current), "current").unwrap();
        fs::write(directory.path().join(legacy), "legacy").unwrap();

        remove_other_managed_private_keys(directory.path(), &current);

        assert!(directory.path().join(&current).is_file());
        assert!(!directory.path().join(legacy).exists());
    }

    #[test]
    fn writes_managed_private_key_with_restricted_permissions() {
        let directory = tempfile::tempdir().unwrap();
        let credentials_dir = directory.path().join("credentials");
        let path =
            write_private_key_to_dir(&credentials_dir, "managed-test-v1.pem", "private").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "private");
        let replaced =
            write_private_key_to_dir(&credentials_dir, "managed-test-v1.pem", "rotated").unwrap();
        assert_eq!(replaced, path);
        assert_eq!(fs::read_to_string(&path).unwrap(), "rotated");
        #[cfg(unix)]
        {
            assert_eq!(
                fs::metadata(&credentials_dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn persisted_login_survives_local_expiry_metadata_and_keeps_status() {
        let temp = tempfile::tempdir().unwrap();
        let credentials_dir = temp.path().join("credentials");
        let account = AgentAuthAccount {
            username: "alice".to_string(),
            key_version: 7,
            // This timestamp is deliberately in the past. It is cached display
            // metadata, not authority for a local automatic logout.
            expires_at: Some(1),
        };
        let user_key = RsaKeyPair::generate(2048).unwrap();
        let proxy_identity = RsaKeyPair::generate(2048).unwrap();
        let private_key_path = write_private_key_to_dir(
            &credentials_dir,
            &managed_private_key_file_name(&account.username, account.key_version),
            &user_key.private_key_to_pem().unwrap(),
        )
        .unwrap();
        write_private_key_to_dir(
            &credentials_dir,
            PROXY_IDENTITY_PUBLIC_KEY_FILE,
            &proxy_identity.public_key_to_pem().unwrap(),
        )
        .unwrap();

        persist_agent_login_to_dir(&credentials_dir, &account, AgentAuthAccountStatus::Expired)
            .unwrap();
        let restored = load_persisted_agent_login_from_dir(&credentials_dir)
            .unwrap()
            .expect("persisted login");

        assert_eq!(restored.account, account);
        assert_eq!(restored.account_status, AgentAuthAccountStatus::Expired);
        assert_eq!(restored.private_key_path, private_key_path);
        assert_eq!(
            restored.proxy_identity_public_key_path,
            credentials_dir.join(PROXY_IDENTITY_PUBLIC_KEY_FILE)
        );
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(credentials_dir.join(super::PERSISTED_AGENT_LOGIN_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn persisted_login_requires_untampered_managed_credential_files() {
        let temp = tempfile::tempdir().unwrap();
        let credentials_dir = temp.path().join("credentials");
        let account = AgentAuthAccount {
            username: "alice".to_string(),
            key_version: 1,
            expires_at: None,
        };
        persist_agent_login_to_dir(&credentials_dir, &account, AgentAuthAccountStatus::Active)
            .unwrap();

        let error = load_persisted_agent_login_from_dir(&credentials_dir).unwrap_err();
        assert!(error.contains("凭据缺失"));
    }
}
