use std::fs;
use std::io::Write;
use std::net::IpAddr;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use protocol::RsaKeyPair;
use reqwest::{redirect::Policy, Client, Response, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tauri::Manager;
use tempfile::Builder;
use tracing::{info, instrument, warn};
use url::Url;
use zeroize::Zeroizing;

use crate::models::AgentAuthAccount;

const CREDENTIALS_DIR: &str = "credentials";
const MAX_NORMAL_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_PRIVATE_KEY_RESPONSE_BYTES: usize = 256 * 1024;

pub(crate) struct DownloadedCredential {
    pub(crate) account: AgentAuthAccount,
    pub(crate) private_key_pem: Zeroizing<String>,
    pub(crate) proxy_web_url: String,
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
    private_key_pem: String,
    key_version: i64,
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
        proxy_web_url: normalized_url,
    })
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
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("定位 Agent 数据目录失败：{error}"))?;
    let credentials_dir = app_data_dir.join(CREDENTIALS_DIR);
    let file_name = managed_private_key_file_name(username, key_version);
    write_private_key_to_dir(&credentials_dir, &file_name, private_key_pem)
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
    let username_hex = username
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("managed-{username_hex}-v{key_version}.pem")
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
    if let Ok(directory) = fs::File::open(credentials_dir) {
        let _ = directory.sync_all();
    }
    Ok(destination)
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
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    use super::{
        build_proxy_web_client, managed_private_key_file_name, normalize_proxy_web_url,
        registration_page_url, validate_key_pair, write_private_key_to_dir,
    };

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
    fn managed_key_filename_cannot_escape_credentials_directory() {
        let name = managed_private_key_file_name("../用户/name", 7);
        assert!(!name.contains('/'));
        assert!(!name.contains('\\'));
        assert!(name.ends_with("-v7.pem"));
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
}
