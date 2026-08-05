use std::{
    fs,
    net::SocketAddr,
    path::Path,
    sync::{Arc, atomic::AtomicU64},
    time::Duration,
};

use proxy_control_protocol::{
    ACCESS_BATCHES_PATH, AccessBatchRequest, AccessBatchResponse, AccessEvent,
};
use reqwest::{Client, StatusCode, Url, header};
use tokio::sync::Mutex;

use super::{AccessEventSink, authorization_store::AuthorizationStore};
use crate::{
    config::ProxyConfig,
    error::{ProxyError, Result},
};

const MAX_CONTROL_TOKEN_BYTES: u64 = 512;

pub struct RemoteControlPlane {
    pub(super) client: Client,
    pub(super) events_client: Client,
    pub(super) base_url: Url,
    pub(super) token: Arc<str>,
    pub(super) entry_id: Arc<str>,
    pub(super) advertised_address: Arc<str>,
    pub(super) request_timeout: Duration,
    pub(super) authorization_store: AuthorizationStore,
    pub(super) authorization_refresh: Mutex<()>,
    pub(super) last_event_id: AtomicU64,
}

impl RemoteControlPlane {
    pub async fn new(config: &ProxyConfig) -> Result<Arc<Self>> {
        validate_entry_id(&config.entry_id)?;
        let advertised_address = validate_advertised_address(&config.advertised_address)?;
        let base_url = validate_registry_url(&config.registry_url)?;
        let token = load_control_token(Path::new(&config.registry_control_token_path))?;
        let timeout = Duration::from_secs(config.control_request_timeout_secs.clamp(1, 60));
        let client = control_client_builder(timeout)
            .timeout(timeout)
            .build()
            .map_err(|error| {
                ProxyError::Configuration(format!("创建 Registry 控制面 HTTP 客户端失败：{error}"))
            })?;
        // SSE 响应会持续存在，不能复用带整个请求总时限的普通控制面客户端。
        // 连接和响应头仍由 events.rs 单独限时，响应体则允许长期流式读取。
        let events_client = control_client_builder(timeout).build().map_err(|error| {
            ProxyError::Configuration(format!("创建 Registry 事件流 HTTP 客户端失败：{error}"))
        })?;
        let authorization_store = AuthorizationStore::open(
            Path::new(&config.authorization_database_path),
            base_url.as_str(),
            &config.entry_id,
        )
        .await?;
        let initial_revision = authorization_store.initial_revision().unwrap_or(0);
        Ok(Arc::new(Self {
            client,
            events_client,
            base_url,
            token: Arc::from(token),
            entry_id: Arc::from(config.entry_id.as_str()),
            advertised_address: Arc::from(advertised_address),
            request_timeout: timeout,
            authorization_store,
            authorization_refresh: Mutex::new(()),
            last_event_id: AtomicU64::new(initial_revision),
        }))
    }

    pub(super) fn endpoint(&self, path: &str) -> Result<Url> {
        self.base_url.join(path).map_err(|error| {
            ProxyError::Configuration(format!("构造 Registry 控制面 URL 失败：{error}"))
        })
    }

    pub(super) fn bearer_value(&self) -> String {
        format!("Bearer {}", self.token)
    }
}

fn control_client_builder(timeout: Duration) -> reqwest::ClientBuilder {
    Client::builder()
        .connect_timeout(timeout.min(Duration::from_secs(10)))
        // Product policy accepts Registry certificates without chain or hostname validation.
        .danger_accept_invalid_certs(true)
        .user_agent(concat!("ppaass-proxy-entry/", env!("CARGO_PKG_VERSION")))
}

#[async_trait::async_trait]
impl AccessEventSink for RemoteControlPlane {
    async fn submit_access_batch(&self, batch_id: &str, events: &[AccessEvent]) -> Result<()> {
        let response = self
            .client
            .post(self.endpoint(ACCESS_BATCHES_PATH)?)
            .header(header::AUTHORIZATION, self.bearer_value())
            .json(&AccessBatchRequest {
                entry_id: self.entry_id.to_string(),
                batch_id: batch_id.to_string(),
                events: events.to_vec(),
            })
            .send()
            .await
            .map_err(|error| ProxyError::ControlPlane(format!("上报访问记录批次失败：{error}")))?;
        if response.status() != StatusCode::OK {
            return Err(control_status_error("上报访问记录批次", response.status()));
        }
        response
            .json::<AccessBatchResponse>()
            .await
            .map_err(|error| ProxyError::ControlPlane(format!("访问记录批次响应无效：{error}")))?;
        Ok(())
    }
}

pub(super) fn control_status_error(operation: &str, status: StatusCode) -> ProxyError {
    ProxyError::ControlPlane(format!("{operation}返回 HTTP {status}"))
}

pub fn validate_entry_id(entry_id: &str) -> Result<()> {
    if entry_id.is_empty()
        || entry_id.len() > proxy_control_protocol::MAX_ENTRY_ID_BYTES
        || !entry_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ProxyError::Configuration(format!(
            "entry_id 必须是 1..={} 字节的安全标识符",
            proxy_control_protocol::MAX_ENTRY_ID_BYTES
        )));
    }
    Ok(())
}

pub fn validate_advertised_address(value: &str) -> Result<String> {
    if value.is_empty()
        || value.len() > proxy_control_protocol::MAX_ADVERTISED_ADDRESS_BYTES
        || value.chars().any(char::is_whitespace)
        || value.contains(['/', '\\', '?', '#', '@'])
        || value.contains("://")
    {
        return Err(invalid_advertised_address());
    }
    if let Ok(address) = value.parse::<SocketAddr>() {
        if address.port() == 0 {
            return Err(invalid_advertised_address());
        }
        return Ok(address.to_string());
    }

    let (host, port_text) = value
        .rsplit_once(':')
        .ok_or_else(invalid_advertised_address)?;
    let port = port_text
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(invalid_advertised_address)?;
    if host.is_empty() || host.len() > 253 || host.contains(':') || !host.is_ascii() {
        return Err(invalid_advertised_address());
    }
    if !host.split('.').all(valid_hostname_label) {
        return Err(invalid_advertised_address());
    }
    Ok(format!("{}:{port}", host.to_ascii_lowercase()))
}

fn valid_hostname_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && label
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && label
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn invalid_advertised_address() -> ProxyError {
    ProxyError::Configuration(
        "advertised_address 必须是域名、IPv4 或方括号 IPv6 加非零端口".to_string(),
    )
}

pub fn validate_registry_url(value: &str) -> Result<Url> {
    let mut url = Url::parse(value)
        .map_err(|error| ProxyError::Configuration(format!("registry_url 无效：{error}")))?;
    if url.query().is_some() || url.fragment().is_some() {
        return Err(ProxyError::Configuration(
            "registry_url 不能包含 query 或 fragment".to_string(),
        ));
    }
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(ProxyError::Configuration(
            "registry_url 必须是包含主机名的 HTTP 或 HTTPS 地址".to_string(),
        ));
    }
    url.set_path("/");
    Ok(url)
}

pub fn load_control_token(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        ProxyError::Configuration(format!(
            "无法读取 Registry 控制面 Token 文件 {}：{error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_CONTROL_TOKEN_BYTES {
        return Err(ProxyError::Configuration(format!(
            "Registry 控制面 Token 路径必须是至多 {MAX_CONTROL_TOKEN_BYTES} 字节的普通文件：{}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ProxyError::Configuration(format!(
                "Registry 控制面 Token 文件不能授予属组或其他用户权限：{}",
                path.display()
            )));
        }
    }
    let token = fs::read_to_string(path).map_err(|error| {
        ProxyError::Configuration(format!(
            "无法读取 Registry 控制面 Token 文件 {}：{error}",
            path.display()
        ))
    })?;
    let token = token.trim();
    if token.len() < 32 || token.chars().any(char::is_whitespace) {
        return Err(ProxyError::Configuration(
            "Registry 控制面 Token 必须至少 32 字节且不能包含空白字符".to_string(),
        ));
    }
    Ok(token.to_string())
}
