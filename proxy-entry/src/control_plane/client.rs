use std::{
    collections::HashMap,
    fs,
    net::IpAddr,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use dashmap::DashMap;
use proxy_control_protocol::{
    ACCESS_BATCHES_PATH, AUTHORIZATION_RESOLVE_PATH, AccessBatchRequest, AccessBatchResponse,
    AccessEvent, AuthorizationResolveRequest, AuthorizationResolveResponse, CONTROL_HEALTH_PATH,
    CONTROL_PROTOCOL_VERSION, ControlHealthResponse,
};
use reqwest::{Client, StatusCode, Url, header};
use sha2::{Digest, Sha256};
use tokio::{
    sync::{Mutex, RwLock},
    time::Instant,
};
use tracing::{debug, info};

use super::AccessEventSink;
use crate::{
    config::{ProxyConfig, UserConfig},
    error::{ProxyError, Result},
};

const MAX_CONTROL_TOKEN_BYTES: u64 = 512;

#[derive(Clone)]
pub(super) struct CachedAuthorization {
    pub value: Option<UserConfig>,
    pub cached_at: Instant,
}

pub(crate) struct RemoteControlPlane {
    pub(super) client: Client,
    pub(super) base_url: Url,
    pub(super) token: Arc<str>,
    pub(super) entry_id: Arc<str>,
    pub(super) cache_max_age: Duration,
    pub(super) cache: RwLock<HashMap<String, CachedAuthorization>>,
    pub(super) request_locks: DashMap<String, Arc<Mutex<()>>>,
    pub(super) last_event_id: AtomicU64,
}

impl RemoteControlPlane {
    pub(crate) async fn connect(
        config: &ProxyConfig,
        transport_identity_public_key_pem: &str,
    ) -> Result<Arc<Self>> {
        validate_entry_id(&config.entry_id)?;
        let base_url = validate_control_url(&config.registry_control_url)?;
        let token = load_control_token(Path::new(&config.registry_control_token_path))?;
        let timeout = Duration::from_secs(config.control_request_timeout_secs.clamp(1, 60));
        let client = Client::builder()
            .connect_timeout(timeout.min(Duration::from_secs(10)))
            .timeout(timeout)
            .user_agent(concat!("ppaass-proxy-entry/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| {
                ProxyError::Configuration(format!("创建 Registry 控制面 HTTP 客户端失败：{error}"))
            })?;
        let control = Arc::new(Self {
            client,
            base_url,
            token: Arc::from(token),
            entry_id: Arc::from(config.entry_id.as_str()),
            cache_max_age: Duration::from_secs(config.authorization_cache_max_age_secs),
            cache: RwLock::new(HashMap::new()),
            request_locks: DashMap::new(),
            last_event_id: AtomicU64::new(0),
        });
        control
            .verify_health(transport_identity_public_key_pem)
            .await?;
        super::events::spawn_authorization_event_listener(Arc::downgrade(&control));
        Ok(control)
    }

    pub(super) fn endpoint(&self, path: &str) -> Result<Url> {
        self.base_url.join(path).map_err(|error| {
            ProxyError::Configuration(format!("构造 Registry 控制面 URL 失败：{error}"))
        })
    }

    pub(super) fn bearer_value(&self) -> String {
        format!("Bearer {}", self.token)
    }

    pub(super) async fn clear_authorization_cache(&self) {
        self.cache.write().await.clear();
        debug!("已使 Proxy Entry 授权缓存全部失效");
    }

    async fn verify_health(&self, transport_identity_public_key_pem: &str) -> Result<()> {
        let response = self
            .client
            .get(self.endpoint(CONTROL_HEALTH_PATH)?)
            .send()
            .await
            .map_err(|error| {
                ProxyError::ControlPlane(format!("Registry 控制面健康检查失败：{error}"))
            })?;
        if response.status() != StatusCode::OK {
            return Err(ProxyError::ControlPlane(format!(
                "Registry 控制面健康检查返回 HTTP {}",
                response.status()
            )));
        }
        let health = response
            .json::<ControlHealthResponse>()
            .await
            .map_err(|error| {
                ProxyError::ControlPlane(format!("Registry 控制面健康响应无效：{error}"))
            })?;
        if health.protocol_version != CONTROL_PROTOCOL_VERSION {
            return Err(ProxyError::ControlPlane(format!(
                "Registry 控制协议版本不兼容：Entry={}，Registry={}",
                CONTROL_PROTOCOL_VERSION, health.protocol_version
            )));
        }
        let expected_identity = hex::encode(Sha256::digest(
            transport_identity_public_key_pem.trim().as_bytes(),
        ));
        if health.proxy_identity_sha256 != expected_identity {
            return Err(ProxyError::ControlPlane(
                "Entry 传输身份与 Registry 发布给 Agent 的身份不一致".to_string(),
            ));
        }
        info!(
            registry_instance_id = health.registry_instance_id,
            protocol_version = health.protocol_version,
            "Registry 控制面连接和 Proxy 身份校验成功"
        );
        Ok(())
    }

    pub(super) async fn fetch_authorization(&self, username: &str) -> Result<Option<UserConfig>> {
        let response = self
            .client
            .post(self.endpoint(AUTHORIZATION_RESOLVE_PATH)?)
            .header(header::AUTHORIZATION, self.bearer_value())
            .json(&AuthorizationResolveRequest {
                username: username.to_string(),
            })
            .send()
            .await
            .map_err(|error| {
                ProxyError::ControlPlane(format!("查询 Registry 用户授权失败：{error}"))
            })?;
        if response.status() != StatusCode::OK {
            return Err(control_status_error("查询用户授权", response.status()));
        }
        let resolved = response
            .json::<AuthorizationResolveResponse>()
            .await
            .map_err(|error| {
                ProxyError::ControlPlane(format!("Registry 用户授权响应无效：{error}"))
            })?;
        self.last_event_id
            .fetch_max(resolved.revision, Ordering::Release);
        resolved
            .authorization
            .map(|authorization| {
                if authorization.username != username {
                    return Err(ProxyError::ControlPlane(
                        "Registry 返回了不匹配的用户名".to_string(),
                    ));
                }
                Ok(UserConfig {
                    username: authorization.username,
                    public_key_pem: authorization.public_key_pem,
                    expires_at: authorization.expires_at.map(|value| value.to_string()),
                    permissions: authorization.permissions,
                    enabled: authorization.enabled,
                    key_version: Some(authorization.key_version),
                })
            })
            .transpose()
    }
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

fn control_status_error(operation: &str, status: StatusCode) -> ProxyError {
    ProxyError::ControlPlane(format!("{operation}返回 HTTP {status}"))
}

fn validate_entry_id(entry_id: &str) -> Result<()> {
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

fn validate_control_url(value: &str) -> Result<Url> {
    let mut url = Url::parse(value).map_err(|error| {
        ProxyError::Configuration(format!("registry_control_url 无效：{error}"))
    })?;
    if url.query().is_some() || url.fragment().is_some() {
        return Err(ProxyError::Configuration(
            "registry_control_url 不能包含 query 或 fragment".to_string(),
        ));
    }
    let secure = url.scheme() == "https";
    let loopback_http = url.scheme() == "http"
        && url.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
    if !secure && !loopback_http {
        return Err(ProxyError::Configuration(
            "registry_control_url 必须使用 HTTPS；仅回环地址允许 HTTP".to_string(),
        ));
    }
    url.set_path("/");
    Ok(url)
}

fn load_control_token(path: &Path) -> Result<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_url_requires_https_except_for_loopback_development() {
        assert!(validate_control_url("https://registry.example.com").is_ok());
        assert!(validate_control_url("http://127.0.0.1:8797").is_ok());
        assert!(validate_control_url("http://localhost:8797").is_ok());
        assert!(validate_control_url("http://registry.example.com").is_err());
        assert!(validate_control_url("https://registry.example.com?token=bad").is_err());
    }

    #[test]
    fn entry_id_rejects_unsafe_or_empty_values() {
        assert!(validate_entry_id("entry-production:1").is_ok());
        assert!(validate_entry_id("").is_err());
        assert!(validate_entry_id("../entry").is_err());
        assert!(
            validate_entry_id(&"x".repeat(proxy_control_protocol::MAX_ENTRY_ID_BYTES + 1)).is_err()
        );
    }

    #[test]
    fn control_token_file_is_trimmed_and_validated() {
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("control-token");
        let token = "0123456789abcdef0123456789abcdef";
        fs::write(&path, format!("{token}\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(load_control_token(&path).unwrap(), token);

        fs::write(&path, "too-short").unwrap();
        assert!(load_control_token(&path).is_err());
    }
}
