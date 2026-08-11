use crate::store::{
    AccessLogRepository, AccessProtocol, AccessRecord, AccountActor, AccountRepository,
    AccountRole, AccountStatus, AgentDeviceAuthorization, AgentDeviceAuthorizationClaim,
    AgentDeviceAuthorizationDecision, AgentDeviceAuthorizationFinalize,
    AgentDeviceAuthorizationPoll, AgentDeviceAuthorizationRepository,
    AgentDeviceAuthorizationStatus, ApprovedKeyMaterial, AuditAction, AuditEvent, AuditEventQuery,
    AuditLogRepository, DEPRECATED_AGENT_CONFIG_VIEW_PERMISSION, ExternalIdentity,
    KEY_ROTATE_PERMISSION, KeyGenerationRequest, KeyPairRotation, KeyRequestApproval,
    KeyRequestKind, KeyRequestRejection, KeyRequestStatus, MAX_ACCESS_LOG_QUERY_LIMIT,
    MAX_ACCESS_LOG_RETENTION_DAYS, MIN_ACCESS_LOG_RETENTION_DAYS, ManagedUser, ManagedUserUpdate,
    NewAgentDeviceAuthorization, NewKeyGenerationRequest, NewManagedUser, NewProxyAddress, NewUser,
    NewUserAccount, PRIVATE_KEY_READ_PERMISSION, ProxyAddress, ProxyAddressRepository,
    ProxyAddressUpdate, UserOrigin, UserRecord, UserRepository, UserRepositoryError, UserUpdate,
    WebAccount, normalize_username, parse_expires_at,
};
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{
        DefaultBodyLimit, FromRequest, Path, Query, State,
        rejection::{BytesRejection, JsonRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get, post, put},
};
use protocol::RsaKeyPair;
use rand::RngExt;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, sync::Arc, time::Duration};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tower_http::{services::ServeDir, timeout::TimeoutLayer, trace::TraceLayer};
use tracing::{info, instrument, warn};
use zeroize::Zeroizing;

use crate::{
    agent_tokens::AgentAccessTokenService,
    auth::{AuthenticatedSession, PasswordService, SessionStore, append_set_cookie, random_token},
    error::ApiError,
    secrets::PrivateKeyCipher,
    web_handoffs::{
        AGENT_WEB_SESSION_HANDOFF_TTL_SECONDS, AgentWebSessionHandoffConsumeError,
        AgentWebSessionHandoffIssueError, AgentWebSessionHandoffStore,
    },
};

const MAX_REQUEST_BODY_BYTES: usize = 32 * 1024;
const REQUEST_TIMEOUT_SECONDS: u64 = 30;
const MAX_AGENT_PRIVATE_KEY_BYTES: usize = 16 * 1024;
const MAX_AGENT_TOKEN_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_ACCESS_RECORD_LIMIT: u32 = 100;
const MAX_AUDIT_SEARCH_CHARACTERS: usize = 120;
const SECONDS_PER_DAY: i64 = 86_400;
const RSA_BITS: usize = 2048;
const AGENT_DEVICE_AUTHORIZATION_TTL_SECONDS: i64 = 10 * 60;
const AGENT_DEVICE_POLL_INTERVAL_SECONDS: u32 = 5;
const AGENT_DEVICE_CODE_BYTES: usize = 32;
const PROXY_ENTRY_ONLINE_WINDOW_SECONDS: i64 = 90;
const AGENT_USER_CODE_CHARACTERS: usize = 12;
const AGENT_USER_CODE_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const AGENT_DEVICE_CODE_HASH_DOMAIN: &[u8] = b"ppaass-agent-device-code-v1\0";
const AGENT_USER_CODE_HASH_DOMAIN: &[u8] = b"ppaass-agent-user-code-v1\0";
const PROXY_CONNECT_TCP_PERMISSION: &str = "proxy.connect.tcp";
const PROXY_CONNECT_UDP_PERMISSION: &str = "proxy.connect.udp";
const PROXY_ENTRY_SELECT_PERMISSION: &str = "agent.proxy_entry.select";
const REQUIRED_WEB_USER_PERMISSIONS: [&str; 4] = [
    PROXY_CONNECT_TCP_PERMISSION,
    PROXY_CONNECT_UDP_PERMISSION,
    PRIVATE_KEY_READ_PERMISSION,
    KEY_ROTATE_PERMISSION,
];

#[derive(Clone)]
pub struct AppState {
    pub instance_id: Arc<str>,
    pub users: Arc<dyn UserRepository>,
    pub accounts: Arc<dyn AccountRepository>,
    pub access_logs: Arc<dyn AccessLogRepository>,
    pub device_authorizations: Arc<dyn AgentDeviceAuthorizationRepository>,
    pub proxy_addresses: Arc<dyn ProxyAddressRepository>,
    pub audit_logs: Arc<dyn AuditLogRepository>,
    pub passwords: PasswordService,
    pub sessions: SessionStore,
    pub agent_tokens: AgentAccessTokenService,
    pub agent_events: crate::AgentEventHub,
    pub web_session_handoffs: AgentWebSessionHandoffStore,
    pub private_keys: PrivateKeyCipher,
    pub allow_registration: bool,
}

mod helpers;
mod models;
mod routes;

use base64::Engine;
use helpers::*;
use models::*;
use routes::*;

#[doc(hidden)]
pub fn agent_default_permissions() -> Vec<String> {
    default_web_permissions()
}

#[doc(hidden)]
pub fn include_required_agent_permissions(permissions: Vec<String>) -> Vec<String> {
    with_required_web_permissions(permissions)
}

#[doc(hidden)]
pub fn hash_agent_user_code(value: &str) -> Result<String, ApiError> {
    agent_user_code_hash(value)
}

#[doc(hidden)]
pub fn resolve_assigned_proxy_addresses(
    managed: &ManagedUser,
    account: &WebAccount,
) -> Result<Vec<String>, ApiError> {
    assigned_proxy_addresses(managed, account)
}

pub fn build_router(state: AppState, frontend_dist: Option<PathBuf>) -> Router {
    build_router_with_timeout(
        state,
        frontend_dist,
        Duration::from_secs(REQUEST_TIMEOUT_SECONDS),
    )
}

#[doc(hidden)]
pub fn build_router_with_timeout(
    state: AppState,
    frontend_dist: Option<PathBuf>,
    request_timeout: Duration,
) -> Router {
    let v1 = Router::new()
        .route("/auth/providers", get(get_auth_providers))
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route(
            "/auth/agent-handoff",
            get(consume_agent_web_session_handoff),
        )
        .route("/agent/login", post(agent_login))
        .route("/agent/me", get(get_agent_profile))
        .route("/agent/proxy-entry", put(select_agent_proxy_entry))
        .route("/agent/events", get(get_agent_events))
        .route(
            "/agent/web-session-handoffs",
            post(create_agent_web_session_handoff),
        )
        .route(
            "/agent/device-authorizations",
            post(start_agent_device_authorization),
        )
        .route(
            "/agent/device-authorizations/token",
            post(poll_agent_device_authorization),
        )
        .route(
            "/agent/device-authorizations/inspect",
            post(inspect_agent_device_authorization),
        )
        .route(
            "/agent/device-authorizations/approve",
            post(approve_agent_device_authorization),
        )
        .route(
            "/agent/device-authorizations/deny",
            post(deny_agent_device_authorization),
        )
        .route("/session", get(get_session))
        .route("/me", get(get_me))
        .route(
            "/me/profile",
            put(update_my_profile).layer(DefaultBodyLimit::max(MAX_PROFILE_REQUEST_BODY_BYTES)),
        )
        .route("/me/password", put(change_my_password))
        .route("/me/private-key", get(get_my_private_key))
        .route("/me/rotate-key", post(rotate_my_key))
        .route("/me/key-request", get(get_my_key_request))
        .route("/me/key-requests", post(submit_my_key_request))
        .route("/me/access-records", get(get_my_access_records))
        .route(
            "/admin/users",
            get(admin_list_users).post(admin_create_user),
        )
        .route(
            "/admin/users/{identifier}",
            get(admin_get_user)
                .patch(admin_update_user)
                .delete(admin_delete_user),
        )
        .route(
            "/admin/users/{identifier}/rotate-key",
            post(admin_rotate_key),
        )
        .route("/admin/key-requests", get(admin_list_key_requests))
        .route(
            "/admin/key-requests/{request_id}/approve",
            post(admin_approve_key_request),
        )
        .route(
            "/admin/key-requests/{request_id}/reject",
            post(admin_reject_key_request),
        )
        .route(
            "/admin/access-log-settings",
            get(admin_get_access_log_settings).patch(admin_update_access_log_settings),
        )
        .route(
            "/admin/proxy-addresses",
            get(admin_list_proxy_addresses).post(admin_create_proxy_address),
        )
        .route(
            "/admin/proxy-addresses/{proxy_address_id}",
            axum::routing::patch(admin_update_proxy_address).delete(admin_delete_proxy_address),
        )
        .route("/admin/audit-events", get(admin_list_audit_events))
        .fallback(api_not_found)
        .method_not_allowed_fallback(api_method_not_allowed);

    let api = Router::new()
        .nest("/v1", v1)
        .fallback(api_not_found)
        .method_not_allowed_fallback(api_method_not_allowed);

    let router = Router::new()
        .route("/healthz", get(health))
        .route("/api", any(api_not_found))
        .nest("/api", api)
        .with_state(state);

    let router = match frontend_dist {
        Some(frontend_dist) if frontend_dist.is_dir() => {
            info!(directory = %frontend_dist.display(), "启用 Vue 静态资源托管");
            router.fallback_service(
                ServeDir::new(frontend_dist).append_index_html_on_directories(true),
            )
        }
        Some(frontend_dist) => {
            warn!(
                directory = %frontend_dist.display(),
                "Vue 构建目录不存在，仅启动 API"
            );
            router
        }
        None => router,
    };

    router
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            request_timeout,
        ))
        .layer(TraceLayer::new_for_http().make_span_with(
            |request: &axum::http::Request<axum::body::Body>| {
                // 只记录 path，不把查询参数写入 tracing span，避免设备授权码或
                // 未来新增的一次性敏感参数出现在日志中。
                tracing::debug_span!(
                    "http_request",
                    method = %request.method(),
                    path = %request_path_for_trace(request)
                )
            },
        ))
        .layer(middleware::from_fn(add_security_headers))
}

pub fn request_path_for_trace<B>(request: &axum::http::Request<B>) -> &str {
    request.uri().path()
}

async fn api_not_found() -> ApiError {
    ApiError::not_found("API 路径不存在")
}

async fn api_method_not_allowed() -> ApiError {
    ApiError::method_not_allowed()
}

async fn add_security_headers(request: axum::extract::Request, next: Next) -> Response {
    let request_path = request.uri().path().to_string();
    let is_api = request_path == "/api" || request_path.starts_with("/api/");
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
             font-src 'self' data:; img-src 'self' data:; connect-src 'self'; \
             frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        ),
    );
    headers.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        header::HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    if is_api {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}
