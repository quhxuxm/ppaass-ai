use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{
        ConnectInfo, DefaultBodyLimit, FromRequest, FromRequestParts, Path, Query, State,
        rejection::{BytesRejection, JsonRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get, post, put},
};
use protocol::RsaKeyPair;
use proxy_user_store::{
    AccessLogRepository, AccessProtocol, AccessRecord, AccountRepository, AccountRole,
    AccountStatus, AgentDeviceAuthorization, AgentDeviceAuthorizationClaim,
    AgentDeviceAuthorizationDecision, AgentDeviceAuthorizationFinalize,
    AgentDeviceAuthorizationPoll, AgentDeviceAuthorizationRepository,
    AgentDeviceAuthorizationStatus, ApprovedKeyMaterial, ExternalIdentity, KeyGenerationRequest,
    KeyPairRotation, KeyRequestApproval, KeyRequestKind, KeyRequestStatus,
    MAX_ACCESS_LOG_QUERY_LIMIT, MAX_ACCESS_LOG_RETENTION_DAYS, MIN_ACCESS_LOG_RETENTION_DAYS,
    ManagedUser, ManagedUserUpdate, NewAgentDeviceAuthorization, NewKeyGenerationRequest,
    NewManagedUser, NewUser, NewUserAccount, UserOrigin, UserRecord, UserRepository,
    UserRepositoryError, UserUpdate, WebAccount, normalize_username, parse_expires_at,
};
use rand::RngExt;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::{convert::Infallible, future, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tower_http::{services::ServeDir, timeout::TimeoutLayer, trace::TraceLayer};
use tracing::{info, instrument, warn};
use zeroize::Zeroizing;

use crate::{
    agent_tokens::AgentAccessTokenService,
    auth::{AuthenticatedSession, PasswordService, SessionStore, append_set_cookie, random_token},
    error::ApiError,
    rate_limit::{AgentDeviceAuthorizationGuard, DeviceAuthorizationEndpoint},
    secrets::PrivateKeyCipher,
};

const MAX_REQUEST_BODY_BYTES: usize = 32 * 1024;
#[cfg(not(test))]
const REQUEST_TIMEOUT_SECONDS: u64 = 30;
// Parallel API tests intentionally exercise several real 2048-bit RSA key generations.
// Give those CPU-bound test requests enough time on smaller CI runners without weakening
// the production request deadline.
#[cfg(test)]
const REQUEST_TIMEOUT_SECONDS: u64 = 180;
const MAX_AGENT_PRIVATE_KEY_BYTES: usize = 16 * 1024;
const MAX_AGENT_TOKEN_RESPONSE_BYTES: usize = 32 * 1024;
const DEFAULT_ACCESS_RECORD_LIMIT: u32 = 100;
const SECONDS_PER_DAY: i64 = 86_400;
const RSA_BITS: usize = 2048;
const AGENT_DEVICE_AUTHORIZATION_TTL_SECONDS: i64 = 10 * 60;
const AGENT_DEVICE_POLL_INTERVAL_SECONDS: u32 = 5;
const AGENT_DEVICE_CODE_BYTES: usize = 32;
const AGENT_USER_CODE_CHARACTERS: usize = 12;
const AGENT_USER_CODE_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const AGENT_DEVICE_CODE_HASH_DOMAIN: &[u8] = b"ppaass-agent-device-code-v1\0";
const AGENT_USER_CODE_HASH_DOMAIN: &[u8] = b"ppaass-agent-user-code-v1\0";
const PRIVATE_KEY_READ_PERMISSION: &str = "key.private.read";
const KEY_ROTATE_PERMISSION: &str = "key.rotate";
const PROXY_CONNECT_TCP_PERMISSION: &str = "proxy.connect.tcp";
const PROXY_CONNECT_UDP_PERMISSION: &str = "proxy.connect.udp";
const REQUIRED_WEB_USER_PERMISSIONS: [&str; 4] = [
    PROXY_CONNECT_TCP_PERMISSION,
    PROXY_CONNECT_UDP_PERMISSION,
    PRIVATE_KEY_READ_PERMISSION,
    KEY_ROTATE_PERMISSION,
];

#[derive(Clone)]
pub struct AppState {
    pub users: Arc<dyn UserRepository>,
    pub accounts: Arc<dyn AccountRepository>,
    pub access_logs: Arc<dyn AccessLogRepository>,
    pub device_authorizations: Arc<dyn AgentDeviceAuthorizationRepository>,
    pub passwords: PasswordService,
    pub sessions: SessionStore,
    pub agent_tokens: AgentAccessTokenService,
    pub private_keys: PrivateKeyCipher,
    pub proxy_identity_public_key_pem: Arc<str>,
    pub allow_registration: bool,
    pub device_authorization_guard: AgentDeviceAuthorizationGuard,
}

struct OptionalPeerAddress(Option<SocketAddr>);

impl<S> FromRequestParts<S> for OptionalPeerAddress
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let address = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(address)| *address);
        future::ready(Ok(Self(address)))
    }
}

mod helpers;
mod models;
mod routes;

use base64::Engine;
use helpers::*;
use models::*;
use routes::*;

pub fn build_router(state: AppState, frontend_dist: Option<PathBuf>) -> Router {
    let v1 = Router::new()
        .route("/auth/providers", get(get_auth_providers))
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/agent/login", post(agent_login))
        .route("/agent/me", get(get_agent_profile))
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
            Duration::from_secs(REQUEST_TIMEOUT_SECONDS),
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

fn request_path_for_trace<B>(request: &axum::http::Request<B>) -> &str {
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

#[cfg(test)]
mod tests;
