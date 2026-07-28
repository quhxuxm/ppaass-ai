use axum::{
    Json, Router,
    extract::{
        ConnectInfo, DefaultBodyLimit, FromRequestParts, Path, Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get, post},
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

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

#[derive(Debug, Serialize)]
struct ProvidersResponse {
    local_registration: bool,
}

#[derive(Debug, Serialize)]
struct SessionResponse {
    authenticated: bool,
    account: Option<WebAccount>,
    csrf_token: Option<String>,
    expires_at: Option<i64>,
}

#[derive(Debug, Serialize)]
struct AuthenticationResponse {
    account: WebAccount,
    csrf_token: String,
    session_expires_at: i64,
}

#[derive(Serialize)]
struct AgentDeviceAuthorizationStartResponse {
    device_code: String,
    user_code: String,
    verification_uri: &'static str,
    verification_uri_complete: String,
    expires_in: i64,
    interval: u32,
}

#[derive(Debug, Serialize)]
struct AgentDeviceAuthorizationInspectionResponse {
    client_name: String,
    platform: String,
    expires_at: i64,
    status: AgentDeviceAuthorizationStatus,
}

#[derive(Debug, Serialize)]
struct AgentDeviceAuthorizationDecisionResponse {
    status: AgentDeviceAuthorizationStatus,
}

#[derive(Serialize)]
struct AgentDeviceTokenResponse {
    account: WebAccount,
    profile: AgentDeviceProfileResponse,
    public_key_pem: String,
    proxy_identity_public_key_pem: Arc<str>,
    #[serde(serialize_with = "serialize_zeroizing_string")]
    private_key_pem: Zeroizing<String>,
    csrf_token: String,
    session_expires_at: i64,
}

#[derive(Debug, Serialize)]
struct AgentDeviceProfileResponse {
    username: String,
    permissions: Vec<String>,
    key_version: i64,
    expires_at: Option<i64>,
}

#[derive(Debug, Serialize)]
struct MeResponse {
    account: WebAccount,
    profile: Option<MeProfileResponse>,
    key_state: KeyState,
    pending_request: Option<SelfKeyRequestResponse>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum KeyState {
    Missing,
    Active,
    Expired,
    Disabled,
}

#[derive(Debug, Serialize)]
struct MeProfileResponse {
    username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key_pem: Option<String>,
    permissions: Vec<String>,
    enabled: bool,
    origin: UserOrigin,
    key_version: i64,
    expires_at: Option<i64>,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Serialize)]
struct SelfKeyRequestResponse {
    request_id: String,
    kind: KeyRequestKind,
    status: KeyRequestStatus,
    requested_at: i64,
    reviewed_at: Option<i64>,
    approved_expires_at: Option<i64>,
}

#[derive(Debug, Serialize)]
struct MyKeyRequestResponse {
    request: Option<SelfKeyRequestResponse>,
}

#[derive(Debug, Serialize)]
struct AdminKeyRequestResponse {
    request_id: String,
    account: WebAccount,
    kind: KeyRequestKind,
    status: KeyRequestStatus,
    expected_key_version: Option<i64>,
    reviewer_account_id: Option<String>,
    requested_at: i64,
    reviewed_at: Option<i64>,
    approved_expires_at: Option<i64>,
}

#[derive(Debug, Serialize)]
struct AdminKeyRequestsResponse {
    requests: Vec<AdminKeyRequestResponse>,
}

#[derive(Debug, Serialize)]
struct AdminKeyRequestDecisionResponse {
    request: AdminKeyRequestResponse,
    user: Option<AdminManagedUserResponse>,
}

#[derive(Debug, Serialize)]
struct AccessRecordsResponse {
    records: Vec<AccessRecordResponse>,
    retention_days: u16,
}

#[derive(Debug, Serialize)]
struct AccessRecordResponse {
    target_host: String,
    target_port: u16,
    protocol: AccessProtocol,
    access_count: u64,
    accessed_at: i64,
}

#[derive(Debug, Serialize)]
struct AccessLogSettingsResponse {
    retention_days: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    purged_records: Option<u64>,
}

#[derive(Debug, Serialize)]
struct ManagedUsersResponse {
    users: Vec<AdminManagedUserResponse>,
}

/// 管理员专用的用户视图。这里故意不复用 `UserRecord`，避免未来给
/// `UserRecord` 增加字段时意外把密钥材料暴露到管理员 API。
#[derive(Debug, Serialize)]
struct AdminManagedUserResponse {
    account: Option<WebAccount>,
    profile: Option<AdminUserProfileResponse>,
    has_private_key: bool,
    providers: Vec<ExternalIdentity>,
}

#[derive(Debug, Serialize)]
struct AdminUserProfileResponse {
    username: String,
    permissions: Vec<String>,
    enabled: bool,
    origin: UserOrigin,
    key_version: i64,
    expires_at: Option<i64>,
    created_at: i64,
    updated_at: i64,
}

#[derive(Serialize)]
struct PrivateKeyResponse {
    username: String,
    public_key_pem: String,
    proxy_identity_public_key_pem: Arc<str>,
    #[serde(serialize_with = "serialize_zeroizing_string")]
    private_key_pem: Zeroizing<String>,
    key_version: i64,
}

#[derive(Debug, Serialize)]
struct CreatedManagedUserResponse {
    user: AdminManagedUserResponse,
}

#[derive(Debug, Serialize)]
struct AdminKeyRotationResponse {
    user: AdminManagedUserResponse,
    key_version: i64,
}

impl From<ManagedUser> for AdminManagedUserResponse {
    fn from(user: ManagedUser) -> Self {
        Self {
            account: user.account,
            profile: user.profile.map(AdminUserProfileResponse::from),
            has_private_key: user.has_private_key,
            providers: user.providers,
        }
    }
}

impl From<UserRecord> for AdminUserProfileResponse {
    fn from(profile: UserRecord) -> Self {
        let UserRecord {
            username,
            public_key_pem: _,
            permissions,
            enabled,
            origin,
            key_version,
            expires_at,
            created_at,
            updated_at,
        } = profile;
        Self {
            username,
            permissions,
            enabled,
            origin,
            key_version,
            expires_at,
            created_at,
            updated_at,
        }
    }
}

impl SelfKeyRequestResponse {
    fn from_request(request: KeyGenerationRequest) -> Self {
        Self {
            request_id: request.request_id,
            kind: request.kind,
            status: request.status,
            requested_at: request.requested_at,
            reviewed_at: request.reviewed_at,
            approved_expires_at: request.approved_expires_at,
        }
    }
}

impl From<AccessRecord> for AccessRecordResponse {
    fn from(record: AccessRecord) -> Self {
        Self {
            target_host: record.target_host,
            target_port: record.target_port,
            protocol: record.protocol,
            access_count: record.access_count,
            accessed_at: record.accessed_at,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordLoginRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationRequest {
    username: String,
    password: String,
    #[serde(default)]
    display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentDeviceAuthorizationStartRequest {
    platform: String,
    #[serde(default)]
    client_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentUserCodeRequest {
    user_code: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentDeviceTokenRequest {
    device_code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminCreateUserRequest {
    username: String,
    password: String,
    #[serde(default)]
    display_name: Option<String>,
    expires_at: ExpiresAtValue,
    #[serde(default)]
    permissions: Option<Vec<String>>,
    #[serde(default = "enabled_by_default")]
    enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminUpdateUserRequest {
    #[serde(default)]
    role: Option<AccountRole>,
    #[serde(default)]
    status: Option<AccountStatus>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    permissions: Option<Vec<String>>,
    #[serde(default)]
    expires_at: PatchField<ExpiresAtValue>,
    #[serde(default)]
    display_name: PatchField<String>,
    #[serde(default)]
    email: PatchField<String>,
    #[serde(default)]
    avatar_url: PatchField<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveKeyRequest {
    expires_at: ExpiresAtValue,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessRecordsQuery {
    #[serde(default)]
    since: Option<i64>,
    #[serde(default = "default_access_record_limit")]
    limit: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateAccessLogSettingsRequest {
    retention_days: u16,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ExpiresAtValue {
    String(String),
    Timestamp(i64),
}

#[derive(Debug, Default)]
enum PatchField<T> {
    #[default]
    Missing,
    Null,
    Value(T),
}

impl<'de, T> Deserialize<'de> for PatchField<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(match Option::<T>::deserialize(deserializer)? {
            Some(value) => Self::Value(value),
            None => Self::Null,
        })
    }
}

pub fn build_router(state: AppState, frontend_dist: Option<PathBuf>) -> Router {
    let v1 = Router::new()
        .route("/auth/providers", get(get_auth_providers))
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
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

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn get_auth_providers(State(state): State<AppState>) -> Json<ProvidersResponse> {
    Json(ProvidersResponse {
        local_registration: state.allow_registration,
    })
}

#[instrument(skip(state, headers, payload))]
async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    OptionalPeerAddress(peer): OptionalPeerAddress,
    payload: Result<Json<RegistrationRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    validate_browser_mutation(&headers)?;
    if !state.allow_registration {
        return Err(ApiError::forbidden("普通用户注册未启用"));
    }
    let Json(request) = payload.map_err(ApiError::from_json_rejection)?;
    let _permit = state.device_authorization_guard.enter(
        DeviceAuthorizationEndpoint::Registration,
        &headers,
        peer,
    )?;
    let username = normalize_username(&request.username)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let password_hash = state
        .passwords
        .hash_password(request.password)
        .await
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let account = state
        .accounts
        .create_user_account(NewUserAccount {
            account_id: new_account_id(),
            login_name: username.clone(),
            password_hash: Some(password_hash),
            display_name: trim_optional(request.display_name),
            email: None,
            avatar_url: None,
            external_identity: None,
        })
        .await?;
    info!(
        account_id = account.account_id,
        username, "普通用户账号注册成功，等待提交密钥申请"
    );
    finish_login(&state, account).await
}

#[instrument(skip(state, headers, payload))]
async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    OptionalPeerAddress(peer): OptionalPeerAddress,
    payload: Result<Json<PasswordLoginRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    validate_browser_mutation(&headers)?;
    let Json(request) = payload.map_err(ApiError::from_json_rejection)?;
    let normalized_login_name = normalize_username(&request.username).ok();
    let _permit = state.device_authorization_guard.enter_login(
        &headers,
        peer,
        normalized_login_name
            .as_deref()
            .unwrap_or("<invalid-login-name>"),
    )?;
    let record = match normalized_login_name {
        Some(login_name) => state.accounts.get_login_record(&login_name).await?,
        None => None,
    };
    let password_hash = record
        .as_ref()
        .and_then(|record| record.password_hash.clone());
    let valid = state
        .passwords
        .verify_password(request.password, password_hash)
        .await
        .map_err(|_| ApiError::internal())?;
    let Some(record) = record.filter(|_| valid) else {
        return Err(ApiError::invalid_credentials());
    };
    if record.account.status != AccountStatus::Active {
        return Err(ApiError::invalid_credentials());
    }
    finish_login(&state, record.account).await
}

async fn finish_login(state: &AppState, account: WebAccount) -> Result<Response, ApiError> {
    let login_time = OffsetDateTime::now_utc().unix_timestamp();
    state
        .accounts
        .update_last_login(&account.account_id, login_time)
        .await?;
    let (session, cookie) = state.sessions.issue(&account.account_id);
    let mut response = Json(AuthenticationResponse {
        account,
        csrf_token: session.csrf_token,
        session_expires_at: session.expires_at,
    })
    .into_response();
    append_set_cookie(response.headers_mut(), cookie);
    Ok(response)
}

#[instrument(skip(state, headers))]
async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    validate_browser_mutation(&headers)?;
    let session = state
        .sessions
        .authenticate(state.accounts.as_ref(), &headers)
        .await?;
    state.sessions.require_csrf(&session, &headers)?;
    let cookie = state.sessions.clear(&headers);
    let mut response = StatusCode::NO_CONTENT.into_response();
    append_set_cookie(response.headers_mut(), cookie);
    Ok(response)
}

async fn get_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let response = match state
        .sessions
        .authenticate(state.accounts.as_ref(), &headers)
        .await
    {
        Ok(session) => SessionResponse {
            authenticated: true,
            account: Some(session.account),
            csrf_token: Some(session.csrf_token),
            expires_at: Some(session.expires_at),
        },
        Err(error) if error.is_unauthorized() => SessionResponse {
            authenticated: false,
            account: None,
            csrf_token: None,
            expires_at: None,
        },
        Err(error) => return Err(error),
    };
    Ok(Json(response).into_response())
}

#[instrument(skip(state, headers, payload))]
async fn start_agent_device_authorization(
    State(state): State<AppState>,
    OptionalPeerAddress(peer): OptionalPeerAddress,
    headers: HeaderMap,
    payload: Result<Json<AgentDeviceAuthorizationStartRequest>, JsonRejection>,
) -> Result<Json<AgentDeviceAuthorizationStartResponse>, ApiError> {
    validate_native_agent_request(&headers)?;
    let _permit = state.device_authorization_guard.enter(
        DeviceAuthorizationEndpoint::Start,
        &headers,
        peer,
    )?;
    let Json(request) = payload.map_err(ApiError::from_json_rejection)?;
    let platform = normalize_agent_platform(&request.platform)?;
    let client_name = request
        .client_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| match platform.as_str() {
            "android" => "PPAASS Android Agent".to_string(),
            "windows" => "PPAASS Windows Agent".to_string(),
            _ => unreachable!("平台已在上方校验"),
        });
    let created_at = current_timestamp();
    let expires_at = created_at.saturating_add(AGENT_DEVICE_AUTHORIZATION_TTL_SECONDS);

    for _ in 0..3 {
        let device_code = random_token(AGENT_DEVICE_CODE_BYTES);
        let user_code = generate_agent_user_code();
        let create = state
            .device_authorizations
            .create_agent_device_authorization(NewAgentDeviceAuthorization {
                device_code_hash: hash_agent_code(
                    AGENT_DEVICE_CODE_HASH_DOMAIN,
                    device_code.as_bytes(),
                ),
                user_code_hash: hash_agent_code(
                    AGENT_USER_CODE_HASH_DOMAIN,
                    canonical_agent_user_code(&user_code)?.as_bytes(),
                ),
                client_name: client_name.clone(),
                platform: platform.clone(),
                created_at,
                expires_at,
            })
            .await;
        match create {
            Ok(()) => {
                return Ok(Json(AgentDeviceAuthorizationStartResponse {
                    device_code,
                    user_code: user_code.clone(),
                    verification_uri: "/#agent-authorize",
                    verification_uri_complete: format!("/#agent-authorize={user_code}"),
                    expires_in: AGENT_DEVICE_AUTHORIZATION_TTL_SECONDS,
                    interval: AGENT_DEVICE_POLL_INTERVAL_SECONDS,
                }));
            }
            Err(UserRepositoryError::AgentDeviceAuthorizationConflict) => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(ApiError::internal())
}

#[instrument(skip(state, headers, payload))]
async fn inspect_agent_device_authorization(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<AgentUserCodeRequest>, JsonRejection>,
) -> Result<Json<AgentDeviceAuthorizationInspectionResponse>, ApiError> {
    validate_browser_mutation(&headers)?;
    let session = authenticate(&state, &headers).await?;
    state.sessions.require_csrf(&session, &headers)?;
    require_agent_user_account(&session.account)?;
    let Json(request) = payload.map_err(ApiError::from_json_rejection)?;
    let user_code_hash = agent_user_code_hash(&request.user_code)?;
    let authorization = state
        .device_authorizations
        .get_agent_device_authorization_by_user_code(&user_code_hash, current_timestamp())
        .await?
        .ok_or_else(|| ApiError::not_found("设备授权码无效"))?;
    ensure_visible_agent_authorization(&authorization, &session.account)?;
    Ok(Json(AgentDeviceAuthorizationInspectionResponse {
        client_name: authorization.client_name,
        platform: authorization.platform,
        expires_at: authorization.expires_at,
        status: authorization.status,
    }))
}

#[instrument(skip(state, headers, payload))]
async fn approve_agent_device_authorization(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<AgentUserCodeRequest>, JsonRejection>,
) -> Result<Json<AgentDeviceAuthorizationDecisionResponse>, ApiError> {
    validate_browser_mutation(&headers)?;
    let session = authenticate(&state, &headers).await?;
    state.sessions.require_csrf(&session, &headers)?;
    require_agent_user_account(&session.account)?;
    let Json(request) = payload.map_err(ApiError::from_json_rejection)?;
    let user_code_hash = agent_user_code_hash(&request.user_code)?;
    let authorization = state
        .device_authorizations
        .get_agent_device_authorization_by_user_code(&user_code_hash, current_timestamp())
        .await?
        .ok_or_else(|| ApiError::not_found("设备授权码无效"))?;
    ensure_visible_agent_authorization(&authorization, &session.account)?;
    // 在 challenge 进入 authorized 之前验证当前密钥可解密，避免 Agent 领取到
    // 一个已知不可用的授权。
    let (_profile, private_key) = load_agent_credentials(&state, &session.account).await?;
    drop(private_key);

    let decision = state
        .device_authorizations
        .authorize_agent_device(
            &user_code_hash,
            &session.account.account_id,
            session.account.auth_version,
            current_timestamp(),
        )
        .await?;
    match decision {
        AgentDeviceAuthorizationDecision::Authorized
        | AgentDeviceAuthorizationDecision::AlreadyAuthorized => {
            info!(
                account_id = session.account.account_id,
                "用户批准 Agent 设备登录"
            );
            Ok(Json(AgentDeviceAuthorizationDecisionResponse {
                status: AgentDeviceAuthorizationStatus::Authorized,
            }))
        }
        AgentDeviceAuthorizationDecision::Expired => Err(agent_device_expired_error()),
        AgentDeviceAuthorizationDecision::Denied
        | AgentDeviceAuthorizationDecision::AlreadyDenied => Err(ApiError::conflict(
            "device_authorization_denied",
            "该设备登录已被拒绝",
        )),
        AgentDeviceAuthorizationDecision::Finalized => Err(ApiError::conflict(
            "device_authorization_finalized",
            "该设备登录已完成，不能重复授权",
        )),
        AgentDeviceAuthorizationDecision::NotFound => Err(ApiError::not_found("设备授权码无效")),
    }
}

#[instrument(skip(state, headers, payload))]
async fn deny_agent_device_authorization(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<AgentUserCodeRequest>, JsonRejection>,
) -> Result<Json<AgentDeviceAuthorizationDecisionResponse>, ApiError> {
    validate_browser_mutation(&headers)?;
    let session = authenticate(&state, &headers).await?;
    state.sessions.require_csrf(&session, &headers)?;
    require_agent_user_account(&session.account)?;
    let Json(request) = payload.map_err(ApiError::from_json_rejection)?;
    let decision = state
        .device_authorizations
        .deny_agent_device(
            &agent_user_code_hash(&request.user_code)?,
            &session.account.account_id,
            current_timestamp(),
        )
        .await?;
    match decision {
        AgentDeviceAuthorizationDecision::Denied
        | AgentDeviceAuthorizationDecision::AlreadyDenied => {
            info!(
                account_id = session.account.account_id,
                "用户拒绝 Agent 设备登录"
            );
            Ok(Json(AgentDeviceAuthorizationDecisionResponse {
                status: AgentDeviceAuthorizationStatus::Denied,
            }))
        }
        AgentDeviceAuthorizationDecision::Expired => Err(agent_device_expired_error()),
        AgentDeviceAuthorizationDecision::Authorized
        | AgentDeviceAuthorizationDecision::AlreadyAuthorized => Err(ApiError::conflict(
            "device_authorization_authorized",
            "该设备登录已经获得授权",
        )),
        AgentDeviceAuthorizationDecision::Finalized => Err(ApiError::conflict(
            "device_authorization_finalized",
            "该设备登录已完成，不能重复操作",
        )),
        AgentDeviceAuthorizationDecision::NotFound => Err(ApiError::not_found("设备授权码无效")),
    }
}

#[instrument(skip(state, headers, payload))]
async fn poll_agent_device_authorization(
    State(state): State<AppState>,
    OptionalPeerAddress(peer): OptionalPeerAddress,
    headers: HeaderMap,
    payload: Result<Json<AgentDeviceTokenRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    validate_native_agent_request(&headers)?;
    let _permit = state.device_authorization_guard.enter(
        DeviceAuthorizationEndpoint::Poll,
        &headers,
        peer,
    )?;
    let Json(request) = payload.map_err(ApiError::from_json_rejection)?;
    let device_code_hash = agent_device_code_hash(&request.device_code)?;
    let poll = state
        .device_authorizations
        .poll_agent_device_authorization(
            &device_code_hash,
            current_timestamp(),
            AGENT_DEVICE_POLL_INTERVAL_SECONDS,
        )
        .await?;
    let (account_id, expected_auth_version) = match poll {
        AgentDeviceAuthorizationPoll::Pending {
            retry_after_seconds,
        } => {
            return Err(ApiError::device_authorization_error(
                StatusCode::PRECONDITION_REQUIRED,
                "authorization_pending",
                "等待用户在浏览器中确认",
                Some(retry_after_seconds),
            ));
        }
        AgentDeviceAuthorizationPoll::SlowDown {
            retry_after_seconds,
        } => {
            return Err(ApiError::device_authorization_error(
                StatusCode::TOO_MANY_REQUESTS,
                "slow_down",
                "轮询过于频繁，请按 Retry-After 稍后重试",
                Some(retry_after_seconds),
            ));
        }
        AgentDeviceAuthorizationPoll::Denied => {
            return Err(ApiError::device_authorization_error(
                StatusCode::FORBIDDEN,
                "access_denied",
                "用户拒绝了该设备登录",
                None,
            ));
        }
        AgentDeviceAuthorizationPoll::Expired => return Err(agent_device_expired_error()),
        AgentDeviceAuthorizationPoll::NotFound | AgentDeviceAuthorizationPoll::Consumed => {
            return Err(ApiError::device_authorization_error(
                StatusCode::BAD_REQUEST,
                "invalid_device_code",
                "设备码无效或已被使用",
                None,
            ));
        }
        AgentDeviceAuthorizationPoll::Authorized {
            account_id,
            account_auth_version,
        } => (account_id, account_auth_version),
    };

    let account = state
        .accounts
        .get_account_by_id(&account_id)
        .await?
        .ok_or_else(agent_device_authorization_invalidated)?;
    if account.auth_version != expected_auth_version {
        return Err(agent_device_authorization_invalidated());
    }
    if require_agent_user_account(&account).is_err() {
        return Err(agent_device_authorization_invalidated());
    }
    let (profile, private_key) = load_agent_credentials_for_claim(&state, &account).await?;
    let claim = AgentDeviceAuthorizationClaim {
        device_code_hash,
        account_id: account.account_id.clone(),
        account_auth_version: expected_auth_version,
        username: profile.username.clone(),
        permissions: profile.permissions.clone(),
        key_version: profile.key_version,
        expires_at: profile.expires_at,
        now: current_timestamp(),
    };
    let login_time = current_timestamp();
    state
        .accounts
        .update_last_login(&account.account_id, login_time)
        .await?;
    let (session, cookie) = state.sessions.issue(&account.account_id);
    let response_body = AgentDeviceTokenResponse {
        account,
        profile: AgentDeviceProfileResponse {
            username: profile.username,
            permissions: profile.permissions,
            key_version: profile.key_version,
            expires_at: profile.expires_at,
        },
        public_key_pem: private_key.public_key_pem,
        proxy_identity_public_key_pem: private_key.proxy_identity_public_key_pem,
        private_key_pem: private_key.private_key_pem,
        csrf_token: session.csrf_token.clone(),
        session_expires_at: session.expires_at,
    };
    let mut encoded = match serde_json::to_vec(&response_body) {
        Ok(encoded) => Zeroizing::new(encoded),
        Err(_) => {
            state.sessions.revoke_issued(&session);
            return Err(ApiError::internal());
        }
    };
    if encoded.len() > MAX_AGENT_TOKEN_RESPONSE_BYTES {
        state.sessions.revoke_issued(&session);
        warn!(
            account_id = response_body.account.account_id,
            bytes = encoded.len(),
            "拒绝返回异常大小的 Agent 凭据响应"
        );
        return Err(ApiError::internal());
    }
    let finalize = match state
        .device_authorizations
        .finalize_agent_device_authorization(claim)
        .await
    {
        Ok(finalize) => finalize,
        Err(error) => {
            state.sessions.revoke_issued(&session);
            return Err(error.into());
        }
    };
    match finalize {
        AgentDeviceAuthorizationFinalize::Finalized => {}
        AgentDeviceAuthorizationFinalize::AlreadyFinalized => {
            state.sessions.revoke_issued(&session);
            return Err(ApiError::device_authorization_error(
                StatusCode::BAD_REQUEST,
                "invalid_device_code",
                "设备码无效或已被使用",
                None,
            ));
        }
        AgentDeviceAuthorizationFinalize::Expired => {
            state.sessions.revoke_issued(&session);
            return Err(agent_device_expired_error());
        }
        AgentDeviceAuthorizationFinalize::Invalidated
        | AgentDeviceAuthorizationFinalize::NotFound => {
            state.sessions.revoke_issued(&session);
            return Err(agent_device_authorization_invalidated());
        }
    }
    let encoded = std::mem::take(&mut *encoded);
    let mut response = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        encoded,
    )
        .into_response();
    append_set_cookie(response.headers_mut(), cookie);
    Ok(response)
}

async fn get_me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<MeResponse>, ApiError> {
    let session = authenticate(&state, &headers).await?;
    let managed = state
        .accounts
        .get_managed_user(&session.account.account_id)
        .await?
        .ok_or_else(|| ApiError::not_found("账号不存在"))?;
    let pending_request = state
        .accounts
        .get_pending_key_generation_request(&session.account.account_id)
        .await?
        .map(SelfKeyRequestResponse::from_request);
    let key_state = key_state(&managed, current_timestamp());
    let expose_public_key = key_state == KeyState::Active;
    Ok(Json(MeResponse {
        account: session.account,
        profile: managed
            .profile
            .map(|profile| me_profile_response(profile, expose_public_key)),
        key_state,
        pending_request,
    }))
}

async fn get_my_private_key(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<PrivateKeyResponse>, ApiError> {
    let session = authenticate(&state, &headers).await?;
    let profile = require_active_key_profile(&state, &session.account).await?;
    require_profile_permission(&profile, PRIVATE_KEY_READ_PERMISSION)?;
    Ok(Json(load_private_key(&state, profile).await?))
}

#[instrument(skip(state, headers))]
async fn rotate_my_key(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<PrivateKeyResponse>, ApiError> {
    validate_browser_mutation(&headers)?;
    let session = authenticate(&state, &headers).await?;
    state.sessions.require_csrf(&session, &headers)?;
    let profile = require_active_key_profile(&state, &session.account).await?;
    require_profile_permission(&profile, KEY_ROTATE_PERMISSION)?;
    let response = rotate_profile_key(&state, profile).await?;
    info!(username = response.username, "用户重生成自己的 RSA 密钥");
    Ok(Json(response))
}

async fn get_my_key_request(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<MyKeyRequestResponse>, ApiError> {
    let session = authenticate(&state, &headers).await?;
    let request = state
        .accounts
        .get_pending_key_generation_request(&session.account.account_id)
        .await?
        .map(SelfKeyRequestResponse::from_request);
    Ok(Json(MyKeyRequestResponse { request }))
}

#[instrument(skip(state, headers))]
async fn submit_my_key_request(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    validate_browser_mutation(&headers)?;
    let session = authenticate(&state, &headers).await?;
    state.sessions.require_csrf(&session, &headers)?;

    if let Some(existing) = state
        .accounts
        .get_pending_key_generation_request(&session.account.account_id)
        .await?
    {
        return Ok(Json(SelfKeyRequestResponse::from_request(existing)).into_response());
    }

    let managed = state
        .accounts
        .get_managed_user(&session.account.account_id)
        .await?
        .ok_or_else(|| ApiError::not_found("账号不存在"))?;
    match key_state(&managed, current_timestamp()) {
        KeyState::Active => {
            return Err(ApiError::conflict(
                "key_already_active",
                "现有密钥仍有效，请直接使用自助轮换接口",
            ));
        }
        KeyState::Disabled => {
            return Err(ApiError::forbidden("Proxy 用户已停用，不能申请密钥"));
        }
        KeyState::Missing | KeyState::Expired => {}
    }

    let request = NewKeyGenerationRequest {
        request_id: new_key_request_id(),
        account_id: session.account.account_id.clone(),
    };
    let (status, request) = match state.accounts.submit_key_generation_request(request).await {
        Ok(request) => (StatusCode::CREATED, request),
        Err(UserRepositoryError::PendingKeyRequestConflict { .. }) => {
            let request = state
                .accounts
                .get_pending_key_generation_request(&session.account.account_id)
                .await?
                .ok_or_else(ApiError::internal)?;
            (StatusCode::OK, request)
        }
        Err(error) => return Err(error.into()),
    };
    info!(
        account_id = session.account.account_id,
        request_id = request.request_id,
        kind = request.kind.as_str(),
        "用户提交密钥申请"
    );
    Ok((status, Json(SelfKeyRequestResponse::from_request(request))).into_response())
}

async fn get_my_access_records(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<AccessRecordsQuery>, QueryRejection>,
) -> Result<Json<AccessRecordsResponse>, ApiError> {
    let session = authenticate(&state, &headers).await?;
    let Query(query) = query.map_err(|_| ApiError::bad_request("访问记录查询参数无效"))?;
    if !(1..=MAX_ACCESS_LOG_QUERY_LIMIT).contains(&query.limit) {
        return Err(ApiError::bad_request(format!(
            "limit 必须在 1..={MAX_ACCESS_LOG_QUERY_LIMIT} 之间"
        )));
    }
    let settings = state.access_logs.get_access_log_settings().await?;
    let retention_since = access_log_cutoff(settings.retention_days);
    let since = query.since.unwrap_or(retention_since).max(retention_since);
    let records = match session.account.linked_username.as_deref() {
        Some(username) => state
            .access_logs
            .list_recent_access(username, since, query.limit)
            .await?
            .into_iter()
            .map(AccessRecordResponse::from)
            .collect(),
        None => Vec::new(),
    };
    Ok(Json(AccessRecordsResponse {
        records,
        retention_days: settings.retention_days,
    }))
}

async fn admin_list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ManagedUsersResponse>, ApiError> {
    require_admin(&state, &headers).await?;
    let users = state
        .accounts
        .list_managed_users()
        .await?
        .into_iter()
        .map(AdminManagedUserResponse::from)
        .collect();
    Ok(Json(ManagedUsersResponse { users }))
}

async fn admin_get_user(
    State(state): State<AppState>,
    Path(identifier): Path<String>,
    headers: HeaderMap,
) -> Result<Json<AdminManagedUserResponse>, ApiError> {
    require_admin(&state, &headers).await?;
    Ok(Json(
        resolve_managed_user(&state, &identifier).await?.into(),
    ))
}

#[instrument(skip(state, headers, payload))]
async fn admin_create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<AdminCreateUserRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    validate_browser_mutation(&headers)?;
    let session = require_admin(&state, &headers).await?;
    state.sessions.require_csrf(&session, &headers)?;
    let Json(request) = payload.map_err(ApiError::from_json_rejection)?;
    let username = normalize_username(&request.username)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let expires_at = parse_future_expiration(request.expires_at, &username)?;
    let password_hash = state
        .passwords
        .hash_password(request.password)
        .await
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let generated = generate_initial_stored_keys(&state, &username).await?;
    let permissions = with_required_web_permissions(request.permissions.unwrap_or_default());
    let managed = state
        .accounts
        .create_managed_user(NewManagedUser {
            account_id: new_account_id(),
            login_name: username.clone(),
            password_hash: Some(password_hash),
            role: AccountRole::User,
            status: AccountStatus::Active,
            display_name: trim_optional(request.display_name),
            email: None,
            avatar_url: None,
            profile: NewUser {
                username: username.clone(),
                public_key_pem: generated.public_key_pem,
                permissions,
                enabled: request.enabled,
                origin: UserOrigin::Admin,
                expires_at: Some(expires_at),
            },
            encrypted_private_key: generated.encrypted_private_key,
            external_identity: None,
        })
        .await?;
    info!(
        admin_account_id = session.account.account_id,
        username, "管理员创建普通用户并生成 RSA 密钥"
    );
    Ok((
        StatusCode::CREATED,
        Json(CreatedManagedUserResponse {
            user: managed.into(),
        }),
    )
        .into_response())
}

#[instrument(skip(state, headers, payload), fields(identifier))]
async fn admin_update_user(
    State(state): State<AppState>,
    Path(identifier): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<AdminUpdateUserRequest>, JsonRejection>,
) -> Result<Json<AdminManagedUserResponse>, ApiError> {
    validate_browser_mutation(&headers)?;
    let session = require_admin(&state, &headers).await?;
    state.sessions.require_csrf(&session, &headers)?;
    let Json(request) = payload.map_err(ApiError::from_json_rejection)?;
    let managed = resolve_managed_user(&state, &identifier).await?;

    let expires_at = match request.expires_at {
        PatchField::Missing => None,
        PatchField::Null => Some(None),
        PatchField::Value(value) => {
            let username = managed
                .profile
                .as_ref()
                .map(|profile| profile.username.as_str())
                .unwrap_or(&identifier);
            Some(Some(value.parse(username)?))
        }
    };
    let mut update = ManagedUserUpdate {
        role: request.role,
        status: request.status,
        enabled: request.enabled,
        permissions: request.permissions,
        expires_at,
        display_name: patch_optional(request.display_name),
        email: patch_optional(request.email),
        avatar_url: patch_optional(request.avatar_url),
    };
    // Web 托管账号的四项基础能力是不可撤销的；历史导入 profile 没有
    // Web 账号和可恢复私钥，必须保留其原始权限语义。
    if managed.account.is_some() {
        if update.expires_at == Some(None) {
            return Err(ApiError::bad_request(
                "Web 用户的 expires_at 不能清空；请设置明确的过期时间",
            ));
        }
        if let Some(target_expires_at) = update.expires_at
            && match managed.profile.as_ref() {
                None => true,
                Some(profile) => {
                    let timestamp = current_timestamp();
                    let currently_expired = profile
                        .expires_at
                        .is_some_and(|expires_at| expires_at <= timestamp);
                    let target_is_unexpired =
                        target_expires_at.is_none_or(|expires_at| expires_at > timestamp);
                    currently_expired && target_is_unexpired
                }
            }
        {
            return Err(ApiError::conflict(
                "key_request_required",
                "不能通过修改有效期恢复旧密钥，请由用户提交密钥申请并审批",
            ));
        }
        update.permissions = update.permissions.map(with_required_web_permissions);
    }
    if update.is_empty() {
        return Err(ApiError::bad_request("至少提供一个需要修改的字段"));
    }

    let updated = if let Some(account) = managed.account {
        state
            .accounts
            .update_managed_user(&account.account_id, update)
            .await?
    } else {
        if update.role.is_some()
            || update.status.is_some()
            || update.display_name.is_some()
            || update.email.is_some()
            || update.avatar_url.is_some()
        {
            return Err(ApiError::bad_request(
                "历史 legacy 用户尚未绑定 Web 账号，不能修改账号字段",
            ));
        }
        let profile = managed
            .profile
            .ok_or_else(|| ApiError::not_found("用户不存在"))?;
        let profile = state
            .users
            .update_user(
                &profile.username,
                UserUpdate {
                    public_key_pem: None,
                    permissions: update.permissions,
                    enabled: update.enabled,
                    expires_at: update.expires_at,
                },
            )
            .await?;
        ManagedUser {
            account: None,
            profile: Some(profile),
            has_private_key: false,
            providers: Vec::new(),
        }
    };
    info!(
        admin_account_id = session.account.account_id,
        identifier, "管理员更新用户"
    );
    Ok(Json(updated.into()))
}

#[instrument(skip(state, headers), fields(identifier))]
async fn admin_delete_user(
    State(state): State<AppState>,
    Path(identifier): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    validate_browser_mutation(&headers)?;
    let session = require_admin(&state, &headers).await?;
    state.sessions.require_csrf(&session, &headers)?;
    let managed = resolve_managed_user(&state, &identifier).await?;
    if let Some(account) = managed.account {
        state
            .accounts
            .delete_managed_user(&account.account_id)
            .await?;
    } else if let Some(profile) = managed.profile {
        state.users.delete_user(&profile.username).await?;
    } else {
        return Err(ApiError::not_found("用户不存在"));
    }
    info!(
        admin_account_id = session.account.account_id,
        identifier, "管理员删除用户"
    );
    Ok(StatusCode::NO_CONTENT)
}

#[instrument(skip(state, headers), fields(identifier))]
async fn admin_rotate_key(
    State(state): State<AppState>,
    Path(identifier): Path<String>,
    headers: HeaderMap,
) -> Result<Json<AdminKeyRotationResponse>, ApiError> {
    validate_browser_mutation(&headers)?;
    let session = require_admin(&state, &headers).await?;
    state.sessions.require_csrf(&session, &headers)?;
    let mut managed = resolve_managed_user(&state, &identifier).await?;
    if managed.account.is_none() {
        return Err(ApiError::bad_request(
            "legacy 用户没有可登录的 Web 账号，不能生成无人可领取的密钥",
        ));
    }
    match key_state(&managed, current_timestamp()) {
        KeyState::Active => {}
        KeyState::Disabled => {
            return Err(ApiError::forbidden("Proxy 用户已停用，不能轮换密钥"));
        }
        KeyState::Missing | KeyState::Expired => {
            return Err(ApiError::conflict(
                "key_request_required",
                "该用户需要先提交密钥申请并由管理员审批",
            ));
        }
    }
    let profile = managed
        .profile
        .take()
        .ok_or_else(|| ApiError::not_found("该账号没有 Proxy 用户配置"))?;
    let updated_profile = rotate_profile_key_for_admin(&state, profile).await?;
    let key_version = updated_profile.key_version;
    info!(
        admin_account_id = session.account.account_id,
        username = updated_profile.username,
        "管理员重生成用户 RSA 密钥"
    );
    managed.profile = Some(updated_profile);
    managed.has_private_key = true;
    Ok(Json(AdminKeyRotationResponse {
        user: managed.into(),
        key_version,
    }))
}

async fn admin_list_key_requests(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AdminKeyRequestsResponse>, ApiError> {
    require_admin(&state, &headers).await?;
    let requests = state
        .accounts
        .list_pending_key_generation_requests()
        .await?;
    let mut responses = Vec::with_capacity(requests.len());
    for request in requests {
        responses.push(admin_key_request_response(&state, request).await?);
    }
    Ok(Json(AdminKeyRequestsResponse {
        requests: responses,
    }))
}

#[instrument(skip(state, headers, payload), fields(request_id))]
async fn admin_approve_key_request(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
    headers: HeaderMap,
    payload: Result<Json<ApproveKeyRequest>, JsonRejection>,
) -> Result<Json<AdminKeyRequestDecisionResponse>, ApiError> {
    validate_browser_mutation(&headers)?;
    let session = require_admin(&state, &headers).await?;
    state.sessions.require_csrf(&session, &headers)?;
    let Json(payload) = payload.map_err(ApiError::from_json_rejection)?;
    let expires_at = parse_future_expiration(payload.expires_at, "key-request")?;
    let request = state
        .accounts
        .get_key_generation_request(&request_id)
        .await?
        .ok_or_else(|| UserRepositoryError::KeyRequestNotFound(request_id.clone()))?;
    if request.status != KeyRequestStatus::Pending {
        return Err(UserRepositoryError::KeyRequestAlreadyReviewed {
            request_id,
            status: request.status,
        }
        .into());
    }

    let managed = state
        .accounts
        .get_managed_user(&request.account_id)
        .await?
        .ok_or_else(|| ApiError::not_found("申请账号不存在"))?;
    let account = managed.account.as_ref().ok_or_else(ApiError::internal)?;
    let material = approved_key_material(&state, &request, &managed, account, expires_at).await?;
    let result = state
        .accounts
        .approve_key_generation_request(KeyRequestApproval {
            request_id: request.request_id,
            reviewer_account_id: session.account.account_id.clone(),
            expires_at,
            material,
        })
        .await?;
    let request_response = admin_key_request_response(&state, result.request).await?;
    info!(
        admin_account_id = session.account.account_id,
        request_id = request_response.request_id,
        account_id = request_response.account.account_id,
        "管理员批准密钥申请"
    );
    Ok(Json(AdminKeyRequestDecisionResponse {
        request: request_response,
        user: Some(result.managed_user.into()),
    }))
}

#[instrument(skip(state, headers), fields(request_id))]
async fn admin_reject_key_request(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<AdminKeyRequestDecisionResponse>, ApiError> {
    validate_browser_mutation(&headers)?;
    let session = require_admin(&state, &headers).await?;
    state.sessions.require_csrf(&session, &headers)?;
    let request = state
        .accounts
        .reject_key_generation_request(&request_id, &session.account.account_id)
        .await?;
    let request = admin_key_request_response(&state, request).await?;
    info!(
        admin_account_id = session.account.account_id,
        request_id = request.request_id,
        account_id = request.account.account_id,
        "管理员拒绝密钥申请"
    );
    Ok(Json(AdminKeyRequestDecisionResponse {
        request,
        user: None,
    }))
}

async fn admin_get_access_log_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AccessLogSettingsResponse>, ApiError> {
    require_admin(&state, &headers).await?;
    let settings = state.access_logs.get_access_log_settings().await?;
    Ok(Json(AccessLogSettingsResponse {
        retention_days: settings.retention_days,
        purged_records: None,
    }))
}

#[instrument(skip(state, headers, payload))]
async fn admin_update_access_log_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<UpdateAccessLogSettingsRequest>, JsonRejection>,
) -> Result<Json<AccessLogSettingsResponse>, ApiError> {
    validate_browser_mutation(&headers)?;
    let session = require_admin(&state, &headers).await?;
    state.sessions.require_csrf(&session, &headers)?;
    let Json(payload) = payload.map_err(ApiError::from_json_rejection)?;
    if !(MIN_ACCESS_LOG_RETENTION_DAYS..=MAX_ACCESS_LOG_RETENTION_DAYS)
        .contains(&payload.retention_days)
    {
        return Err(ApiError::bad_request(format!(
            "retention_days 必须在 {MIN_ACCESS_LOG_RETENTION_DAYS}..={MAX_ACCESS_LOG_RETENTION_DAYS} 之间"
        )));
    }
    let settings = state
        .access_logs
        .set_access_log_retention_days(payload.retention_days)
        .await?;
    let purged_records = state
        .access_logs
        .purge_access_records_before(access_log_cutoff(settings.retention_days))
        .await?;
    info!(
        admin_account_id = session.account.account_id,
        retention_days = settings.retention_days,
        purged_records,
        "管理员更新访问记录保留期并清理过期记录"
    );
    Ok(Json(AccessLogSettingsResponse {
        retention_days: settings.retention_days,
        purged_records: Some(purged_records),
    }))
}

async fn admin_key_request_response(
    state: &AppState,
    request: KeyGenerationRequest,
) -> Result<AdminKeyRequestResponse, ApiError> {
    let account = state
        .accounts
        .get_account_by_id(&request.account_id)
        .await?
        .ok_or_else(|| ApiError::not_found("密钥申请关联的账号不存在"))?;
    Ok(AdminKeyRequestResponse {
        request_id: request.request_id,
        account,
        kind: request.kind,
        status: request.status,
        expected_key_version: request.expected_key_version,
        reviewer_account_id: request.reviewer_account_id,
        requested_at: request.requested_at,
        reviewed_at: request.reviewed_at,
        approved_expires_at: request.approved_expires_at,
    })
}

async fn approved_key_material(
    state: &AppState,
    request: &KeyGenerationRequest,
    managed: &ManagedUser,
    account: &WebAccount,
    expires_at: i64,
) -> Result<ApprovedKeyMaterial, ApiError> {
    match request.kind {
        KeyRequestKind::Initial => {
            if managed.profile.is_some() || account.linked_username.is_some() {
                return Err(ApiError::conflict(
                    "stale_key_request",
                    "账号已经具备 Proxy 用户配置",
                ));
            }
            let generated =
                generate_stored_keys(&state.private_keys, &account.login_name, 1).await?;
            Ok(ApprovedKeyMaterial::Initial {
                profile: NewUser {
                    username: account.login_name.clone(),
                    public_key_pem: generated.public_key_pem,
                    permissions: default_web_permissions(),
                    enabled: true,
                    origin: initial_user_origin(managed),
                    expires_at: Some(expires_at),
                },
                encrypted_private_key: generated.encrypted_private_key,
            })
        }
        KeyRequestKind::Rotate => {
            let profile = managed
                .profile
                .as_ref()
                .ok_or_else(|| ApiError::conflict("stale_key_request", "Proxy 用户配置不存在"))?;
            if !profile.enabled {
                return Err(ApiError::forbidden("Proxy 用户已停用，不能批准密钥申请"));
            }
            let expected = request
                .expected_key_version
                .ok_or_else(ApiError::internal)?;
            let next_version = expected.checked_add(1).ok_or_else(ApiError::internal)?;
            let generated =
                generate_stored_keys(&state.private_keys, &profile.username, next_version).await?;
            Ok(ApprovedKeyMaterial::Rotate {
                public_key_pem: generated.public_key_pem,
                encrypted_private_key: generated.encrypted_private_key,
            })
        }
    }
}

fn initial_user_origin(managed: &ManagedUser) -> UserOrigin {
    if managed
        .providers
        .iter()
        .any(|identity| identity.provider == "wechat")
    {
        UserOrigin::Wechat
    } else {
        UserOrigin::Local
    }
}

async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedSession, ApiError> {
    state
        .sessions
        .authenticate(state.accounts.as_ref(), headers)
        .await
}

async fn require_admin(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedSession, ApiError> {
    let session = authenticate(state, headers).await?;
    if session.account.role != AccountRole::Admin {
        return Err(ApiError::forbidden("需要管理员权限"));
    }
    Ok(session)
}

async fn require_active_key_profile(
    state: &AppState,
    account: &WebAccount,
) -> Result<UserRecord, ApiError> {
    let managed = state
        .accounts
        .get_managed_user(&account.account_id)
        .await?
        .ok_or_else(|| ApiError::not_found("账号不存在"))?;
    match key_state(&managed, current_timestamp()) {
        KeyState::Active => managed.profile.ok_or_else(ApiError::internal),
        KeyState::Disabled => Err(ApiError::forbidden("Proxy 用户已停用")),
        KeyState::Missing | KeyState::Expired => Err(ApiError::conflict(
            "key_request_required",
            "当前没有可用密钥，请先提交密钥申请",
        )),
    }
}

fn key_state(managed: &ManagedUser, timestamp: i64) -> KeyState {
    let Some(profile) = managed.profile.as_ref() else {
        return KeyState::Missing;
    };
    if !profile.enabled {
        return KeyState::Disabled;
    }
    if profile
        .expires_at
        .is_some_and(|expires_at| expires_at <= timestamp)
    {
        return KeyState::Expired;
    }
    if !managed.has_private_key {
        return KeyState::Missing;
    }
    KeyState::Active
}

fn me_profile_response(profile: UserRecord, expose_public_key: bool) -> MeProfileResponse {
    let UserRecord {
        username,
        public_key_pem,
        permissions,
        enabled,
        origin,
        key_version,
        expires_at,
        created_at,
        updated_at,
    } = profile;
    MeProfileResponse {
        username,
        public_key_pem: expose_public_key.then_some(public_key_pem),
        permissions,
        enabled,
        origin,
        key_version,
        expires_at,
        created_at,
        updated_at,
    }
}

async fn resolve_managed_user(state: &AppState, identifier: &str) -> Result<ManagedUser, ApiError> {
    if let Some(user) = state
        .accounts
        .get_managed_user_by_username(identifier)
        .await?
    {
        return Ok(user);
    }
    if let Some(account) = state.accounts.get_account_by_login(identifier).await? {
        return state
            .accounts
            .get_managed_user(&account.account_id)
            .await?
            .ok_or_else(|| ApiError::not_found("用户不存在"));
    }
    Err(ApiError::not_found("用户不存在"))
}

fn require_profile_permission(profile: &UserRecord, permission: &str) -> Result<(), ApiError> {
    if profile
        .permissions
        .iter()
        .any(|candidate| candidate == permission)
    {
        Ok(())
    } else {
        Err(ApiError::forbidden(format!("缺少权限：{permission}")))
    }
}

async fn load_private_key(
    state: &AppState,
    profile: UserRecord,
) -> Result<PrivateKeyResponse, ApiError> {
    let encrypted = state
        .accounts
        .load_encrypted_private_key(&profile.username)
        .await?
        .ok_or_else(|| ApiError::not_found("该用户没有可恢复的托管私钥，请先重生成密钥"))?;
    if encrypted.key_version != profile.key_version {
        warn!(
            username = profile.username,
            profile_version = profile.key_version,
            private_version = encrypted.key_version,
            "公钥与托管私钥版本不一致"
        );
        return Err(ApiError::internal());
    }
    let private_key_pem = state
        .private_keys
        .decrypt(
            &encrypted.username,
            encrypted.key_version,
            &encrypted.encrypted_private_key,
        )
        .map_err(|error| {
            warn!(username = profile.username, %error, "托管私钥解密失败");
            ApiError::internal()
        })?;
    Ok(PrivateKeyResponse {
        username: profile.username,
        public_key_pem: profile.public_key_pem,
        proxy_identity_public_key_pem: state.proxy_identity_public_key_pem.clone(),
        private_key_pem,
        key_version: profile.key_version,
    })
}

async fn rotate_profile_key(
    state: &AppState,
    profile: UserRecord,
) -> Result<PrivateKeyResponse, ApiError> {
    let next_version = profile
        .key_version
        .checked_add(1)
        .ok_or_else(ApiError::internal)?;
    let GeneratedKeys {
        public_key_pem,
        private_key_pem,
        encrypted_private_key,
    } = generate_keys(&state.private_keys, &profile.username, next_version).await?;
    let updated = state
        .accounts
        .rotate_keypair(KeyPairRotation {
            username: profile.username,
            expected_key_version: profile.key_version,
            public_key_pem,
            encrypted_private_key,
        })
        .await?;
    Ok(PrivateKeyResponse {
        username: updated.username,
        public_key_pem: updated.public_key_pem,
        proxy_identity_public_key_pem: state.proxy_identity_public_key_pem.clone(),
        private_key_pem,
        key_version: updated.key_version,
    })
}

async fn rotate_profile_key_for_admin(
    state: &AppState,
    profile: UserRecord,
) -> Result<UserRecord, ApiError> {
    let next_version = profile
        .key_version
        .checked_add(1)
        .ok_or_else(ApiError::internal)?;
    let generated =
        generate_stored_keys(&state.private_keys, &profile.username, next_version).await?;
    state
        .accounts
        .rotate_keypair(KeyPairRotation {
            username: profile.username,
            expected_key_version: profile.key_version,
            public_key_pem: generated.public_key_pem,
            encrypted_private_key: generated.encrypted_private_key,
        })
        .await
        .map_err(Into::into)
}

async fn generate_initial_stored_keys(
    state: &AppState,
    username: &str,
) -> Result<StoredKeys, ApiError> {
    generate_stored_keys(&state.private_keys, username, 1).await
}

async fn generate_stored_keys(
    cipher: &PrivateKeyCipher,
    username: &str,
    key_version: i64,
) -> Result<StoredKeys, ApiError> {
    let GeneratedKeys {
        public_key_pem,
        private_key_pem,
        encrypted_private_key,
    } = generate_keys(cipher, username, key_version).await?;
    // 管理端只负责生成并托管，明文私钥在入库前立即清零，不进入响应模型。
    drop(private_key_pem);
    Ok(StoredKeys {
        public_key_pem,
        encrypted_private_key,
    })
}

async fn generate_keys(
    cipher: &PrivateKeyCipher,
    username: &str,
    key_version: i64,
) -> Result<GeneratedKeys, ApiError> {
    let raw = tokio::task::spawn_blocking(|| {
        let pair = RsaKeyPair::generate(RSA_BITS).map_err(|_| ApiError::internal())?;
        let public_key_pem = pair.public_key_to_pem().map_err(|_| ApiError::internal())?;
        let private_key_pem = pair
            .private_key_to_pem()
            .map(Zeroizing::new)
            .map_err(|_| ApiError::internal())?;
        Ok::<_, ApiError>((public_key_pem, private_key_pem))
    })
    .await
    .map_err(|_| ApiError::internal())??;
    let encrypted_private_key = cipher
        .encrypt(username, key_version, raw.1.as_str())
        .map_err(|error| {
            warn!(username, %error, "托管私钥加密失败");
            ApiError::internal()
        })?;
    Ok(GeneratedKeys {
        public_key_pem: raw.0,
        private_key_pem: raw.1,
        encrypted_private_key,
    })
}

struct GeneratedKeys {
    public_key_pem: String,
    private_key_pem: Zeroizing<String>,
    encrypted_private_key: Vec<u8>,
}

struct StoredKeys {
    public_key_pem: String,
    encrypted_private_key: Vec<u8>,
}

impl ExpiresAtValue {
    fn parse(self, username: &str) -> Result<i64, ApiError> {
        let timestamp = match self {
            Self::String(value) => parse_expires_at(username, &value),
            Self::Timestamp(value) => parse_expires_at(username, &value.to_string()),
        }
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
        OffsetDateTime::from_unix_timestamp(timestamp)
            .map_err(|_| ApiError::bad_request("expires_at 超出支持的时间范围"))?
            .format(&Rfc3339)
            .map_err(|_| ApiError::bad_request("expires_at 无法表示为 RFC3339 时间"))?;
        Ok(timestamp)
    }
}

fn parse_future_expiration(value: ExpiresAtValue, subject: &str) -> Result<i64, ApiError> {
    let expires_at = value.parse(subject)?;
    let timestamp = current_timestamp();
    if expires_at <= timestamp {
        return Err(ApiError::bad_request(
            "expires_at 必须是严格晚于当前时间的时间点",
        ));
    }
    Ok(expires_at)
}

fn default_web_permissions() -> Vec<String> {
    with_required_web_permissions(Vec::new())
}

fn with_required_web_permissions(mut permissions: Vec<String>) -> Vec<String> {
    permissions.extend(REQUIRED_WEB_USER_PERMISSIONS.map(str::to_string));
    permissions.sort_unstable();
    permissions.dedup();
    permissions
}

fn new_account_id() -> String {
    format!("acc_{}", random_token(24))
}

fn new_key_request_id() -> String {
    format!("keyreq_{}", random_token(24))
}

fn normalize_agent_platform(value: &str) -> Result<String, ApiError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "android" => Ok("android".to_string()),
        "windows" => Ok("windows".to_string()),
        _ => Err(ApiError::bad_request(
            "platform 目前只支持 android 或 windows",
        )),
    }
}

fn generate_agent_user_code() -> String {
    let mut entropy = [0_u8; AGENT_USER_CODE_CHARACTERS];
    rand::rng().fill(&mut entropy);
    let canonical = entropy
        .iter()
        .map(|byte| AGENT_USER_CODE_ALPHABET[usize::from(*byte) % AGENT_USER_CODE_ALPHABET.len()])
        .map(char::from)
        .collect::<String>();
    format!(
        "{}-{}-{}",
        &canonical[0..4],
        &canonical[4..8],
        &canonical[8..12]
    )
}

fn canonical_agent_user_code(value: &str) -> Result<String, ApiError> {
    let canonical = value
        .bytes()
        .filter(|byte| *byte != b'-' && !byte.is_ascii_whitespace())
        .map(|byte| byte.to_ascii_uppercase())
        .collect::<Vec<_>>();
    if canonical.len() != AGENT_USER_CODE_CHARACTERS
        || !canonical
            .iter()
            .all(|byte| AGENT_USER_CODE_ALPHABET.contains(byte))
    {
        return Err(ApiError::bad_request("设备授权短码格式无效"));
    }
    String::from_utf8(canonical).map_err(|_| ApiError::bad_request("设备授权短码格式无效"))
}

fn agent_device_code_hash(value: &str) -> Result<String, ApiError> {
    if value.len() != 43
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ApiError::bad_request("device_code 格式无效"));
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApiError::bad_request("device_code 格式无效"))?;
    if decoded.len() != AGENT_DEVICE_CODE_BYTES
        || base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&decoded) != value
    {
        return Err(ApiError::bad_request("device_code 格式无效"));
    }
    Ok(hash_agent_code(
        AGENT_DEVICE_CODE_HASH_DOMAIN,
        value.as_bytes(),
    ))
}

fn agent_user_code_hash(value: &str) -> Result<String, ApiError> {
    let canonical = canonical_agent_user_code(value)?;
    Ok(hash_agent_code(
        AGENT_USER_CODE_HASH_DOMAIN,
        canonical.as_bytes(),
    ))
}

fn hash_agent_code(domain: &[u8], value: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(value);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.finalize())
}

fn require_agent_user_account(account: &WebAccount) -> Result<(), ApiError> {
    if account.role != AccountRole::User {
        return Err(ApiError::forbidden("管理员账号不能授权 Agent 普通用户登录"));
    }
    if account.status != AccountStatus::Active {
        return Err(ApiError::forbidden("账号已停用"));
    }
    Ok(())
}

async fn load_agent_credentials(
    state: &AppState,
    account: &WebAccount,
) -> Result<(UserRecord, PrivateKeyResponse), ApiError> {
    require_agent_user_account(account)?;
    let profile = require_active_key_profile(state, account).await?;
    require_profile_permission(&profile, PRIVATE_KEY_READ_PERMISSION)?;
    let private_key = load_private_key(state, profile.clone()).await?;
    if private_key.private_key_pem.len() > MAX_AGENT_PRIVATE_KEY_BYTES {
        warn!(
            username = profile.username,
            bytes = private_key.private_key_pem.len(),
            "拒绝返回异常大小的 Agent 私钥"
        );
        return Err(ApiError::internal());
    }
    Ok((profile, private_key))
}

async fn load_agent_credentials_for_claim(
    state: &AppState,
    account: &WebAccount,
) -> Result<(UserRecord, PrivateKeyResponse), ApiError> {
    let managed = state
        .accounts
        .get_managed_user(&account.account_id)
        .await?
        .ok_or_else(agent_device_authorization_invalidated)?;
    let profile = match key_state(&managed, current_timestamp()) {
        KeyState::Active => managed
            .profile
            .ok_or_else(agent_device_authorization_invalidated)?,
        KeyState::Missing | KeyState::Expired | KeyState::Disabled => {
            return Err(agent_device_authorization_invalidated());
        }
    };
    if require_profile_permission(&profile, PRIVATE_KEY_READ_PERMISSION).is_err() {
        return Err(agent_device_authorization_invalidated());
    }
    let private_key = load_private_key(state, profile.clone()).await?;
    if private_key.private_key_pem.len() > MAX_AGENT_PRIVATE_KEY_BYTES {
        warn!(
            username = profile.username,
            bytes = private_key.private_key_pem.len(),
            "拒绝返回异常大小的 Agent 私钥"
        );
        return Err(ApiError::internal());
    }
    Ok((profile, private_key))
}

fn ensure_visible_agent_authorization(
    authorization: &AgentDeviceAuthorization,
    account: &WebAccount,
) -> Result<(), ApiError> {
    if authorization.expires_at <= current_timestamp() {
        return Err(agent_device_expired_error());
    }
    match authorization.status {
        AgentDeviceAuthorizationStatus::Pending => Ok(()),
        AgentDeviceAuthorizationStatus::Authorized | AgentDeviceAuthorizationStatus::Denied
            if authorization.authorized_account_id.as_deref()
                == Some(account.account_id.as_str()) =>
        {
            Ok(())
        }
        AgentDeviceAuthorizationStatus::Authorized
        | AgentDeviceAuthorizationStatus::Denied
        | AgentDeviceAuthorizationStatus::Consumed => Err(ApiError::conflict(
            "device_authorization_finalized",
            "该设备授权码已经被处理",
        )),
    }
}

fn agent_device_expired_error() -> ApiError {
    ApiError::device_authorization_error(
        StatusCode::BAD_REQUEST,
        "expired_token",
        "设备授权码已过期，请在 Agent 中重新开始登录",
        None,
    )
}

fn agent_device_authorization_invalidated() -> ApiError {
    ApiError::device_authorization_error(
        StatusCode::FORBIDDEN,
        "authorization_invalidated",
        "账号状态已变化，请在 Agent 中重新开始登录",
        None,
    )
}

fn current_timestamp() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

fn default_access_record_limit() -> u32 {
    DEFAULT_ACCESS_RECORD_LIMIT
}

fn access_log_cutoff(retention_days: u16) -> i64 {
    current_timestamp().saturating_sub(i64::from(retention_days) * SECONDS_PER_DAY)
}

fn enabled_by_default() -> bool {
    true
}

fn trim_optional(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_string())
    })
}

fn serialize_zeroizing_string<S>(
    value: &Zeroizing<String>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(value.as_str())
}

fn patch_optional(value: PatchField<String>) -> Option<Option<String>> {
    match value {
        PatchField::Missing => None,
        PatchField::Null => Some(None),
        PatchField::Value(value) => Some(trim_optional(Some(value))),
    }
}

fn validate_browser_mutation(headers: &HeaderMap) -> Result<(), ApiError> {
    if let Some(site) = headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
        && !matches!(site, "same-origin" | "same-site" | "none")
    {
        return Err(ApiError::forbidden("拒绝跨站修改请求"));
    }
    Ok(())
}

fn validate_native_agent_request(headers: &HeaderMap) -> Result<(), ApiError> {
    if headers.contains_key(header::ORIGIN) {
        return Err(ApiError::forbidden(
            "Agent 设备授权接口不接受浏览器跨源请求",
        ));
    }
    if let Some(site) = headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
        && site != "none"
    {
        return Err(ApiError::forbidden(
            "Agent 设备授权接口只接受原生客户端请求",
        ));
    }
    Ok(())
}

// `encode`/`decode` are trait methods used for opaque Agent device codes.
use base64::Engine;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rate_limit::{
        LOGIN_ACCOUNT_CAPACITY, LOGIN_CLIENT_CAPACITY, REGISTRATION_CLIENT_CAPACITY,
    };
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use proxy_user_store::{
        AccessLogRepository, NewAccessRecord, NewAdminAccount, SqliteUserRepository,
    };
    use serde_json::{Value, json};
    use tempfile::TempDir;
    use tower::ServiceExt;

    const MASTER_SECRET: &str = "test-only-private-key-secret-with-32-plus-bytes";
    const FUTURE_EXPIRATION: i64 = 4_102_444_800;
    const LATER_FUTURE_EXPIRATION: i64 = 4_102_531_200;

    fn test_proxy_identity_public_key() -> Arc<str> {
        static KEY: std::sync::OnceLock<Arc<str>> = std::sync::OnceLock::new();
        KEY.get_or_init(|| {
            Arc::from(
                RsaKeyPair::generate(RSA_BITS)
                    .unwrap()
                    .public_key_to_pem()
                    .unwrap(),
            )
        })
        .clone()
    }

    #[test]
    fn http_trace_path_excludes_sensitive_query_parameters() {
        let request = Request::builder()
            .uri("/api/v1/agent/device-authorizations/inspect?user_code=secret-code")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            request_path_for_trace(&request),
            "/api/v1/agent/device-authorizations/inspect"
        );
    }

    async fn test_app() -> (TempDir, Router) {
        let (directory, _store, _sessions, _private_keys, app) = test_app_with_components().await;
        (directory, app)
    }

    #[tokio::test]
    async fn third_party_oauth_routes_are_not_exposed() {
        let (_directory, app) = test_app().await;
        for path in [
            "/api/v1/auth/oauth/google/start",
            "/api/v1/auth/oauth/wechat/start",
            "/api/v1/auth/oauth/wechat/callback?code=secret&state=secret",
        ] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }
    }

    async fn test_app_with_components() -> (
        TempDir,
        Arc<SqliteUserRepository>,
        SessionStore,
        PrivateKeyCipher,
        Router,
    ) {
        let directory = TempDir::new().unwrap();
        let store = Arc::new(
            SqliteUserRepository::connect(directory.path().join("users.sqlite3"))
                .await
                .unwrap(),
        );
        let passwords = PasswordService::new(1).await.unwrap();
        let hash = passwords
            .hash_password("admin-test-password".to_string())
            .await
            .unwrap();
        store
            .bootstrap_admin_if_none(NewAdminAccount {
                account_id: "acc_admin".to_string(),
                login_name: "admin".to_string(),
                password_hash: Some(hash),
                display_name: Some("Admin".to_string()),
                email: None,
                avatar_url: None,
            })
            .await
            .unwrap();
        let sessions = SessionStore::new(false);
        let private_keys = PrivateKeyCipher::new(MASTER_SECRET).unwrap();
        let state = AppState {
            users: store.clone(),
            accounts: store.clone(),
            access_logs: store.clone(),
            device_authorizations: store.clone(),
            passwords,
            sessions: sessions.clone(),
            private_keys: private_keys.clone(),
            proxy_identity_public_key_pem: test_proxy_identity_public_key(),
            allow_registration: true,
            device_authorization_guard: AgentDeviceAuthorizationGuard::default(),
        };
        (
            directory,
            store,
            sessions,
            private_keys,
            build_router(state, None),
        )
    }

    async fn json_body(response: Response) -> Value {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn assert_admin_response_is_redacted(body: &Value) {
        let serialized = serde_json::to_string(body).unwrap();
        for forbidden in [
            "public_key_pem",
            "private_key_pem",
            "BEGIN PUBLIC KEY",
            "BEGIN PRIVATE KEY",
            "credentials",
        ] {
            assert!(
                !serialized.contains(forbidden),
                "管理员响应不应包含 {forbidden}: {serialized}"
            );
        }
    }

    async fn login_admin(app: &Router) -> (String, String) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"username":"admin","password":"admin-test-password"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let body = json_body(response).await;
        (cookie, body["csrf_token"].as_str().unwrap().to_string())
    }

    async fn register_user(app: &Router, username: &str, password: &str) -> (String, String) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/register")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"username":username,"password":password}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let body = json_body(response).await;
        (cookie, body["csrf_token"].as_str().unwrap().to_string())
    }

    async fn login_user(app: &Router, username: &str, password: &str) -> (String, String) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"username":username,"password":password}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let body = json_body(response).await;
        (cookie, body["csrf_token"].as_str().unwrap().to_string())
    }

    async fn login_from_peer(app: &Router, username: &str, password: &str, peer: &str) -> Response {
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/login")
                    .extension(ConnectInfo(peer.parse::<SocketAddr>().unwrap()))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"username":username,"password":password}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn create_approved_user(
        app: &Router,
        admin_cookie: &str,
        admin_csrf: &str,
        username: &str,
        password: &str,
    ) -> Value {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/users")
                    .header(header::COOKIE, admin_cookie)
                    .header("x-csrf-token", admin_csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": username,
                            "password": password,
                            "expires_at": FUTURE_EXPIRATION
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        json_body(response).await
    }

    async fn start_device_authorization(app: &Router, platform: &str) -> (String, String) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/agent/device-authorizations")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "platform": platform,
                            "client_name": "Test Agent"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["verification_uri"], "/#agent-authorize");
        assert_eq!(body["expires_in"], AGENT_DEVICE_AUTHORIZATION_TTL_SECONDS);
        assert_eq!(body["interval"], AGENT_DEVICE_POLL_INTERVAL_SECONDS);
        let device_code = body["device_code"].as_str().unwrap().to_string();
        let user_code = body["user_code"].as_str().unwrap().to_string();
        assert_eq!(device_code.len(), 43);
        assert_eq!(user_code.len(), 14);
        assert_eq!(
            body["verification_uri_complete"],
            format!("/#agent-authorize={user_code}")
        );
        (device_code, user_code)
    }

    async fn poll_device_authorization(app: &Router, device_code: &str) -> Response {
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/agent/device-authorizations/token")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"device_code": device_code}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn registration_and_admin_creation_share_the_eight_character_password_minimum() {
        let (_directory, app) = test_app().await;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/register")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": "short-registration-password",
                            "password": "1234567"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            json_body(response).await["error"]["message"]
                .as_str()
                .unwrap()
                .contains('8')
        );

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/register")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": "boundary-registration-password",
                            "password": "12345678"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let (admin_cookie, admin_csrf) = login_admin(&app).await;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/users")
                    .header(header::COOKIE, &admin_cookie)
                    .header("x-csrf-token", &admin_csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": "short-admin-password",
                            "password": "1234567",
                            "expires_at": FUTURE_EXPIRATION
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            json_body(response).await["error"]["message"]
                .as_str()
                .unwrap()
                .contains('8')
        );

        let created = create_approved_user(
            &app,
            &admin_cookie,
            &admin_csrf,
            "boundary-admin-password",
            "abcdefgh",
        )
        .await;
        assert_eq!(
            created["user"]["account"]["login_name"],
            "boundary-admin-password"
        );
        login_user(&app, "boundary-admin-password", "abcdefgh").await;
    }

    #[tokio::test]
    async fn public_registration_is_strictly_limited_by_trusted_peer_address() {
        let (_directory, app) = test_app().await;
        for index in 0..REGISTRATION_CLIENT_CAPACITY as usize {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/auth/register")
                        .extension(ConnectInfo(
                            "203.0.113.90:31000".parse::<SocketAddr>().unwrap(),
                        ))
                        .header("content-type", "application/json")
                        .body(Body::from(
                            json!({
                                "username": format!("limited-registration-{index}"),
                                "password": "short"
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/register")
                    .extension(ConnectInfo(
                        "203.0.113.90:31001".parse::<SocketAddr>().unwrap(),
                    ))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": "registration-rate-exhausted",
                            "password": "short"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(response.headers().contains_key(header::RETRY_AFTER));
        assert_eq!(json_body(response).await["error"]["code"], "rate_limited");
    }

    #[tokio::test]
    async fn password_login_limits_ip_and_account_without_account_enumeration() {
        let (_directory, store, _sessions, _private_keys, app) = test_app_with_components().await;
        register_user(&app, "disabled-user", "disabled-user-password").await;
        let disabled = store
            .get_account_by_login("disabled-user")
            .await
            .unwrap()
            .unwrap();
        store
            .update_managed_user(
                &disabled.account_id,
                ManagedUserUpdate {
                    status: Some(AccountStatus::Disabled),
                    ..ManagedUserUpdate::default()
                },
            )
            .await
            .unwrap();

        let disabled_response = login_from_peer(
            &app,
            "disabled-user",
            "disabled-user-password",
            "203.0.113.101:32001",
        )
        .await;
        let missing_response = login_from_peer(
            &app,
            "missing-user",
            "disabled-user-password",
            "203.0.113.102:32002",
        )
        .await;
        let malformed_response =
            login_from_peer(&app, "", "disabled-user-password", "203.0.113.103:32003").await;
        assert_eq!(disabled_response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(missing_response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(malformed_response.status(), StatusCode::UNAUTHORIZED);
        let disabled_body = json_body(disabled_response).await;
        assert_eq!(json_body(missing_response).await, disabled_body);
        assert_eq!(json_body(malformed_response).await, disabled_body);

        let oversized_password = "x".repeat(257);
        for index in 0..LOGIN_ACCOUNT_CAPACITY as u16 {
            let response = login_from_peer(
                &app,
                "distributed-target",
                &oversized_password,
                &format!("198.51.100.{}:33000", index + 1),
            )
            .await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        let response = login_from_peer(
            &app,
            "distributed-target",
            &oversized_password,
            "198.51.100.200:33000",
        )
        .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(response.headers().contains_key(header::RETRY_AFTER));

        for index in 0..LOGIN_CLIENT_CAPACITY as usize {
            let response = login_from_peer(
                &app,
                &format!("credential-stuffing-{index}"),
                &oversized_password,
                "192.0.2.80:34000",
            )
            .await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        let response = login_from_peer(
            &app,
            "credential-stuffing-exhausted",
            &oversized_password,
            "192.0.2.80:34001",
        )
        .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(json_body(response).await["error"]["code"], "rate_limited");
    }

    #[tokio::test]
    async fn initial_key_request_requires_approval_before_owner_can_read_keys() {
        let (_directory, app) = test_app().await;
        let (cookie, csrf) = register_user(&app, "alice", "alice-safe-password").await;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/me")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["key_state"], "missing");
        assert!(body["profile"].is_null());
        assert!(body["pending_request"].is_null());
        assert!(!body.to_string().contains("public_key_pem"));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/me/private-key")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = json_body(response).await;
        assert!(!body.to_string().contains("PUBLIC KEY"));
        assert!(!body.to_string().contains("PRIVATE KEY"));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/me/rotate-key")
                    .header(header::COOKIE, &cookie)
                    .header("x-csrf-token", &csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let missing_csrf = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/me/key-requests")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing_csrf.status(), StatusCode::FORBIDDEN);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/me/key-requests")
                    .header(header::COOKIE, &cookie)
                    .header("x-csrf-token", &csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let request = json_body(response).await;
        let request_id = request["request_id"].as_str().unwrap().to_string();
        assert_eq!(request["kind"], "initial");
        assert_eq!(request["status"], "pending");

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/me/key-requests")
                    .header(header::COOKIE, &cookie)
                    .header("x-csrf-token", &csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_body(response).await["request_id"], request_id);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/me/key-request")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            json_body(response).await["request"]["request_id"],
            request_id
        );

        let (admin_cookie, admin_csrf) = login_admin(&app).await;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/admin/key-requests")
                    .header(header::COOKIE, &admin_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["requests"][0]["request_id"], request_id);
        assert_admin_response_is_redacted(&body);

        let approve_uri = format!("/api/v1/admin/key-requests/{request_id}/approve");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&approve_uri)
                    .header(header::COOKIE, &admin_cookie)
                    .header("x-csrf-token", &admin_csrf)
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&approve_uri)
                    .header(header::COOKIE, &admin_cookie)
                    .header("x-csrf-token", &admin_csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"expires_at": 1}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(approve_uri)
                    .header(header::COOKIE, &admin_cookie)
                    .header("x-csrf-token", &admin_csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"expires_at": FUTURE_EXPIRATION}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["request"]["status"], "approved");
        assert_eq!(body["user"]["profile"]["key_version"], 1);
        assert_admin_response_is_redacted(&body);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/me")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = json_body(response).await;
        assert_eq!(body["key_state"], "active");
        assert!(
            body["profile"]["public_key_pem"]
                .as_str()
                .unwrap()
                .contains("BEGIN PUBLIC KEY")
        );
        assert!(body["pending_request"].is_null());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/me/private-key")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert!(
            body["public_key_pem"]
                .as_str()
                .unwrap()
                .contains("PUBLIC KEY")
        );
        assert!(
            body["private_key_pem"]
                .as_str()
                .unwrap()
                .contains("PRIVATE KEY")
        );
        assert!(
            body["proxy_identity_public_key_pem"]
                .as_str()
                .unwrap()
                .contains("BEGIN PUBLIC KEY")
        );
    }

    #[tokio::test]
    async fn admin_key_management_is_redacted_but_owner_can_read_keys() {
        let (_directory, app) = test_app().await;
        let (cookie, csrf) = login_admin(&app).await;
        let request_body = json!({
            "username":"bob",
            "password":"bob-secure-password",
            "expires_at": FUTURE_EXPIRATION
        })
        .to_string();
        let missing_csrf = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/users")
                    .header(header::COOKIE, &cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(request_body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing_csrf.status(), StatusCode::FORBIDDEN);

        let missing_expiration = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/users")
                    .header(header::COOKIE, &cookie)
                    .header("x-csrf-token", &csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"username":"missing-expiry","password":"safe-user-password"})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            missing_expiration.status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );

        let past_expiration = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/users")
                    .header(header::COOKIE, &cookie)
                    .header("x-csrf-token", &csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "username":"past-expiry",
                            "password":"safe-user-password",
                            "expires_at":1
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(past_expiration.status(), StatusCode::BAD_REQUEST);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/users")
                    .header(header::COOKIE, &cookie)
                    .header("x-csrf-token", &csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(request_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = json_body(response).await;
        assert_eq!(body["user"]["profile"]["username"], "bob");
        assert_eq!(body["user"]["profile"]["key_version"], 1);
        assert_admin_response_is_redacted(&body);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/admin/users")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_admin_response_is_redacted(&json_body(response).await);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/admin/users/bob")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_admin_response_is_redacted(&json_body(response).await);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/api/v1/admin/users/bob")
                    .header(header::COOKIE, &cookie)
                    .header("x-csrf-token", &csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"display_name": "Bob"}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_admin_response_is_redacted(&json_body(response).await);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/users/bob/rotate-key")
                    .header(header::COOKIE, &cookie)
                    .header("x-csrf-token", &csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["key_version"], 2);
        assert_eq!(body["user"]["profile"]["key_version"], 2);
        assert_admin_response_is_redacted(&body);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/admin/users/bob/private-key")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_admin_response_is_redacted(&json_body(response).await);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"username":"bob","password":"bob-secure-password"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let owner_cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/me/private-key")
                    .header(header::COOKIE, owner_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert!(
            body["public_key_pem"]
                .as_str()
                .unwrap()
                .contains("BEGIN PUBLIC KEY")
        );
        assert!(
            body["proxy_identity_public_key_pem"]
                .as_str()
                .unwrap()
                .contains("BEGIN PUBLIC KEY")
        );
        assert!(
            body["private_key_pem"]
                .as_str()
                .unwrap()
                .contains("BEGIN PRIVATE KEY")
        );
    }

    #[tokio::test]
    async fn admin_permission_updates_cannot_remove_required_web_capabilities() {
        let (_directory, app) = test_app().await;
        let (cookie, csrf) = login_admin(&app).await;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/users")
                    .header(header::COOKIE, &cookie)
                    .header("x-csrf-token", &csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": "permission-user",
                            "password": "permission-user-password",
                            "expires_at": FUTURE_EXPIRATION,
                            "permissions": ["audit.read"]
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            json_body(response).await["user"]["profile"]["permissions"],
            json!([
                "audit.read",
                "key.private.read",
                "key.rotate",
                "proxy.connect.tcp",
                "proxy.connect.udp"
            ])
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/api/v1/admin/users/permission-user")
                    .header(header::COOKIE, cookie)
                    .header("x-csrf-token", csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"permissions": []}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            json_body(response).await["profile"]["permissions"],
            json!([
                "key.private.read",
                "key.rotate",
                "proxy.connect.tcp",
                "proxy.connect.udp"
            ])
        );
    }

    #[tokio::test]
    async fn legacy_database_permission_update_does_not_gain_private_key_capabilities() {
        let (directory, app) = test_app().await;
        let store = SqliteUserRepository::connect(directory.path().join("users.sqlite3"))
            .await
            .unwrap();
        let public_key = RsaKeyPair::generate(2048)
            .unwrap()
            .public_key_to_pem()
            .unwrap();
        store
            .create_user_record(NewUser::new("legacy-user", public_key, UserOrigin::Legacy))
            .await
            .unwrap();

        let (cookie, csrf) = login_admin(&app).await;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/api/v1/admin/users/legacy-user")
                    .header(header::COOKIE, &cookie)
                    .header("x-csrf-token", &csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"permissions": ["legacy.audit"]}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["profile"]["origin"], "legacy");
        assert_eq!(body["profile"]["permissions"], json!(["legacy.audit"]));
        assert_admin_response_is_redacted(&body);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/users/legacy-user/rotate-key")
                    .header(header::COOKIE, cookie)
                    .header("x-csrf-token", csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_admin_response_is_redacted(&json_body(response).await);
    }

    #[tokio::test]
    async fn active_user_can_rotate_own_key_but_cannot_use_admin_api() {
        let (_directory, app) = test_app().await;
        let (admin_cookie, admin_csrf) = login_admin(&app).await;
        let created = create_approved_user(
            &app,
            &admin_cookie,
            &admin_csrf,
            "rotate-user",
            "rotate-user-password",
        )
        .await;
        assert_admin_response_is_redacted(&created);
        let (cookie, csrf) = login_user(&app, "rotate-user", "rotate-user-password").await;
        let before = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/me/private-key")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let before = json_body(before).await;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/me/rotate-key")
                    .header(header::COOKIE, &cookie)
                    .header("x-csrf-token", csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let after = json_body(response).await;
        assert_eq!(after["key_version"], 2);
        assert_ne!(after["public_key_pem"], before["public_key_pem"]);
        assert_ne!(after["private_key_pem"], before["private_key_pem"]);

        let forbidden = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/admin/users")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn expired_key_is_hidden_and_can_only_be_restored_by_approval() {
        let (_directory, app) = test_app().await;
        let (admin_cookie, admin_csrf) = login_admin(&app).await;
        create_approved_user(
            &app,
            &admin_cookie,
            &admin_csrf,
            "expired-user",
            "expired-user-password",
        )
        .await;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/api/v1/admin/users/expired-user")
                    .header(header::COOKIE, &admin_cookie)
                    .header("x-csrf-token", &admin_csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"expires_at": 1}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_admin_response_is_redacted(&json_body(response).await);
        let (cookie, csrf) = login_user(&app, "expired-user", "expired-user-password").await;

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/me")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["key_state"], "expired");
        assert!(!body.to_string().contains("public_key_pem"));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/me/private-key")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(
            !json_body(response)
                .await
                .to_string()
                .contains("PRIVATE KEY")
        );

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/me/rotate-key")
                    .header(header::COOKIE, &cookie)
                    .header("x-csrf-token", &csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/admin/users/expired-user/rotate-key")
                    .header(header::COOKIE, &admin_cookie)
                    .header("x-csrf-token", &admin_csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        for expires_at in [Value::Null, json!(LATER_FUTURE_EXPIRATION)] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("PATCH")
                        .uri("/api/v1/admin/users/expired-user")
                        .header(header::COOKIE, &admin_cookie)
                        .header("x-csrf-token", &admin_csrf)
                        .header("content-type", "application/json")
                        .body(Body::from(json!({"expires_at": expires_at}).to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(
                matches!(
                    response.status(),
                    StatusCode::BAD_REQUEST | StatusCode::CONFLICT
                ),
                "过期密钥不能通过 PATCH 恢复"
            );
        }

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/me/key-requests")
                    .header(header::COOKIE, &cookie)
                    .header("x-csrf-token", &csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let request = json_body(response).await;
        assert_eq!(request["kind"], "rotate");
        let request_id = request["request_id"].as_str().unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/admin/key-requests/{request_id}/approve"))
                    .header(header::COOKIE, &admin_cookie)
                    .header("x-csrf-token", &admin_csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"expires_at": LATER_FUTURE_EXPIRATION}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["user"]["profile"]["key_version"], 2);
        assert_admin_response_is_redacted(&body);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/me/private-key")
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            json_body(response).await["private_key_pem"]
                .as_str()
                .unwrap()
                .contains("PRIVATE KEY")
        );
    }

    #[tokio::test]
    async fn concurrent_key_requests_are_idempotent_and_rejection_allows_retry() {
        let (_directory, app) = test_app().await;
        let (cookie, csrf) = register_user(&app, "request-user", "request-user-password").await;

        let first = app.clone().oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/me/key-requests")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        );
        let second = app.clone().oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/me/key-requests")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        );
        let (first, second) = tokio::join!(first, second);
        let first = first.unwrap();
        let second = second.unwrap();
        assert!(
            matches!(
                (first.status(), second.status()),
                (StatusCode::CREATED, StatusCode::OK) | (StatusCode::OK, StatusCode::CREATED)
            ),
            "并发提交必须恰好创建一条待审批申请"
        );
        let first = json_body(first).await;
        let second = json_body(second).await;
        assert_eq!(first["request_id"], second["request_id"]);
        let rejected_request_id = first["request_id"].as_str().unwrap().to_string();

        let (admin_cookie, admin_csrf) = login_admin(&app).await;
        let reject_uri = format!("/api/v1/admin/key-requests/{rejected_request_id}/reject");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&reject_uri)
                    .header(header::COOKIE, &admin_cookie)
                    .header("x-csrf-token", &admin_csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["request"]["status"], "rejected");
        assert!(body["user"].is_null());
        assert_admin_response_is_redacted(&body);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(reject_uri)
                    .header(header::COOKIE, &admin_cookie)
                    .header("x-csrf-token", &admin_csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/me/key-request")
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(json_body(response).await["request"].is_null());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/me/key-requests")
                    .header(header::COOKIE, cookie)
                    .header("x-csrf-token", csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_ne!(json_body(response).await["request_id"], rejected_request_id);
    }

    #[tokio::test]
    async fn access_records_are_owner_scoped_redacted_and_retention_is_admin_managed() {
        let (directory, app) = test_app().await;
        let (admin_cookie, admin_csrf) = login_admin(&app).await;
        create_approved_user(
            &app,
            &admin_cookie,
            &admin_csrf,
            "access-alice",
            "access-alice-password",
        )
        .await;
        create_approved_user(
            &app,
            &admin_cookie,
            &admin_csrf,
            "access-bob",
            "access-bob-password",
        )
        .await;

        let store = SqliteUserRepository::connect(directory.path().join("users.sqlite3"))
            .await
            .unwrap();
        let now = current_timestamp();
        for record in [
            NewAccessRecord {
                username: "access-alice".to_string(),
                protocol: AccessProtocol::Udp,
                target_host: "CURRENT.EXAMPLE".to_string(),
                target_port: 8443,
                accessed_at: now - 1,
            },
            NewAccessRecord {
                username: "access-alice".to_string(),
                protocol: AccessProtocol::Tcp,
                target_host: "current.example".to_string(),
                target_port: 443,
                accessed_at: now,
            },
            NewAccessRecord {
                username: "access-alice".to_string(),
                protocol: AccessProtocol::Udp,
                target_host: "two-days-old.example".to_string(),
                target_port: 53,
                accessed_at: now - 2 * SECONDS_PER_DAY,
            },
            NewAccessRecord {
                username: "access-bob".to_string(),
                protocol: AccessProtocol::Tcp,
                target_host: "bob-private.example".to_string(),
                target_port: 8443,
                accessed_at: now,
            },
        ] {
            store.record_access(record).await.unwrap();
        }

        let (alice_cookie, _alice_csrf) =
            login_user(&app, "access-alice", "access-alice-password").await;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/me/access-records?limit=10&since=0")
                    .header(header::COOKIE, &alice_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["retention_days"], 7);
        assert_eq!(body["records"].as_array().unwrap().len(), 2);
        assert_eq!(body.as_object().unwrap().len(), 2);
        for record in body["records"].as_array().unwrap() {
            let object = record.as_object().unwrap();
            assert_eq!(object.len(), 5);
            for field in [
                "target_host",
                "target_port",
                "protocol",
                "access_count",
                "accessed_at",
            ] {
                assert!(object.contains_key(field));
            }
        }
        assert_eq!(body["records"][0]["target_host"], "current.example");
        assert_eq!(body["records"][0]["target_port"], 443);
        assert_eq!(body["records"][0]["protocol"], "tcp");
        assert_eq!(body["records"][0]["access_count"], 2);
        let serialized = body.to_string();
        for forbidden in ["access-alice", "access-bob", "bob-private", "record_id"] {
            assert!(
                !serialized.contains(forbidden),
                "访问记录响应不应包含 {forbidden}: {serialized}"
            );
        }

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/me/access-records?username=access-bob")
                    .header(header::COOKIE, &alice_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/v1/me/access-records?limit={}",
                        MAX_ACCESS_LOG_QUERY_LIMIT + 1
                    ))
                    .header(header::COOKIE, &alice_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/me/access-records?since={}", now + 1))
                    .header(header::COOKIE, &alice_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            json_body(response).await["records"]
                .as_array()
                .unwrap()
                .is_empty()
        );

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/admin/access-log-settings")
                    .header(header::COOKIE, &alice_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/admin/access-log-settings")
                    .header(header::COOKIE, &admin_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_body(response).await["retention_days"], 7);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/api/v1/admin/access-log-settings")
                    .header(header::COOKIE, &admin_cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"retention_days": 1}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        for retention_days in [0, MAX_ACCESS_LOG_RETENTION_DAYS + 1] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("PATCH")
                        .uri("/api/v1/admin/access-log-settings")
                        .header(header::COOKIE, &admin_cookie)
                        .header("x-csrf-token", &admin_csrf)
                        .header("content-type", "application/json")
                        .body(Body::from(
                            json!({"retention_days": retention_days}).to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/api/v1/admin/access-log-settings")
                    .header(header::COOKIE, &admin_cookie)
                    .header("x-csrf-token", &admin_csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"retention_days": 1}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["retention_days"], 1);
        assert!(body["purged_records"].as_u64().unwrap() >= 1);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/me/access-records?limit=10&since=0")
                    .header(header::COOKIE, alice_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = json_body(response).await;
        assert_eq!(body["retention_days"], 1);
        assert_eq!(body["records"].as_array().unwrap().len(), 1);
        assert_eq!(body["records"][0]["target_host"], "current.example");
    }

    #[tokio::test]
    async fn agent_device_flow_rate_limits_and_delivers_credentials_once() {
        let (_directory, app) = test_app().await;
        let (admin_cookie, admin_csrf) = login_admin(&app).await;
        create_approved_user(
            &app,
            &admin_cookie,
            &admin_csrf,
            "agent-alice",
            "agent-alice-password",
        )
        .await;
        let (user_cookie, user_csrf) =
            login_user(&app, "agent-alice", "agent-alice-password").await;
        let (device_code, user_code) = start_device_authorization(&app, "android").await;

        let response = poll_device_authorization(&app, &device_code).await;
        assert_eq!(response.status(), StatusCode::PRECONDITION_REQUIRED);
        assert_eq!(
            response.headers().get(header::RETRY_AFTER).unwrap(),
            AGENT_DEVICE_POLL_INTERVAL_SECONDS.to_string().as_str()
        );
        assert_eq!(
            json_body(response).await["error"]["code"],
            "authorization_pending"
        );

        let response = poll_device_authorization(&app, &device_code).await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(response.headers().contains_key(header::RETRY_AFTER));
        assert_eq!(json_body(response).await["error"]["code"], "slow_down");

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/agent/device-authorizations/inspect")
                    .header(header::COOKIE, &user_cookie)
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"user_code": &user_code}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/agent/device-authorizations/inspect")
                    .header(header::COOKIE, &user_cookie)
                    .header("x-csrf-token", &user_csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"user_code": &user_code}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["client_name"], "Test Agent");
        assert_eq!(body["platform"], "android");
        assert_eq!(body["status"], "pending");

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/agent/device-authorizations/approve")
                    .header(header::COOKIE, &user_cookie)
                    .header("x-csrf-token", &user_csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"user_code": user_code}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_body(response).await["status"], "authorized");

        let response = poll_device_authorization(&app, &device_code).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response
                .headers()
                .get(header::SET_COOKIE)
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("ppaass_session=")
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let body = json_body(response).await;
        assert_eq!(body["account"]["login_name"], "agent-alice");
        assert_eq!(body["account"]["role"], "user");
        assert_eq!(body["profile"]["username"], "agent-alice");
        assert!(
            body["profile"]["permissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|permission| permission == PRIVATE_KEY_READ_PERMISSION)
        );
        assert!(
            body["private_key_pem"]
                .as_str()
                .unwrap()
                .contains("BEGIN PRIVATE KEY")
        );
        assert!(
            body["public_key_pem"]
                .as_str()
                .unwrap()
                .contains("BEGIN PUBLIC KEY")
        );
        let serialized = body.to_string();
        assert!(serialized.len() < MAX_AGENT_TOKEN_RESPONSE_BYTES);
        for forbidden in ["device_code", "user_code"] {
            assert!(!serialized.contains(forbidden));
        }

        let response = poll_device_authorization(&app, &device_code).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            json_body(response).await["error"]["code"],
            "invalid_device_code"
        );
    }

    #[tokio::test]
    async fn failed_credential_construction_does_not_burn_device_code() {
        let (_directory, store, _sessions, _private_keys, app) = test_app_with_components().await;
        let (admin_cookie, admin_csrf) = login_admin(&app).await;
        create_approved_user(
            &app,
            &admin_cookie,
            &admin_csrf,
            "retry-device-user",
            "retry-device-password",
        )
        .await;
        let (user_cookie, user_csrf) =
            login_user(&app, "retry-device-user", "retry-device-password").await;
        let (device_code, user_code) = start_device_authorization(&app, "android").await;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/agent/device-authorizations/approve")
                    .header(header::COOKIE, user_cookie)
                    .header("x-csrf-token", user_csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"user_code": &user_code}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let broken_app = build_router(
            AppState {
                users: store.clone(),
                accounts: store.clone(),
                access_logs: store.clone(),
                device_authorizations: store.clone(),
                passwords: PasswordService::new(1).await.unwrap(),
                sessions: SessionStore::new(false),
                private_keys: PrivateKeyCipher::new(
                    "different-test-secret-that-cannot-decrypt-existing-keys",
                )
                .unwrap(),
                proxy_identity_public_key_pem: test_proxy_identity_public_key(),
                allow_registration: true,
                device_authorization_guard: AgentDeviceAuthorizationGuard::default(),
            },
            None,
        );
        let response = poll_device_authorization(&broken_app, &device_code).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let authorization = store
            .get_agent_device_authorization_by_user_code(
                &agent_user_code_hash(&user_code).unwrap(),
                current_timestamp(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            authorization.status,
            AgentDeviceAuthorizationStatus::Authorized
        );

        let response = poll_device_authorization(&app, &device_code).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            json_body(response).await["private_key_pem"]
                .as_str()
                .unwrap()
                .contains("BEGIN PRIVATE KEY")
        );
    }

    #[tokio::test]
    async fn concurrent_device_claim_returns_credentials_to_exactly_one_request() {
        let (_directory, _store, sessions, _private_keys, app) = test_app_with_components().await;
        let (admin_cookie, admin_csrf) = login_admin(&app).await;
        create_approved_user(
            &app,
            &admin_cookie,
            &admin_csrf,
            "concurrent-device-user",
            "concurrent-device-password",
        )
        .await;
        let (user_cookie, user_csrf) =
            login_user(&app, "concurrent-device-user", "concurrent-device-password").await;
        let (device_code, user_code) = start_device_authorization(&app, "windows").await;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/agent/device-authorizations/approve")
                    .header(header::COOKIE, user_cookie)
                    .header("x-csrf-token", user_csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"user_code": user_code}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let sessions_before_claim = sessions.active_session_count();

        let (left, right) = tokio::join!(
            poll_device_authorization(&app, &device_code),
            poll_device_authorization(&app, &device_code)
        );
        let (success, rejected) = if left.status() == StatusCode::OK {
            (left, right)
        } else {
            (right, left)
        };
        assert_eq!(success.status(), StatusCode::OK);
        assert!(
            json_body(success).await["private_key_pem"]
                .as_str()
                .unwrap()
                .contains("BEGIN PRIVATE KEY")
        );
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            json_body(rejected).await["error"]["code"],
            "invalid_device_code"
        );
        assert_eq!(sessions.active_session_count(), sessions_before_claim + 1);
    }

    #[tokio::test]
    async fn public_device_start_flood_is_bounded_and_returns_429() {
        let (_directory, _store, _sessions, _private_keys, app) = test_app_with_components().await;
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..64 {
            let app = app.clone();
            tasks.spawn(async move {
                app.oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/agent/device-authorizations")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            json!({
                                "platform": "android",
                                "client_name": "Flood Test Agent"
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap()
            });
        }
        let mut accepted = 0_i64;
        let mut rejected = 0_i64;
        while let Some(result) = tasks.join_next().await {
            let response = result.unwrap();
            match response.status() {
                StatusCode::OK => accepted += 1,
                StatusCode::TOO_MANY_REQUESTS => {
                    assert!(response.headers().contains_key(header::RETRY_AFTER));
                    assert_eq!(json_body(response).await["error"]["code"], "rate_limited");
                    rejected += 1;
                }
                status => panic!("unexpected device start flood status: {status}"),
            }
        }
        assert!(accepted > 0 && accepted <= 40);
        assert!(rejected > 0);
    }

    #[tokio::test]
    async fn existing_external_account_session_can_authorize_agent_without_a_password() {
        let (_directory, store, sessions, private_keys, app) = test_app_with_components().await;
        let account = store
            .create_user_account(NewUserAccount {
                account_id: "acc_external_only".to_string(),
                login_name: "external_device_user".to_string(),
                password_hash: None,
                display_name: Some("Historical External User".to_string()),
                email: Some("device@example.test".to_string()),
                avatar_url: None,
                external_identity: Some(ExternalIdentity {
                    provider: "retired-provider".to_string(),
                    subject: "retired-subject-device-only".to_string(),
                }),
            })
            .await
            .unwrap();
        let request = store
            .submit_key_generation_request(NewKeyGenerationRequest {
                request_id: "keyreq_external_device".to_string(),
                account_id: account.account_id.clone(),
            })
            .await
            .unwrap();
        let stored_keys = generate_stored_keys(&private_keys, &account.login_name, 1)
            .await
            .unwrap();
        let mut profile = NewUser::new(
            &account.login_name,
            stored_keys.public_key_pem,
            UserOrigin::Local,
        );
        profile.permissions = default_web_permissions();
        profile.expires_at = Some(FUTURE_EXPIRATION);
        store
            .approve_key_generation_request(KeyRequestApproval {
                request_id: request.request_id,
                reviewer_account_id: "acc_admin".to_string(),
                expires_at: FUTURE_EXPIRATION,
                material: ApprovedKeyMaterial::Initial {
                    profile,
                    encrypted_private_key: stored_keys.encrypted_private_key,
                },
            })
            .await
            .unwrap();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": account.login_name,
                            "password": "cannot-login-with-password"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let (device_code, user_code) = start_device_authorization(&app, "windows").await;
        let (browser_session, browser_cookie) = sessions.issue(&account.account_id);
        let browser_cookie = browser_cookie
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/agent/device-authorizations/approve")
                    .header(header::COOKIE, browser_cookie)
                    .header("x-csrf-token", browser_session.csrf_token)
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"user_code": user_code}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = poll_device_authorization(&app, &device_code).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["account"]["account_id"], "acc_external_only");
        assert_eq!(body["profile"]["username"], "external_device_user");
        assert!(
            body["private_key_pem"]
                .as_str()
                .unwrap()
                .contains("BEGIN PRIVATE KEY")
        );
    }

    #[tokio::test]
    async fn agent_device_approval_rejects_admin_missing_keys_and_cross_origin_clients() {
        let (_directory, store, _sessions, _private_keys, app) = test_app_with_components().await;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/agent/device-authorizations")
                    .header(header::ORIGIN, "https://attacker.example")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"platform":"android"}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let (admin_cookie, admin_csrf) = login_admin(&app).await;
        let (_admin_device_code, admin_user_code) =
            start_device_authorization(&app, "android").await;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/agent/device-authorizations/approve")
                    .header(header::COOKIE, &admin_cookie)
                    .header("x-csrf-token", &admin_csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"user_code": admin_user_code}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let (user_cookie, user_csrf) =
            register_user(&app, "waiting-user", "waiting-user-password").await;
        let (waiting_device_code, waiting_user_code) =
            start_device_authorization(&app, "android").await;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/agent/device-authorizations/approve")
                    .header(header::COOKIE, &user_cookie)
                    .header("x-csrf-token", &user_csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"user_code": waiting_user_code}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            json_body(response).await["error"]["code"],
            "key_request_required"
        );
        let response = poll_device_authorization(&app, &waiting_device_code).await;
        assert_eq!(response.status(), StatusCode::PRECONDITION_REQUIRED);

        create_approved_user(
            &app,
            &admin_cookie,
            &admin_csrf,
            "no-private-read",
            "no-private-read-password",
        )
        .await;
        store
            .update_user(
                "no-private-read",
                UserUpdate {
                    permissions: Some(vec![
                        PROXY_CONNECT_TCP_PERMISSION.to_string(),
                        PROXY_CONNECT_UDP_PERMISSION.to_string(),
                    ]),
                    ..UserUpdate::default()
                },
            )
            .await
            .unwrap();
        let (limited_cookie, limited_csrf) =
            login_user(&app, "no-private-read", "no-private-read-password").await;
        let (_limited_device_code, limited_user_code) =
            start_device_authorization(&app, "windows").await;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/agent/device-authorizations/approve")
                    .header(header::COOKIE, limited_cookie)
                    .header("x-csrf-token", limited_csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"user_code": limited_user_code}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(json_body(response).await["error"]["code"], "forbidden");

        for (username, update, expected_status, expected_code) in [
            (
                "disabled-device",
                UserUpdate {
                    enabled: Some(false),
                    ..UserUpdate::default()
                },
                StatusCode::FORBIDDEN,
                "forbidden",
            ),
            (
                "expired-device",
                UserUpdate {
                    expires_at: Some(Some(current_timestamp() - 1)),
                    ..UserUpdate::default()
                },
                StatusCode::CONFLICT,
                "key_request_required",
            ),
        ] {
            let password = format!("{username}-password");
            create_approved_user(&app, &admin_cookie, &admin_csrf, username, &password).await;
            store.update_user(username, update).await.unwrap();
            let (cookie, csrf) = login_user(&app, username, &password).await;
            let (_device_code, user_code) = start_device_authorization(&app, "android").await;
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/agent/device-authorizations/approve")
                        .header(header::COOKIE, cookie)
                        .header("x-csrf-token", csrf)
                        .header("content-type", "application/json")
                        .body(Body::from(json!({"user_code": user_code}).to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected_status);
            assert_eq!(json_body(response).await["error"]["code"], expected_code);
        }
    }

    #[tokio::test]
    async fn denied_agent_device_authorization_cannot_be_claimed() {
        let (_directory, app) = test_app().await;
        let (admin_cookie, admin_csrf) = login_admin(&app).await;
        create_approved_user(
            &app,
            &admin_cookie,
            &admin_csrf,
            "deny-device-user",
            "deny-device-password",
        )
        .await;
        let (user_cookie, user_csrf) =
            login_user(&app, "deny-device-user", "deny-device-password").await;
        let (device_code, user_code) = start_device_authorization(&app, "android").await;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/agent/device-authorizations/deny")
                    .header(header::COOKIE, user_cookie)
                    .header("x-csrf-token", user_csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"user_code": user_code}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_body(response).await["status"], "denied");

        let response = poll_device_authorization(&app, &device_code).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(json_body(response).await["error"]["code"], "access_denied");
    }

    #[tokio::test]
    async fn unknown_api_is_json_and_never_cached() {
        let (_directory, app) = test_app().await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v9/missing")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(json_body(response).await["error"]["code"], "not_found");
    }

    #[test]
    fn new_users_receive_proxy_and_key_permissions_by_default() {
        assert_eq!(
            default_web_permissions(),
            vec![
                "key.private.read",
                "key.rotate",
                "proxy.connect.tcp",
                "proxy.connect.udp",
            ]
        );
        assert_eq!(
            with_required_web_permissions(vec![
                "proxy.connect.tcp".to_string(),
                "audit.read".to_string(),
                "audit.read".to_string(),
            ]),
            vec![
                "audit.read",
                "key.private.read",
                "key.rotate",
                "proxy.connect.tcp",
                "proxy.connect.udp",
            ]
        );
    }
}
