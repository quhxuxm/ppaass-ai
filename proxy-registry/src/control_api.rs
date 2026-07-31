use std::{convert::Infallible, sync::Arc, time::Duration};

use crate::store::{
    AccessBatchRepository, AccessProtocol, NewAccessRecord, ProxyEntryRepository, UserRepository,
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode, header},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use futures::{StreamExt, stream};
use proxy_control_protocol::{
    ACCESS_BATCHES_PATH, AUTHORIZATION_EVENTS_PATH, AUTHORIZATION_RESOLVE_PATH, AccessBatchRequest,
    AccessBatchResponse, AccessProtocol as ControlAccessProtocol, AuthorizationEvent,
    AuthorizationResolveRequest, AuthorizationResolveResponse, AuthorizationSnapshot,
    CONTROL_HEALTH_PATH, CONTROL_PROTOCOL_VERSION, ControlHealthResponse, ENTRY_REGISTRATION_PATH,
    MAX_ACCESS_EVENTS_PER_BATCH, MAX_BATCH_ID_BYTES, MAX_ENTRY_ID_BYTES,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio::sync::broadcast;
use tower_http::{timeout::TimeoutLayer, trace::TraceLayer};
use tracing::{info, warn};

use crate::AgentEventHub;

const CONTROL_REQUEST_TIMEOUT_SECONDS: u64 = 15;
const CONTROL_BODY_LIMIT_BYTES: usize = 256 * 1024;
const CONTROL_KEEP_ALIVE_SECONDS: u64 = 15;
const CONTROL_EVENT_CONNECTION_SECONDS: u64 = 12 * 60 * 60;
const ACCESS_BATCH_IDEMPOTENCY_RETENTION_SECONDS: i64 = 7 * 24 * 60 * 60;
const MIN_CONTROL_TOKEN_BYTES: usize = 32;
const MAX_CONTROL_TOKEN_BYTES: usize = 512;

#[derive(Clone)]
pub struct ControlTokenVerifier {
    digest: Arc<[u8; 32]>,
}

impl ControlTokenVerifier {
    pub fn new(token: &str) -> anyhow::Result<Self> {
        if token.len() < MIN_CONTROL_TOKEN_BYTES
            || token.len() > MAX_CONTROL_TOKEN_BYTES
            || token.chars().any(char::is_whitespace)
        {
            anyhow::bail!(
                "Proxy 控制面 Token 必须为 {MIN_CONTROL_TOKEN_BYTES}..={MAX_CONTROL_TOKEN_BYTES} \
                 字节且不能包含空白字符"
            );
        }
        Ok(Self {
            digest: Arc::new(Sha256::digest(token.as_bytes()).into()),
        })
    }

    fn verify(&self, candidate: &str) -> bool {
        let candidate: [u8; 32] = Sha256::digest(candidate.as_bytes()).into();
        self.digest
            .iter()
            .zip(candidate)
            .fold(0_u8, |difference, (expected, actual)| {
                difference | (expected ^ actual)
            })
            == 0
    }
}

#[derive(Clone)]
pub struct ControlState {
    pub instance_id: Arc<str>,
    pub users: Arc<dyn UserRepository>,
    pub access_batches: Arc<dyn AccessBatchRepository>,
    pub proxy_entries: Arc<dyn ProxyEntryRepository>,
    pub agent_events: AgentEventHub,
    pub token_verifier: ControlTokenVerifier,
}

pub fn build_control_router(state: ControlState) -> Router {
    Router::new()
        .route(CONTROL_HEALTH_PATH, get(control_health))
        .route(ENTRY_REGISTRATION_PATH, post(entries::register_entry))
        .route(AUTHORIZATION_RESOLVE_PATH, post(resolve_authorization))
        .route(AUTHORIZATION_EVENTS_PATH, get(authorization_events))
        .route(ACCESS_BATCHES_PATH, post(ingest_access_batch))
        .with_state(state)
        .layer(DefaultBodyLimit::max(CONTROL_BODY_LIMIT_BYTES))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(CONTROL_REQUEST_TIMEOUT_SECONDS),
        ))
        .layer(TraceLayer::new_for_http())
}

mod entries;

async fn control_health(State(state): State<ControlState>) -> Json<ControlHealthResponse> {
    Json(ControlHealthResponse {
        status: "ok".to_string(),
        protocol_version: CONTROL_PROTOCOL_VERSION,
        registry_instance_id: state.instance_id.to_string(),
    })
}

async fn resolve_authorization(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Json(request): Json<AuthorizationResolveRequest>,
) -> Result<Json<AuthorizationResolveResponse>, ControlApiError> {
    require_control_token(&state, &headers)?;
    let authorization =
        state
            .users
            .get_user(&request.username)
            .await?
            .map(|user| AuthorizationSnapshot {
                username: user.username,
                public_key_pem: user.public_key_pem,
                permissions: user.permissions,
                enabled: user.enabled,
                key_version: user.key_version,
                expires_at: user.expires_at,
            });
    Ok(Json(AuthorizationResolveResponse {
        authorization,
        revision: state.agent_events.latest_revision(),
    }))
}

struct ControlEventStreamState {
    receiver: broadcast::Receiver<crate::agent_events::AgentServerEvent>,
    deadline: tokio::time::Instant,
}

async fn authorization_events(
    State(state): State<ControlState>,
    headers: HeaderMap,
) -> Result<Sse<impl futures::Stream<Item = Result<Event, Infallible>>>, ControlApiError> {
    require_control_token(&state, &headers)?;
    let initial_revision = state.agent_events.latest_revision();
    let requested_revision = headers
        .get("Last-Event-ID")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let updates = stream::unfold(
        ControlEventStreamState {
            receiver: state.agent_events.subscribe(),
            deadline: tokio::time::Instant::now()
                + Duration::from_secs(CONTROL_EVENT_CONNECTION_SECONDS),
        },
        |mut event_stream| async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep_until(event_stream.deadline) => return None,
                    received = event_stream.receiver.recv() => match received {
                        Ok(event) if event.affects_proxy_authorization() => {
                            let payload = AuthorizationEvent {
                                revision: event.revision,
                            };
                            let data = serde_json::to_string(&payload)
                                .unwrap_or_else(|_| "{}".to_string());
                            let item = Event::default()
                                .id(event.revision.to_string())
                                .event("authorization_changed")
                                .data(data);
                            return Some((Ok(item), event_stream));
                        }
                        Ok(_) => {}
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            let item = Event::default()
                                .event("authorization_reset")
                                .data("{}");
                            return Some((Ok(item), event_stream));
                        }
                        Err(broadcast::error::RecvError::Closed) => return None,
                    }
                }
            }
        },
    );
    let initial = stream::once(async move {
        let data = serde_json::to_string(&AuthorizationEvent {
            revision: initial_revision,
        })
        .unwrap_or_else(|_| "{}".to_string());
        let event_name = if requested_revision == Some(initial_revision) {
            "authorization_ready"
        } else {
            "authorization_reset"
        };
        Ok(Event::default()
            .id(initial_revision.to_string())
            .event(event_name)
            .data(data)
            .retry(Duration::from_secs(1)))
    });
    info!("Proxy Entry 控制面 SSE 事件流已连接");
    Ok(Sse::new(initial.chain(updates)).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(CONTROL_KEEP_ALIVE_SECONDS))
            .text("keep-alive"),
    ))
}

async fn ingest_access_batch(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Json(request): Json<AccessBatchRequest>,
) -> Result<Json<AccessBatchResponse>, ControlApiError> {
    require_control_token(&state, &headers)?;
    validate_safe_identifier("entry_id", &request.entry_id, MAX_ENTRY_ID_BYTES)?;
    validate_safe_identifier("batch_id", &request.batch_id, MAX_BATCH_ID_BYTES)?;
    if request.events.is_empty() || request.events.len() > MAX_ACCESS_EVENTS_PER_BATCH {
        return Err(ControlApiError::bad_request(format!(
            "访问记录批次必须包含 1..={MAX_ACCESS_EVENTS_PER_BATCH} 条记录"
        )));
    }
    let records = request
        .events
        .into_iter()
        .map(|event| NewAccessRecord {
            username: event.username,
            protocol: match event.protocol {
                ControlAccessProtocol::Tcp => AccessProtocol::Tcp,
                ControlAccessProtocol::Udp => AccessProtocol::Udp,
            },
            target_host: event.target_host,
            target_port: event.target_port,
            accessed_at: event.accessed_at,
        })
        .collect::<Vec<_>>();
    let received_at = OffsetDateTime::now_utc().unix_timestamp();
    let accepted = state
        .access_batches
        .ingest_access_batch(&request.entry_id, &request.batch_id, &records, received_at)
        .await?;

    let purge_before = received_at.saturating_sub(ACCESS_BATCH_IDEMPOTENCY_RETENTION_SECONDS);
    if let Err(error) = state
        .access_batches
        .purge_access_batches_before(purge_before)
        .await
    {
        warn!(%error, "清理访问记录幂等批次失败，将在后续上报时重试");
    }
    Ok(Json(AccessBatchResponse { accepted }))
}

fn require_control_token(state: &ControlState, headers: &HeaderMap) -> Result<(), ControlApiError> {
    let candidate = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(ControlApiError::unauthorized)?;
    if !state.token_verifier.verify(candidate) {
        return Err(ControlApiError::unauthorized());
    }
    Ok(())
}

fn validate_safe_identifier(
    field: &str,
    value: &str,
    maximum_bytes: usize,
) -> Result<(), ControlApiError> {
    if value.is_empty()
        || value.len() > maximum_bytes
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ControlApiError::bad_request(format!(
            "{field} 必须是 1..={maximum_bytes} 字节的安全标识符"
        )));
    }
    Ok(())
}

#[derive(Debug)]
struct ControlApiError {
    status: StatusCode,
    message: String,
}

#[derive(Serialize)]
struct ControlErrorBody {
    error: String,
}

impl ControlApiError {
    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "无效的 Proxy Entry 控制面凭据".to_string(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }
}

impl From<crate::store::UserRepositoryError> for ControlApiError {
    fn from(error: crate::store::UserRepositoryError) -> Self {
        if let crate::store::UserRepositoryError::ProxyEntryAddressConflict(address) = &error {
            return Self {
                status: StatusCode::CONFLICT,
                message: format!("Proxy Entry 地址已被其他节点占用：{address}"),
            };
        }
        warn!(%error, "Proxy 控制面存储操作失败");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "控制面内部错误".to_string(),
        }
    }
}

impl IntoResponse for ControlApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ControlErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}
