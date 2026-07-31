mod support;

use std::{convert::Infallible, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::{Query, State},
    http::HeaderMap,
    response::sse::{Event, Sse},
    routing::{get, post},
};
use futures::stream;
use protocol::RsaKeyPair;
use proxy_control_protocol::{
    AUTHORIZATION_EVENTS_PATH, AUTHORIZATION_SNAPSHOT_PATH, AuthorizationSnapshot,
    AuthorizationSnapshotQuery, AuthorizationSnapshotResponse, CONTROL_PROTOCOL_VERSION,
    ENTRY_REGISTRATION_PATH, EntryRegistrationResponse,
};
use proxy_entry::{control_plane::RemoteControlPlane, server::ProxyServer};
use tokio::sync::{Mutex, Notify};

const TEST_TOKEN: &str = "0123456789abcdef0123456789abcdef";

#[derive(Clone)]
struct RegistryState {
    snapshot_calls: Arc<std::sync::atomic::AtomicUsize>,
    authorization: AuthorizationSnapshot,
    last_event_ids: Arc<Mutex<Vec<Option<String>>>>,
    event_connected: Arc<Notify>,
}

async fn register() -> Json<EntryRegistrationResponse> {
    tokio::time::sleep(Duration::from_millis(250)).await;
    Json(EntryRegistrationResponse {
        registry_instance_id: "registry-test".to_string(),
        protocol_version: CONTROL_PROTOCOL_VERSION,
        received_at: 1_785_490_000,
    })
}

async fn snapshot(
    State(state): State<RegistryState>,
    Query(_query): Query<AuthorizationSnapshotQuery>,
) -> Json<AuthorizationSnapshotResponse> {
    let revision = state
        .snapshot_calls
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel) as u64
        + 1;
    Json(AuthorizationSnapshotResponse {
        authorizations: vec![state.authorization],
        revision,
        next_cursor: None,
    })
}

async fn events(
    State(state): State<RegistryState>,
    headers: HeaderMap,
) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
    let last_event_id = headers
        .get("Last-Event-ID")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    state.last_event_ids.lock().await.push(last_event_id);
    state.event_connected.notify_one();
    Sse::new(stream::once(async {
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        Ok(Event::default()
            .id("999")
            .event("authorization_changed")
            .data("{}"))
    }))
}

#[tokio::test]
async fn persisted_revision_is_reused_and_sse_body_has_no_total_request_timeout() {
    let public_key = RsaKeyPair::generate(2048)
        .unwrap()
        .public_key_to_pem()
        .unwrap();
    let state = RegistryState {
        snapshot_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        authorization: AuthorizationSnapshot {
            username: "alice".to_string(),
            public_key_pem: public_key,
            permissions: vec!["proxy.connect.tcp".to_string()],
            enabled: true,
            key_version: 1,
            expires_at: None,
        },
        last_event_ids: Arc::new(Mutex::new(Vec::new())),
        event_connected: Arc::new(Notify::new()),
    };
    let app = Router::new()
        .route(ENTRY_REGISTRATION_PATH, post(register))
        .route(AUTHORIZATION_SNAPSHOT_PATH, get(snapshot))
        .route(AUTHORIZATION_EVENTS_PATH, get(events))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let registry_address = listener.local_addr().unwrap();
    let registry = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let directory = tempfile::TempDir::new().unwrap();
    let token_path = directory.path().join("control-token");
    std::fs::write(&token_path, TEST_TOKEN).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut config = support::proxy_config("control_request_timeout_secs = 1");
    config.registry_url = format!("http://{registry_address}");
    config.registry_control_token_path = token_path.display().to_string();
    config.authorization_database_path = directory
        .path()
        .join("authorization.sqlite3")
        .display()
        .to_string();

    let control = RemoteControlPlane::new(&config).await.unwrap();
    assert_eq!(control.refresh_authorizations().await.unwrap(), 1);
    drop(control);
    let entry = tokio::spawn(ProxyServer::new(config).await.unwrap().run());

    tokio::time::timeout(Duration::from_secs(2), state.event_connected.notified())
        .await
        .unwrap();
    assert_eq!(state.last_event_ids.lock().await[0].as_deref(), Some("1"));
    tokio::time::timeout(Duration::from_secs(4), async {
        while state
            .snapshot_calls
            .load(std::sync::atomic::Ordering::Acquire)
            < 3
        {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("SSE 响应体超过普通请求超时后仍应触发快照刷新");
    tokio::time::timeout(Duration::from_secs(4), async {
        while state.last_event_ids.lock().await.len() < 2 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("事件流结束后应携带已提交快照 revision 重连");
    assert_eq!(state.last_event_ids.lock().await[1].as_deref(), Some("3"));

    entry.abort();
    registry.abort();
}
