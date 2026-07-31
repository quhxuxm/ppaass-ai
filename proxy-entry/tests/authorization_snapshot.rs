mod support;

use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use protocol::RsaKeyPair;
use proxy_control_protocol::{
    AUTHORIZATION_SNAPSHOT_PATH, AuthorizationSnapshot, AuthorizationSnapshotQuery,
    AuthorizationSnapshotResponse,
};
use proxy_entry::{
    config::ProxyConfig, control_plane::RemoteControlPlane, user_manager::AuthorizationProvider,
};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tokio::{sync::Mutex, task::JoinHandle};

const TEST_TOKEN: &str = "0123456789abcdef0123456789abcdef";

#[derive(Clone)]
enum SnapshotReply {
    Page(AuthorizationSnapshotResponse),
    Status(StatusCode),
}

#[derive(Clone, Default)]
struct SnapshotState {
    replies: Arc<Mutex<VecDeque<SnapshotReply>>>,
    queries: Arc<Mutex<Vec<AuthorizationSnapshotQuery>>>,
    delay: Duration,
    active: Arc<AtomicUsize>,
    max_active: Arc<AtomicUsize>,
}

async fn snapshot(
    State(state): State<SnapshotState>,
    Query(query): Query<AuthorizationSnapshotQuery>,
) -> Response {
    state.queries.lock().await.push(query);
    let active = state.active.fetch_add(1, Ordering::AcqRel) + 1;
    state.max_active.fetch_max(active, Ordering::AcqRel);
    if !state.delay.is_zero() {
        tokio::time::sleep(state.delay).await;
    }
    let reply = state.replies.lock().await.pop_front();
    state.active.fetch_sub(1, Ordering::AcqRel);
    match reply {
        Some(SnapshotReply::Page(response)) => Json(response).into_response(),
        Some(SnapshotReply::Status(status)) => status.into_response(),
        None => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

async fn spawn_registry(
    replies: impl IntoIterator<Item = SnapshotReply>,
    delay: Duration,
) -> (String, SnapshotState, JoinHandle<()>) {
    let state = SnapshotState {
        replies: Arc::new(Mutex::new(replies.into_iter().collect())),
        delay,
        ..SnapshotState::default()
    };
    let app = Router::new()
        .route(AUTHORIZATION_SNAPSHOT_PATH, get(snapshot))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, state, task)
}

fn authorization(username: &str, public_key_pem: &str, key_version: i64) -> AuthorizationSnapshot {
    AuthorizationSnapshot {
        username: username.to_string(),
        public_key_pem: public_key_pem.to_string(),
        permissions: vec!["proxy.connect.tcp".to_string()],
        enabled: true,
        key_version,
        expires_at: None,
    }
}

fn page(
    revision: u64,
    authorizations: Vec<AuthorizationSnapshot>,
    next_cursor: Option<&str>,
) -> SnapshotReply {
    SnapshotReply::Page(AuthorizationSnapshotResponse {
        authorizations,
        revision,
        next_cursor: next_cursor.map(str::to_string),
    })
}

fn public_key() -> String {
    RsaKeyPair::generate(2048)
        .unwrap()
        .public_key_to_pem()
        .unwrap()
}

fn full_page(prefix: &str, public_key_pem: &str, key_version: i64) -> Vec<AuthorizationSnapshot> {
    (0..256)
        .map(|index| authorization(&format!("{prefix}-{index:03}"), public_key_pem, key_version))
        .collect()
}

fn config_in(directory: &tempfile::TempDir, registry_url: &str, entry_id: &str) -> ProxyConfig {
    let token_path = directory.path().join("control-token");
    if !token_path.exists() {
        std::fs::write(&token_path, TEST_TOKEN).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    let mut config = support::proxy_config("");
    config.entry_id = entry_id.to_string();
    config.registry_url = registry_url.to_string();
    config.registry_control_token_path = token_path.display().to_string();
    config.authorization_database_path = directory
        .path()
        .join("authorization.sqlite3")
        .display()
        .to_string();
    config.control_request_timeout_secs = 2;
    config
}

#[tokio::test]
async fn first_snapshot_is_required_and_persisted_lkg_survives_restart_offline() {
    let key = public_key();
    let (url, _state, registry) = spawn_registry(
        [page(1, vec![authorization("alice", &key, 1)], None)],
        Duration::ZERO,
    )
    .await;
    let directory = tempfile::TempDir::new().unwrap();
    let config = config_in(&directory, &url, "entry-a");
    let control = RemoteControlPlane::new(&config).await.unwrap();

    assert!(control.get_user("alice").await.is_err());
    control.refresh_authorizations().await.unwrap();
    assert_eq!(
        control
            .get_user("alice")
            .await
            .unwrap()
            .unwrap()
            .key_version,
        Some(1)
    );

    drop(control);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(SqliteConnectOptions::new().filename(&config.authorization_database_path))
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO authorization_snapshot_staging \
         (username, public_key_pem, permissions_json, enabled, key_version, expires_at) \
         VALUES (?, ?, ?, 1, 1, NULL)",
    )
    .bind("stale")
    .bind(&key)
    .bind("[\"proxy.connect.tcp\"]")
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;
    registry.abort();
    let _ = registry.await;
    let restarted = RemoteControlPlane::new(&config).await.unwrap();
    assert_eq!(
        restarted
            .get_user("alice")
            .await
            .unwrap()
            .unwrap()
            .public_key_pem,
        key
    );
    assert!(restarted.refresh_authorizations().await.is_err());
    assert!(restarted.get_user("alice").await.unwrap().is_some());
    assert!(restarted.get_user("stale").await.unwrap().is_none());
}

#[tokio::test]
async fn multiple_pages_replace_snapshot_and_remove_missing_users() {
    let first_key = public_key();
    let second_key = public_key();
    let (url, state, registry) = spawn_registry(
        [
            page(1, vec![authorization("alice", &first_key, 1)], None),
            page(2, full_page("bob", &second_key, 2), Some("bob-255")),
            page(2, vec![authorization("carol", &second_key, 2)], None),
        ],
        Duration::ZERO,
    )
    .await;
    let directory = tempfile::TempDir::new().unwrap();
    let control = RemoteControlPlane::new(&config_in(&directory, &url, "entry-a"))
        .await
        .unwrap();

    control.refresh_authorizations().await.unwrap();
    control.refresh_authorizations().await.unwrap();
    assert!(control.get_user("alice").await.unwrap().is_none());
    assert!(control.get_user("bob-000").await.unwrap().is_some());
    assert!(control.get_user("carol").await.unwrap().is_some());

    let queries = state.queries.lock().await;
    assert_eq!(queries[2].after_username.as_deref(), Some("bob-255"));
    assert_eq!(queries[2].revision, Some(2));
    assert_eq!(queries[2].limit, Some(256));
    registry.abort();
}

#[tokio::test]
async fn revision_conflict_restarts_from_first_page_and_eventually_commits() {
    let key = public_key();
    let (url, state, registry) = spawn_registry(
        [
            page(1, vec![authorization("alice", &key, 1)], None),
            page(2, full_page("bob", &key, 2), Some("bob-255")),
            SnapshotReply::Status(StatusCode::CONFLICT),
            page(3, vec![authorization("carol", &key, 3)], None),
        ],
        Duration::ZERO,
    )
    .await;
    let directory = tempfile::TempDir::new().unwrap();
    let control = RemoteControlPlane::new(&config_in(&directory, &url, "entry-a"))
        .await
        .unwrap();

    control.refresh_authorizations().await.unwrap();
    assert_eq!(control.refresh_authorizations().await.unwrap(), 3);
    assert!(control.get_user("alice").await.unwrap().is_none());
    assert!(control.get_user("carol").await.unwrap().is_some());

    let queries = state.queries.lock().await;
    assert_eq!(queries[2].after_username.as_deref(), Some("bob-255"));
    assert_eq!(queries[2].revision, Some(2));
    assert_eq!(queries[3].after_username, None);
    assert_eq!(queries[3].revision, None);
    registry.abort();
}

#[tokio::test]
async fn failed_later_page_keeps_active_snapshot_and_discards_staging() {
    let key = public_key();
    let (url, _state, registry) = spawn_registry(
        [
            page(1, vec![authorization("alice", &key, 1)], None),
            page(2, full_page("bob", &key, 2), Some("bob-255")),
            SnapshotReply::Status(StatusCode::SERVICE_UNAVAILABLE),
        ],
        Duration::ZERO,
    )
    .await;
    let directory = tempfile::TempDir::new().unwrap();
    let control = RemoteControlPlane::new(&config_in(&directory, &url, "entry-a"))
        .await
        .unwrap();

    control.refresh_authorizations().await.unwrap();
    assert!(control.refresh_authorizations().await.is_err());
    assert!(control.get_user("alice").await.unwrap().is_some());
    assert!(control.get_user("bob-000").await.unwrap().is_none());
    registry.abort();
}

#[tokio::test]
async fn short_nonfinal_page_is_rejected_without_replacing_lkg() {
    let key = public_key();
    let (url, _state, registry) = spawn_registry(
        [
            page(1, vec![authorization("alice", &key, 1)], None),
            page(2, vec![authorization("bob", &key, 2)], Some("bob")),
        ],
        Duration::ZERO,
    )
    .await;
    let directory = tempfile::TempDir::new().unwrap();
    let control = RemoteControlPlane::new(&config_in(&directory, &url, "entry-a"))
        .await
        .unwrap();

    control.refresh_authorizations().await.unwrap();
    assert!(control.refresh_authorizations().await.is_err());
    assert!(control.get_user("alice").await.unwrap().is_some());
    registry.abort();
}

#[tokio::test]
async fn successful_empty_snapshot_is_distinct_from_never_loaded() {
    let (url, _state, registry) = spawn_registry([page(4, Vec::new(), None)], Duration::ZERO).await;
    let directory = tempfile::TempDir::new().unwrap();
    let config = config_in(&directory, &url, "entry-a");
    let control = RemoteControlPlane::new(&config).await.unwrap();
    assert!(control.get_user("missing").await.is_err());
    control.refresh_authorizations().await.unwrap();
    assert!(control.get_user("missing").await.unwrap().is_none());
    drop(control);
    let restarted = RemoteControlPlane::new(&config).await.unwrap();
    assert!(restarted.get_user("missing").await.unwrap().is_none());
    registry.abort();
}

#[tokio::test]
async fn persisted_snapshot_is_rejected_for_a_different_control_plane_identity() {
    let key = public_key();
    let (url, _state, registry) = spawn_registry(
        [page(1, vec![authorization("alice", &key, 1)], None)],
        Duration::ZERO,
    )
    .await;
    let directory = tempfile::TempDir::new().unwrap();
    let control = RemoteControlPlane::new(&config_in(&directory, &url, "entry-a"))
        .await
        .unwrap();
    control.refresh_authorizations().await.unwrap();
    drop(control);

    let different_entry = config_in(&directory, &url, "entry-b");
    let reopened = RemoteControlPlane::new(&different_entry).await.unwrap();
    assert!(reopened.get_user("alice").await.is_err());
    drop(reopened);
    let different_registry = config_in(&directory, "http://127.0.0.1:9", "entry-a");
    let reopened = RemoteControlPlane::new(&different_registry).await.unwrap();
    assert!(reopened.get_user("alice").await.is_err());
    registry.abort();
}

#[tokio::test]
async fn concurrent_refreshes_are_single_flight() {
    let key = public_key();
    let (url, state, registry) = spawn_registry(
        [
            page(10, vec![authorization("alice", &key, 1)], None),
            page(9, vec![authorization("alice", &key, 2)], None),
        ],
        Duration::from_millis(100),
    )
    .await;
    let directory = tempfile::TempDir::new().unwrap();
    let control = RemoteControlPlane::new(&config_in(&directory, &url, "entry-a"))
        .await
        .unwrap();
    let (first, second) = tokio::join!(
        control.refresh_authorizations(),
        control.refresh_authorizations()
    );
    first.unwrap();
    second.unwrap();
    assert_eq!(state.max_active.load(Ordering::Acquire), 1);
    assert_eq!(
        control
            .get_user("alice")
            .await
            .unwrap()
            .unwrap()
            .key_version,
        Some(2)
    );
    registry.abort();
}
