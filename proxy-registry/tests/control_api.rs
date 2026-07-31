use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use protocol::RsaKeyPair;
use proxy_control_protocol::{
    ACCESS_BATCHES_PATH, AUTHORIZATION_SNAPSHOT_PATH, AccessBatchRequest, AccessEvent,
    AccessProtocol, AuthorizationSnapshotResponse, CONTROL_PROTOCOL_VERSION,
    ENTRY_REGISTRATION_PATH, EntryRegistrationRequest, EntryRegistrationResponse,
};
use proxy_registry::store::{
    AccessLogRepository, AgentEventRepository, ProxyAddressRepository, SqliteAccessLogRepository,
    SqliteUserRepository, UserRepository,
};
use proxy_registry::{AgentEventHub, ControlState, ControlTokenVerifier, build_control_router};
use serde::Serialize;
use tempfile::TempDir;
use tower::ServiceExt;

const TEST_TOKEN: &str = "test-control-token-0123456789-abcdef";

async fn test_router() -> (
    Router,
    Arc<SqliteUserRepository>,
    Arc<SqliteAccessLogRepository>,
    TempDir,
) {
    let (users, access, directory) = test_repositories().await;
    let router = router_for(users.clone(), access.clone()).await;
    (router, users, access, directory)
}

async fn test_repositories() -> (
    Arc<SqliteUserRepository>,
    Arc<SqliteAccessLogRepository>,
    TempDir,
) {
    let directory = TempDir::new().unwrap();
    let users = Arc::new(
        SqliteUserRepository::connect(directory.path().join("users.sqlite3"))
            .await
            .unwrap(),
    );
    let access = Arc::new(
        SqliteAccessLogRepository::connect(directory.path().join("access.sqlite3"))
            .await
            .unwrap(),
    );
    (users, access, directory)
}

async fn router_for(
    users: Arc<SqliteUserRepository>,
    access: Arc<SqliteAccessLogRepository>,
) -> Router {
    let events = AgentEventHub::start(users.clone()).await.unwrap();
    build_control_router(ControlState {
        instance_id: Arc::from("registry-test"),
        users: users.clone(),
        access_batches: access,
        proxy_entries: users,
        agent_events: events,
        token_verifier: ControlTokenVerifier::new(TEST_TOKEN).unwrap(),
    })
}

fn authorized_json_request(path: &str, body: impl Serialize) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

fn authorized_get_request(path: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {TEST_TOKEN}"))
        .body(Body::empty())
        .unwrap()
}

async fn get_snapshot(app: Router, path: &str) -> AuthorizationSnapshotResponse {
    let response = app.oneshot(authorized_get_request(path)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn authorization_snapshot_is_token_protected_and_supports_an_empty_page() {
    let (app, _users, _access, _directory) = test_router().await;
    let unauthorized = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(AUTHORIZATION_SNAPSHOT_PATH)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let snapshot = get_snapshot(app, AUTHORIZATION_SNAPSHOT_PATH).await;
    assert_eq!(snapshot.revision, 0);
    assert!(snapshot.authorizations.is_empty());
    assert_eq!(snapshot.next_cursor, None);
}

#[tokio::test]
async fn authorization_snapshot_uses_username_keyset_pagination() {
    let (users, access, _directory) = test_repositories().await;
    let key = RsaKeyPair::generate(2048)
        .unwrap()
        .public_key_to_pem()
        .unwrap();
    users.create_user("charlie", &key, None).await.unwrap();
    users.create_user("bob", &key, None).await.unwrap();
    users.create_user("alice", &key, Some(12345)).await.unwrap();
    let expected_revision = users.latest_agent_event_revision().await.unwrap();
    let app = router_for(users, access).await;

    let first = get_snapshot(
        app.clone(),
        &format!("{AUTHORIZATION_SNAPSHOT_PATH}?limit=2"),
    )
    .await;
    assert_eq!(first.revision, expected_revision);
    assert_eq!(
        first
            .authorizations
            .iter()
            .map(|authorization| authorization.username.as_str())
            .collect::<Vec<_>>(),
        ["alice", "bob"]
    );
    assert_eq!(first.next_cursor.as_deref(), Some("bob"));
    assert_eq!(first.authorizations[0].public_key_pem, key.trim());
    assert_eq!(
        first.authorizations[0].permissions,
        proxy_registry::store::default_proxy_permissions()
    );
    assert!(first.authorizations[0].enabled);
    assert_eq!(first.authorizations[0].key_version, 1);
    assert_eq!(first.authorizations[0].expires_at, Some(12345));

    let second = get_snapshot(
        app,
        &format!(
            "{AUTHORIZATION_SNAPSHOT_PATH}?after_username=bob&revision={expected_revision}&limit=2"
        ),
    )
    .await;
    assert_eq!(second.revision, expected_revision);
    assert_eq!(second.authorizations.len(), 1);
    assert_eq!(second.authorizations[0].username, "charlie");
    assert_eq!(second.next_cursor, None);
}

#[tokio::test]
async fn authorization_snapshot_rejects_revision_changes_between_pages() {
    let (users, access, _directory) = test_repositories().await;
    let key = RsaKeyPair::generate(2048)
        .unwrap()
        .public_key_to_pem()
        .unwrap();
    users.create_user("alice", &key, None).await.unwrap();
    users.create_user("bob", &key, None).await.unwrap();
    let app = router_for(users.clone(), access).await;
    let first = get_snapshot(
        app.clone(),
        &format!("{AUTHORIZATION_SNAPSHOT_PATH}?limit=1"),
    )
    .await;
    users.create_user("charlie", &key, None).await.unwrap();

    let response = app
        .clone()
        .oneshot(authorized_get_request(&format!(
            "{AUTHORIZATION_SNAPSHOT_PATH}?after_username=alice&revision={}&limit=1",
            first.revision
        )))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    for invalid_query in ["after_username=alice", "revision=1", "limit=0", "limit=257"] {
        let response = app
            .clone()
            .oneshot(authorized_get_request(&format!(
                "{AUTHORIZATION_SNAPSHOT_PATH}?{invalid_query}"
            )))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{invalid_query}"
        );
    }
}

#[tokio::test]
async fn retried_access_batch_does_not_double_count() {
    let (app, _users, access, _directory) = test_router().await;
    let batch = AccessBatchRequest {
        entry_id: "entry-test".to_string(),
        batch_id: "batch-test".to_string(),
        events: vec![AccessEvent {
            username: "alice".to_string(),
            protocol: AccessProtocol::Tcp,
            target_host: "example.com".to_string(),
            target_port: 443,
            accessed_at: 100,
        }],
    };
    for _ in 0..2 {
        let response = app
            .clone()
            .oneshot(authorized_json_request(ACCESS_BATCHES_PATH, &batch))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    let records = access.list_recent_access("alice", 0, 10).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].access_count, 1);
}

#[tokio::test]
async fn entry_registration_is_protected_and_upserts_the_catalog_node() {
    let (app, users, _access, _directory) = test_router().await;
    let request = EntryRegistrationRequest {
        entry_id: "entry-test".to_string(),
        version: "1.2.3".to_string(),
        protocol_version: CONTROL_PROTOCOL_VERSION,
        advertised_address: "Entry.EXAMPLE:443".to_string(),
    };
    let unauthorized = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(ENTRY_REGISTRATION_PATH)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    for version in ["1.2.3", "1.2.4"] {
        let response = app
            .clone()
            .oneshot(authorized_json_request(
                ENTRY_REGISTRATION_PATH,
                EntryRegistrationRequest {
                    version: version.to_string(),
                    ..request.clone()
                },
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let registered: EntryRegistrationResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(registered.registry_instance_id, "registry-test");
        assert_eq!(registered.protocol_version, CONTROL_PROTOCOL_VERSION);
    }

    let nodes = ProxyAddressRepository::list_proxy_addresses(users.as_ref())
        .await
        .unwrap();
    let registered = nodes
        .iter()
        .filter(|node| node.entry_id.as_deref() == Some("entry-test"))
        .collect::<Vec<_>>();
    assert_eq!(registered.len(), 1);
    assert_eq!(registered[0].address, "entry.example:443");
    assert_eq!(registered[0].entry_version.as_deref(), Some("1.2.4"));

    let conflict = app
        .oneshot(authorized_json_request(
            ENTRY_REGISTRATION_PATH,
            EntryRegistrationRequest {
                entry_id: "entry-conflict".to_string(),
                advertised_address: "entry.example:443".to_string(),
                ..request
            },
        ))
        .await
        .unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn entry_registration_rejects_an_incompatible_protocol_version() {
    let (app, _users, _access, _directory) = test_router().await;
    let response = app
        .oneshot(authorized_json_request(
            ENTRY_REGISTRATION_PATH,
            EntryRegistrationRequest {
                entry_id: "entry-old".to_string(),
                version: "1.0.0".to_string(),
                protocol_version: CONTROL_PROTOCOL_VERSION - 1,
                advertised_address: "old.example:443".to_string(),
            },
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn control_tokens_require_high_entropy_shape() {
    assert!(ControlTokenVerifier::new("short").is_err());
    assert!(ControlTokenVerifier::new(TEST_TOKEN).is_ok());
    assert!(ControlTokenVerifier::new(&format!("{TEST_TOKEN}\n")).is_err());
}
