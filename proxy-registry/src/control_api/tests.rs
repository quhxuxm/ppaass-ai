use std::sync::Arc;

use crate::store::{
    AccessLogRepository, SqliteAccessLogRepository, SqliteUserRepository, UserRepository,
};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use protocol::RsaKeyPair;
use proxy_control_protocol::{
    ACCESS_BATCHES_PATH, AUTHORIZATION_RESOLVE_PATH, AccessBatchRequest, AccessEvent,
    AccessProtocol, AuthorizationResolveRequest, AuthorizationResolveResponse,
};
use tempfile::TempDir;
use tower::ServiceExt;

use super::*;

const TEST_TOKEN: &str = "test-control-token-0123456789-abcdef";

async fn test_router() -> (
    Router,
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
    let events = AgentEventHub::start(users.clone()).await.unwrap();
    let router = build_control_router(ControlState {
        instance_id: Arc::from("registry-test"),
        proxy_identity_sha256: Arc::from("identity-test"),
        users: users.clone(),
        access_batches: access.clone(),
        agent_events: events,
        token_verifier: ControlTokenVerifier::new(TEST_TOKEN).unwrap(),
    });
    (router, users, access, directory)
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

#[tokio::test]
async fn authorization_endpoint_is_token_protected_and_returns_only_public_profile() {
    let (app, users, _access, _directory) = test_router().await;
    let key = RsaKeyPair::generate(2048)
        .unwrap()
        .public_key_to_pem()
        .unwrap();
    users.create_user("alice", &key, Some(12345)).await.unwrap();

    let unauthorized = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(AUTHORIZATION_RESOLVE_PATH)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&AuthorizationResolveRequest {
                        username: "alice".to_string(),
                    })
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .oneshot(authorized_json_request(
            AUTHORIZATION_RESOLVE_PATH,
            AuthorizationResolveRequest {
                username: "alice".to_string(),
            },
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let resolved: AuthorizationResolveResponse = serde_json::from_slice(&body).unwrap();
    let authorization = resolved.authorization.unwrap();
    assert_eq!(authorization.username, "alice");
    assert_eq!(authorization.public_key_pem, key.trim());
    assert_eq!(authorization.expires_at, Some(12345));
    assert_eq!(authorization.key_version, 1);
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

#[test]
fn control_tokens_require_high_entropy_shape() {
    assert!(ControlTokenVerifier::new("short").is_err());
    assert!(ControlTokenVerifier::new(TEST_TOKEN).is_ok());
    assert!(ControlTokenVerifier::new(&format!("{TEST_TOKEN}\n")).is_err());
}
