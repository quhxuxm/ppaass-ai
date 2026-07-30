pub(super) use super::super::*;
pub(super) use crate::rate_limit::{
    LOGIN_ACCOUNT_CAPACITY, LOGIN_CLIENT_CAPACITY, REGISTRATION_CLIENT_CAPACITY,
};
pub(super) use axum::{
    body::{Body, to_bytes},
    http::Request,
};
pub(super) use proxy_user_store::{
    AccessLogRepository, NewAccessRecord, NewAdminAccount, SqliteUserRepository,
};
pub(super) use serde_json::{Value, json};
pub(super) use tempfile::TempDir;
pub(super) use tower::ServiceExt;

pub(super) const MASTER_SECRET: &str = "test-only-private-key-secret-with-32-plus-bytes";
pub(super) const FUTURE_EXPIRATION: i64 = 4_102_444_800;
pub(super) const LATER_FUTURE_EXPIRATION: i64 = 4_102_531_200;
pub(super) const TEST_PROXY_ADDRESS_ID: &str = "pxy_web_test";

pub(super) fn test_proxy_identity_public_key() -> Arc<str> {
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
pub(super) fn http_trace_path_excludes_sensitive_query_parameters() {
    let request = Request::builder()
        .uri("/api/v1/agent/device-authorizations/inspect?user_code=secret-code")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        request_path_for_trace(&request),
        "/api/v1/agent/device-authorizations/inspect"
    );
}

pub(super) async fn test_app() -> (TempDir, Router) {
    let (directory, _store, _sessions, _handoffs, _private_keys, app) =
        test_app_with_components().await;
    (directory, app)
}

#[tokio::test]
pub(super) async fn third_party_oauth_routes_are_not_exposed() {
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

pub(super) async fn test_app_with_components() -> (
    TempDir,
    Arc<SqliteUserRepository>,
    SessionStore,
    AgentWebSessionHandoffStore,
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
        .create_proxy_address(NewProxyAddress {
            proxy_address_id: TEST_PROXY_ADDRESS_ID.to_string(),
            label: "Web test proxy".to_string(),
            address: "127.0.0.1:8080".to_string(),
            enabled: true,
        })
        .await
        .unwrap();
    store
        .bootstrap_admin_if_absent(NewAdminAccount {
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
    let web_session_handoffs = AgentWebSessionHandoffStore::new();
    let private_keys = PrivateKeyCipher::new(MASTER_SECRET).unwrap();
    let agent_tokens = AgentAccessTokenService::new(MASTER_SECRET).unwrap();
    let agent_events = crate::agent_events::AgentEventHub::new();
    let state = AppState {
        users: store.clone(),
        accounts: store.clone(),
        access_logs: store.clone(),
        device_authorizations: store.clone(),
        proxy_addresses: store.clone(),
        audit_logs: store.clone(),
        passwords,
        sessions: sessions.clone(),
        agent_tokens,
        agent_events: agent_events.clone(),
        web_session_handoffs: web_session_handoffs.clone(),
        private_keys: private_keys.clone(),
        proxy_identity_public_key_pem: test_proxy_identity_public_key(),
        allow_registration: true,
        device_authorization_guard: AgentDeviceAuthorizationGuard::default(),
    };
    (
        directory,
        store,
        sessions,
        web_session_handoffs,
        private_keys,
        build_router(state, None),
    )
}

pub(super) async fn json_body(response: Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

pub(super) fn assert_admin_response_is_redacted(body: &Value) {
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

pub(super) async fn login_admin(app: &Router) -> (String, String) {
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

pub(super) async fn register_user(
    app: &Router,
    username: &str,
    password: &str,
) -> (String, String) {
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

pub(super) async fn login_user(app: &Router, username: &str, password: &str) -> (String, String) {
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

pub(super) async fn login_from_peer(
    app: &Router,
    username: &str,
    password: &str,
    peer: &str,
) -> Response {
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

pub(super) async fn create_approved_user(
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
                        "expires_at": FUTURE_EXPIRATION,
                        "proxy_address_ids": [TEST_PROXY_ADDRESS_ID],
                        "audit_reason": "测试创建用户"
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

pub(super) async fn start_device_authorization(app: &Router, platform: &str) -> (String, String) {
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

pub(super) async fn poll_device_authorization(app: &Router, device_code: &str) -> Response {
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
