use super::common::*;
use base64::Engine;
use futures::StreamExt;
use proxy_registry::AGENT_PROFILE_REFRESH_SECONDS;

const PACKET_CAPTURE_PERMISSION: &str = "agent.packet_capture";
const EGRESS_EDIT_PERMISSION: &str = "agent.egress.edit";
const RUNTIME_THREADS_EDIT_PERMISSION: &str = "agent.runtime_threads.edit";

#[tokio::test]
async fn agent_login_returns_permissions_and_event_driven_sync_observes_admin_changes() {
    let (_directory, app) = test_app().await;
    let (admin_cookie, admin_csrf) = login_admin(&app).await;
    create_approved_user(
        &app,
        &admin_cookie,
        &admin_csrf,
        "sync-user",
        "sync-user-password",
    )
    .await;

    let response = agent_login(&app, "sync-user", "sync-user-password").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let login = json_body(response).await;
    assert_eq!(login["account"]["role"], "user");
    assert_eq!(login["profile"]["username"], "sync-user");
    assert_eq!(
        login["profile"]["proxy_addresses"],
        json!(["127.0.0.1:8080"])
    );
    assert_eq!(
        login["refresh_after_seconds"],
        AGENT_PROFILE_REFRESH_SECONDS
    );
    assert!(
        login["private_key_pem"]
            .as_str()
            .unwrap()
            .contains("BEGIN PRIVATE KEY")
    );
    let first_token = login["agent_access_token"].as_str().unwrap().to_string();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/admin/users/sync-user")
                .header(header::COOKIE, &admin_cookie)
                .header("x-csrf-token", &admin_csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "permissions": [
                            PACKET_CAPTURE_PERMISSION,
                            EGRESS_EDIT_PERMISSION,
                            RUNTIME_THREADS_EDIT_PERMISSION,
                            "custom.keep"
                        ],
                        "audit_reason": "更新 Agent 权限"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = agent_profile(&app, &first_token).await;
    assert_eq!(response.status(), StatusCode::OK);
    let synced = json_body(response).await;
    let permissions = synced["profile"]["permissions"].as_array().unwrap();
    assert_eq!(
        synced["profile"]["proxy_addresses"],
        json!(["127.0.0.1:8080"])
    );
    for permission in [
        PACKET_CAPTURE_PERMISSION,
        EGRESS_EDIT_PERMISSION,
        RUNTIME_THREADS_EDIT_PERMISSION,
        "custom.keep",
    ] {
        assert!(
            permissions.iter().any(|candidate| candidate == permission),
            "missing {permission}: {permissions:?}"
        );
    }
    assert_ne!(synced["agent_access_token"].as_str().unwrap(), first_token);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/admin/users/sync-user")
                .header(header::COOKIE, &admin_cookie)
                .header("x-csrf-token", &admin_csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "permissions": [],
                        "audit_reason": "撤销 Agent 权限"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = agent_profile(&app, &first_token).await;
    assert_eq!(response.status(), StatusCode::OK);
    let revoked = json_body(response).await;
    let permissions = revoked["profile"]["permissions"].as_array().unwrap();
    for permission in [
        PACKET_CAPTURE_PERMISSION,
        EGRESS_EDIT_PERMISSION,
        RUNTIME_THREADS_EDIT_PERMISSION,
        "custom.keep",
    ] {
        assert!(
            !permissions.iter().any(|candidate| candidate == permission),
            "revoked permission still returned: {permission}: {permissions:?}"
        );
    }
}

#[tokio::test]
async fn authenticated_agent_event_stream_starts_with_sync_event() {
    let (_directory, app) = test_app().await;
    let (admin_cookie, admin_csrf) = login_admin(&app).await;
    create_approved_user(
        &app,
        &admin_cookie,
        &admin_csrf,
        "event-user",
        "event-user-password",
    )
    .await;
    let login = json_body(agent_login(&app, "event-user", "event-user-password").await).await;
    let token = login["agent_access_token"].as_str().unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/agent/events")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::ACCEPT, "text/event-stream")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/event-stream")
    );
    let mut stream = response.into_body().into_data_stream();
    let first = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let first = std::str::from_utf8(&first).unwrap();
    assert!(first.contains("event: sync"), "{first:?}");

    let update = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/admin/users/event-user")
                .header(header::COOKIE, admin_cookie)
                .header("x-csrf-token", admin_csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "permissions": [PACKET_CAPTURE_PERMISSION],
                        "audit_reason": "启用抓包权限"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(update.status(), StatusCode::OK);

    let changed = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let changed = std::str::from_utf8(&changed).unwrap();
    assert!(changed.contains("event: profile_changed"), "{changed:?}");
}

#[tokio::test]
async fn avatar_update_is_published_and_returned_to_android_agent_endpoints() {
    let (_directory, app) = test_app().await;
    let (admin_cookie, admin_csrf) = login_admin(&app).await;
    create_approved_user(
        &app,
        &admin_cookie,
        &admin_csrf,
        "avatar-sync-user",
        "avatar-sync-password",
    )
    .await;
    let (user_cookie, user_csrf) =
        login_user(&app, "avatar-sync-user", "avatar-sync-password").await;
    let initial =
        json_body(agent_login(&app, "avatar-sync-user", "avatar-sync-password").await).await;
    let token = initial["agent_access_token"].as_str().unwrap();

    let events = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/agent/events")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::ACCEPT, "text/event-stream")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(events.status(), StatusCode::OK);
    let mut stream = events.into_body().into_data_stream();
    let initial_event = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        std::str::from_utf8(&initial_event)
            .unwrap()
            .contains("event: sync")
    );

    let avatar = test_avatar_data_url();
    let update = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/me/profile")
                .header(header::COOKIE, user_cookie)
                .header("x-csrf-token", user_csrf)
                .header("content-type", "application/json")
                .body(Body::from(json!({"avatar_data_url": avatar}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(update.status(), StatusCode::OK);

    let changed = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        std::str::from_utf8(&changed)
            .unwrap()
            .contains("event: profile_changed")
    );

    let synced = json_body(agent_profile(&app, token).await).await;
    assert_eq!(synced["account"]["avatar_url"], avatar);
    let relogin =
        json_body(agent_login(&app, "avatar-sync-user", "avatar-sync-password").await).await;
    assert_eq!(relogin["account"]["avatar_url"], avatar);
}

#[tokio::test]
async fn agent_event_stream_requires_a_valid_bearer_token() {
    let (_directory, app) = test_app().await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/agent/events")
                .header(header::AUTHORIZATION, "Bearer invalid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn agent_sync_reports_disabled_account_without_logging_it_out() {
    let (_directory, app) = test_app().await;
    let (admin_cookie, admin_csrf) = login_admin(&app).await;
    create_approved_user(
        &app,
        &admin_cookie,
        &admin_csrf,
        "disabled-sync",
        "disabled-sync-password",
    )
    .await;
    let login = json_body(agent_login(&app, "disabled-sync", "disabled-sync-password").await).await;
    let token = login["agent_access_token"].as_str().unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/admin/users/disabled-sync")
                .header(header::COOKIE, admin_cookie)
                .header("x-csrf-token", admin_csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "status": "disabled",
                        "audit_reason": "停用同步测试账号"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = agent_profile(&app, token).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["account"]["status"], "disabled");
    assert_eq!(body["profile"]["username"], "disabled-sync");

    let response = agent_login(&app, "disabled-sync", "disabled-sync-password").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn agent_sync_rejects_tampered_bearer_tokens() {
    let (_directory, app) = test_app().await;
    let response = agent_profile(&app, "not-a-valid-token").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn agent_credentials_are_not_exposed_to_browser_origin_requests() {
    let (_directory, app) = test_app().await;
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/login")
                .header(header::ORIGIN, "https://attacker.example")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"username": "admin", "password": "admin-test-password"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn malformed_agent_login_does_not_echo_submitted_secret() {
    let (_directory, app) = test_app().await;
    let submitted_secret = "malformed-login-secret";
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/login")
                .header("content-type", "application/json")
                .body(Body::from(json!(submitted_secret).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = json_body(response).await;
    assert_eq!(body["error"]["code"], "invalid_json");
    assert!(!body.to_string().contains(submitted_secret));
}

async fn agent_login(app: &Router, username: &str, password: &str) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"username": username, "password": password}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn agent_profile(app: &Router, token: &str) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/agent/me")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

fn test_avatar_data_url() -> String {
    let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
    png.extend_from_slice(&64_u32.to_be_bytes());
    png.extend_from_slice(&64_u32.to_be_bytes());
    format!(
        "data:image/png;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(png)
    )
}
