use super::common::*;
use base64::Engine;

#[tokio::test]
async fn admin_agent_lists_approves_and_rejects_key_requests() {
    let (_directory, app) = test_app().await;
    let (root_cookie, root_csrf) = login_admin(&app).await;
    create_approved_user(
        &app,
        &root_cookie,
        &root_csrf,
        "agent-admin",
        "agent-admin-password",
    )
    .await;
    set_user_role(&app, &root_cookie, &root_csrf, "agent-admin", "admin").await;
    let admin_token = agent_login_token(&app, "agent-admin", "agent-admin-password").await;

    let user_token = create_agent_user(
        &app,
        &root_cookie,
        &root_csrf,
        "ordinary-agent",
        "ordinary-agent-password",
    )
    .await;
    let response = native_get(&app, "/api/v1/admin/key-requests", &user_token).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let first_request = register_and_request_key(
        &app,
        "requester-one",
        "requester-one-password",
        "请批准第一份密钥",
    )
    .await;
    let list = native_get(&app, "/api/v1/admin/key-requests", &admin_token).await;
    assert_eq!(list.status(), StatusCode::OK);
    let body = json_body(list).await;
    assert_eq!(body["requests"][0]["request_id"], first_request);
    assert_eq!(body["requests"][0]["request_message"], "请批准第一份密钥");
    assert_eq!(
        body["requests"][0]["account"]["avatar_url"],
        test_avatar_data_url()
    );
    assert_admin_response_is_redacted(&body);

    let addresses = native_get(&app, "/api/v1/admin/proxy-addresses", &admin_token).await;
    assert_eq!(addresses.status(), StatusCode::OK);
    assert_eq!(
        json_body(addresses).await["proxy_addresses"][0]["proxy_address_id"],
        TEST_PROXY_ADDRESS_ID
    );

    let approved = native_decision(
        &app,
        &format!("/api/v1/admin/key-requests/{first_request}/approve"),
        &admin_token,
        Some(json!({
            "expires_at": FUTURE_EXPIRATION,
            "proxy_address_ids": [TEST_PROXY_ADDRESS_ID]
        })),
    )
    .await;
    assert_eq!(approved.status(), StatusCode::OK);
    let body = json_body(approved).await;
    assert_eq!(body["request"]["status"], "approved");
    assert_eq!(body["request"]["reviewer_login_name"], "agent-admin");
    assert_admin_response_is_redacted(&body);

    let second_request = register_and_request_key(
        &app,
        "requester-two",
        "requester-two-password",
        "这份申请用于拒绝测试",
    )
    .await;
    let rejected = native_decision(
        &app,
        &format!("/api/v1/admin/key-requests/{second_request}/reject"),
        &admin_token,
        Some(json!({"reason": "用途说明不足，请补充后重新申请。"})),
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::OK);
    let body = json_body(rejected).await;
    assert_eq!(body["request"]["status"], "rejected");
    assert_eq!(body["request"]["reviewer_login_name"], "agent-admin");
    assert_eq!(
        body["request"]["rejection_reason"],
        "用途说明不足，请补充后重新申请。"
    );

    set_user_status(&app, &root_cookie, &root_csrf, "agent-admin", "disabled").await;
    let disabled = native_get(&app, "/api/v1/admin/key-requests", &admin_token).await;
    assert_eq!(disabled.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_agent_requests_reject_browser_and_mixed_credentials() {
    let (_directory, app) = test_app().await;
    let (root_cookie, root_csrf) = login_admin(&app).await;
    create_approved_user(
        &app,
        &root_cookie,
        &root_csrf,
        "secure-agent-admin",
        "secure-agent-admin-password",
    )
    .await;
    set_user_role(
        &app,
        &root_cookie,
        &root_csrf,
        "secure-agent-admin",
        "admin",
    )
    .await;
    let token = agent_login_token(&app, "secure-agent-admin", "secure-agent-admin-password").await;

    for request in [
        Request::builder()
            .uri("/api/v1/admin/key-requests")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::ORIGIN, "https://attacker.example"),
        Request::builder()
            .uri("/api/v1/admin/key-requests")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::COOKIE, &root_cookie),
    ] {
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    let native_cross_origin_mutation = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/key-requests/not-found/approve")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::ORIGIN, "https://attacker.example")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "expires_at": FUTURE_EXPIRATION,
                        "proxy_address_ids": [TEST_PROXY_ADDRESS_ID]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(native_cross_origin_mutation.status(), StatusCode::FORBIDDEN);

    let browser_cross_site_mutation = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/key-requests/not-found/reject")
                .header(header::COOKIE, &root_cookie)
                .header("x-csrf-token", &root_csrf)
                .header("sec-fetch-site", "cross-site")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(browser_cross_site_mutation.status(), StatusCode::FORBIDDEN);

    let invalid = native_get(&app, "/api/v1/admin/key-requests", "invalid-token").await;
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
}

async fn create_agent_user(
    app: &Router,
    cookie: &str,
    csrf: &str,
    username: &str,
    password: &str,
) -> String {
    create_approved_user(app, cookie, csrf, username, password).await;
    agent_login_token(app, username, password).await
}

async fn agent_login_token(app: &Router, username: &str, password: &str) -> String {
    let response = app
        .clone()
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
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await["agent_access_token"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn register_and_request_key(
    app: &Router,
    username: &str,
    password: &str,
    message: &str,
) -> String {
    let (cookie, csrf) = register_user(app, username, password).await;
    let avatar = test_avatar_data_url();
    let profile = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/me/profile")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(json!({"avatar_data_url": avatar}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(profile.status(), StatusCode::OK);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/me/key-requests")
                .header(header::COOKIE, cookie)
                .header("x-csrf-token", csrf)
                .header("content-type", "application/json")
                .body(Body::from(json!({"message": message}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    json_body(response).await["request_id"]
        .as_str()
        .unwrap()
        .to_string()
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

async fn set_user_role(app: &Router, cookie: &str, csrf: &str, username: &str, role: &str) {
    patch_user(app, cookie, csrf, username, json!({"role": role})).await;
}

async fn set_user_status(app: &Router, cookie: &str, csrf: &str, username: &str, status: &str) {
    patch_user(app, cookie, csrf, username, json!({"status": status})).await;
}

async fn patch_user(app: &Router, cookie: &str, csrf: &str, username: &str, body: Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/admin/users/{username}"))
                .header(header::COOKIE, cookie)
                .header("x-csrf-token", csrf)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

async fn native_get(app: &Router, uri: &str, token: &str) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn native_decision(app: &Router, uri: &str, token: &str, body: Option<Value>) -> Response {
    let body = body.map(|value| value.to_string()).unwrap_or_default();
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}
