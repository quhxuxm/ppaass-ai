use super::common::*;

#[tokio::test]
async fn audit_events_are_admin_only_and_record_actor_reason_and_change() {
    let (_directory, app) = test_app().await;
    let (admin_cookie, admin_csrf) = login_admin(&app).await;
    create_approved_user(
        &app,
        &admin_cookie,
        &admin_csrf,
        "audit-user",
        "audit-user-password",
    )
    .await;
    let (user_cookie, _) = login_user(&app, "audit-user", "audit-user-password").await;

    let forbidden = get_audits(&app, &user_cookie).await;
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

    let missing_reason = patch_user_permissions(
        &app,
        &admin_cookie,
        &admin_csrf,
        json!({"permissions": ["agent.packet_capture"]}),
    )
    .await;
    assert_eq!(missing_reason.status(), StatusCode::BAD_REQUEST);

    let updated = patch_user_permissions(
        &app,
        &admin_cookie,
        &admin_csrf,
        json!({
            "permissions": ["agent.packet_capture"],
            "audit_reason": "批准该用户使用抓包功能"
        }),
    )
    .await;
    assert_eq!(updated.status(), StatusCode::OK);

    let disabled = patch_user_permissions(
        &app,
        &admin_cookie,
        &admin_csrf,
        json!({
            "status": "disabled",
            "enabled": false,
            "audit_reason": "账号存在异常流量，暂停登录和代理连接"
        }),
    )
    .await;
    assert_eq!(disabled.status(), StatusCode::OK);
    let reenabled = patch_user_permissions(
        &app,
        &admin_cookie,
        &admin_csrf,
        json!({
            "status": "active",
            "enabled": true,
            "audit_reason": "复核完成，恢复登录和代理连接"
        }),
    )
    .await;
    assert_eq!(reenabled.status(), StatusCode::OK);

    let response = get_audits(&app, &admin_cookie).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    let events = body["events"].as_array().unwrap();
    let permission_event = events
        .iter()
        .find(|event| {
            event["action"] == "permissions_updated"
                && event["target_name"] == "audit-user"
                && event["reason"] == "批准该用户使用抓包功能"
        })
        .expect("permission audit event");
    assert_eq!(permission_event["actor_login_name"], "admin");
    assert!(
        permission_event["new_value"]
            .as_str()
            .unwrap()
            .contains("agent.packet_capture")
    );
    assert!(events.iter().any(|event| {
        event["action"] == "proxy_access_enabled"
            && event["target_name"] == "audit-user"
            && event["reason"] == "测试创建用户"
    }));
    for action in ["web_login_disabled", "proxy_access_disabled"] {
        assert!(events.iter().any(|event| {
            event["action"] == action
                && event["target_name"] == "audit-user"
                && event["reason"] == "账号存在异常流量，暂停登录和代理连接"
        }));
    }
    for action in ["web_login_enabled", "proxy_access_enabled"] {
        assert!(events.iter().any(|event| {
            event["action"] == action
                && event["target_name"] == "audit-user"
                && event["reason"] == "复核完成，恢复登录和代理连接"
        }));
    }

    let filtered = get_audits_at(
        &app,
        &admin_cookie,
        "/api/v1/admin/audit-events?limit=100&action=permissions_updated&search=audit-user",
    )
    .await;
    assert_eq!(filtered.status(), StatusCode::OK);
    let filtered = json_body(filtered).await;
    let filtered = filtered["events"].as_array().unwrap();
    assert!(!filtered.is_empty());
    assert!(filtered.iter().all(|event| {
        event["action"] == "permissions_updated" && event["target_name"] == "audit-user"
    }));

    let wildcard = get_audits_at(
        &app,
        &admin_cookie,
        "/api/v1/admin/audit-events?limit=100&search=%25",
    )
    .await;
    assert_eq!(wildcard.status(), StatusCode::OK);
    assert!(
        json_body(wildcard).await["events"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn key_and_proxy_server_audits_require_admin_reasons() {
    let (_directory, app) = test_app().await;
    let (admin_cookie, admin_csrf) = login_admin(&app).await;
    create_approved_user(
        &app,
        &admin_cookie,
        &admin_csrf,
        "rotate-audit-user",
        "rotate-audit-password",
    )
    .await;

    let missing_rotation_reason = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users/rotate-audit-user/rotate-key")
                .header(header::COOKIE, &admin_cookie)
                .header("x-csrf-token", &admin_csrf)
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        missing_rotation_reason.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );

    let rotated = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users/rotate-audit-user/rotate-key")
                .header(header::COOKIE, &admin_cookie)
                .header("x-csrf-token", &admin_csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"reason": "定期轮换管理员托管密钥"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rotated.status(), StatusCode::OK);

    let created_proxy = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/proxy-addresses")
                .header(header::COOKIE, &admin_cookie)
                .header("x-csrf-token", &admin_csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "label": "审计备用服务器",
                        "address": "127.0.0.1:19090",
                        "enabled": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created_proxy.status(), StatusCode::CREATED);
    let proxy_id = json_body(created_proxy).await["proxy_address_id"]
        .as_str()
        .unwrap()
        .to_string();

    let missing_server_reason =
        set_proxy_enabled(&app, &admin_cookie, &admin_csrf, &proxy_id, None).await;
    assert_eq!(missing_server_reason.status(), StatusCode::BAD_REQUEST);
    let disabled = set_proxy_enabled(
        &app,
        &admin_cookie,
        &admin_csrf,
        &proxy_id,
        Some("维护窗口内停用备用服务器"),
    )
    .await;
    assert_eq!(disabled.status(), StatusCode::OK);
    let enabled = set_proxy_status(
        &app,
        &admin_cookie,
        &admin_csrf,
        &proxy_id,
        true,
        Some("维护完成，恢复备用服务器"),
    )
    .await;
    assert_eq!(enabled.status(), StatusCode::OK);

    let (request_cookie, request_csrf) =
        register_user(&app, "approval-audit-user", "approval-audit-password").await;
    let request_id = submit_key_request(&app, &request_cookie, &request_csrf).await;
    let missing_approval_reason = decide_key_request(
        &app,
        &admin_cookie,
        &admin_csrf,
        &request_id,
        "approve",
        json!({
            "expires_at": FUTURE_EXPIRATION,
            "proxy_address_ids": [TEST_PROXY_ADDRESS_ID]
        }),
    )
    .await;
    assert_eq!(
        missing_approval_reason.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let approved = decide_key_request(
        &app,
        &admin_cookie,
        &admin_csrf,
        &request_id,
        "approve",
        json!({
            "expires_at": FUTURE_EXPIRATION,
            "proxy_address_ids": [TEST_PROXY_ADDRESS_ID],
            "reason": "已核实初始密钥申请"
        }),
    )
    .await;
    assert_eq!(approved.status(), StatusCode::OK);

    let (reject_cookie, reject_csrf) =
        register_user(&app, "rejection-audit-user", "rejection-audit-password").await;
    let rejected_request_id = submit_key_request(&app, &reject_cookie, &reject_csrf).await;
    let missing_rejection_reason = decide_key_request(
        &app,
        &admin_cookie,
        &admin_csrf,
        &rejected_request_id,
        "reject",
        json!({}),
    )
    .await;
    assert_eq!(missing_rejection_reason.status(), StatusCode::BAD_REQUEST);
    let rejected = decide_key_request(
        &app,
        &admin_cookie,
        &admin_csrf,
        &rejected_request_id,
        "reject",
        json!({"reason": "用途说明不足，请补充后重新申请"}),
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::OK);

    let response = get_audits(&app, &admin_cookie).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    let events = body["events"].as_array().unwrap();
    assert!(events.iter().any(|event| {
        event["action"] == "key_regenerated"
            && event["target_name"] == "rotate-audit-user"
            && event["actor_login_name"] == "admin"
            && event["reason"] == "定期轮换管理员托管密钥"
    }));
    assert!(events.iter().any(|event| {
        event["action"] == "proxy_server_disabled"
            && event["target_id"] == proxy_id
            && event["actor_login_name"] == "admin"
            && event["reason"] == "维护窗口内停用备用服务器"
    }));
    assert!(events.iter().any(|event| {
        event["action"] == "proxy_server_enabled"
            && event["target_id"] == proxy_id
            && event["actor_login_name"] == "admin"
            && event["reason"] == "维护完成，恢复备用服务器"
    }));
    assert!(events.iter().any(|event| {
        event["action"] == "key_request_approved"
            && event["target_name"] == "approval-audit-user"
            && event["actor_login_name"] == "admin"
            && event["reason"] == "已核实初始密钥申请"
    }));
    assert!(events.iter().any(|event| {
        event["action"] == "key_request_rejected"
            && event["target_name"] == "rejection-audit-user"
            && event["actor_login_name"] == "admin"
            && event["reason"] == "用途说明不足，请补充后重新申请"
    }));
}

async fn get_audits(app: &Router, cookie: &str) -> Response {
    get_audits_at(app, cookie, "/api/v1/admin/audit-events?limit=100").await
}

async fn get_audits_at(app: &Router, cookie: &str, uri: &str) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn patch_user_permissions(app: &Router, cookie: &str, csrf: &str, body: Value) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/admin/users/audit-user")
                .header(header::COOKIE, cookie)
                .header("x-csrf-token", csrf)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn set_proxy_enabled(
    app: &Router,
    cookie: &str,
    csrf: &str,
    proxy_id: &str,
    reason: Option<&str>,
) -> Response {
    set_proxy_status(app, cookie, csrf, proxy_id, false, reason).await
}

async fn set_proxy_status(
    app: &Router,
    cookie: &str,
    csrf: &str,
    proxy_id: &str,
    enabled: bool,
    reason: Option<&str>,
) -> Response {
    let body = match reason {
        Some(reason) => json!({"enabled": enabled, "audit_reason": reason}),
        None => json!({"enabled": enabled}),
    };
    app.clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/admin/proxy-addresses/{proxy_id}"))
                .header(header::COOKIE, cookie)
                .header("x-csrf-token", csrf)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn submit_key_request(app: &Router, cookie: &str, csrf: &str) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/me/key-requests")
                .header(header::COOKIE, cookie)
                .header("x-csrf-token", csrf)
                .header("content-type", "application/json")
                .body(Body::from(json!({"message": "审计集成测试"}).to_string()))
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

async fn decide_key_request(
    app: &Router,
    cookie: &str,
    csrf: &str,
    request_id: &str,
    action: &str,
    body: Value,
) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/key-requests/{request_id}/{action}"))
                .header(header::COOKIE, cookie)
                .header("x-csrf-token", csrf)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}
