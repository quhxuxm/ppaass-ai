use super::common::*;

#[tokio::test]
async fn missing_assignment_uses_the_stable_agent_error_code() {
    let account = WebAccount {
        account_id: "acc_unassigned".to_string(),
        login_name: "unassigned".to_string(),
        role: AccountRole::User,
        status: AccountStatus::Active,
        linked_username: Some("unassigned".to_string()),
        display_name: None,
        email: None,
        avatar_url: None,
        auth_version: 1,
        last_login_at: None,
        created_at: 1,
        updated_at: 1,
    };
    let managed = ManagedUser {
        account: Some(account.clone()),
        profile: None,
        has_private_key: false,
        providers: Vec::new(),
        assigned_proxy_addresses: Vec::new(),
    };
    let response = resolve_assigned_proxy_addresses(&managed, &account)
        .unwrap_err()
        .into_response();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_body(response).await["error"]["code"],
        "proxy_address_not_assigned"
    );
}

#[tokio::test]
async fn admin_catalog_and_user_assignments_enforce_safe_reassignment() {
    let (_directory, app) = test_app().await;
    let (cookie, csrf) = login_admin(&app).await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/proxy-addresses")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"address": "PROXY.example:0443"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = json_body(response).await;
    let proxy_address_id = created["proxy_address_id"].as_str().unwrap();
    assert_eq!(created["address"], "proxy.example:443");
    assert_eq!(created["label"], "proxy.example:443");

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
                        "username": "assigned-user",
                        "password": "assigned-user-password",
                        "expires_at": FUTURE_EXPIRATION,
                        "proxy_address_ids": [proxy_address_id],
                        "audit_reason": "创建节点分配测试用户"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        json_body(response).await["user"]["proxy_addresses"][0]["address"],
        "proxy.example:443"
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/admin/proxy-addresses/{proxy_address_id}"))
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "enabled": false,
                        "audit_reason": "测试已分配服务器不能停用"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_body(response).await["error"]["code"],
        "proxy_address_in_use"
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/admin/users/assigned-user")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"proxy_address_ids": [TEST_PROXY_ADDRESS_ID]}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await["proxy_addresses"][0]["proxy_address_id"],
        TEST_PROXY_ADDRESS_ID
    );

    for (method, expected) in [
        ("PATCH", StatusCode::OK),
        ("DELETE", StatusCode::NO_CONTENT),
    ] {
        let mut request = Request::builder()
            .method(method)
            .uri(format!("/api/v1/admin/proxy-addresses/{proxy_address_id}"))
            .header(header::COOKIE, &cookie)
            .header("x-csrf-token", &csrf);
        let body = if method == "PATCH" {
            request = request.header("content-type", "application/json");
            Body::from(
                json!({
                    "enabled": false,
                    "audit_reason": "停用未分配服务器"
                })
                .to_string(),
            )
        } else {
            Body::empty()
        };
        let response = app
            .clone()
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
}

#[tokio::test]
async fn approval_requires_addresses_and_all_credential_profiles_return_them() {
    let (_directory, app) = test_app().await;
    let (admin_cookie, admin_csrf) = login_admin(&app).await;
    let (cookie, csrf) = register_user(&app, "address-approval", "address-approval-password").await;
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
    let request_id = json_body(response).await["request_id"]
        .as_str()
        .unwrap()
        .to_string();
    let approval_uri = format!("/api/v1/admin/key-requests/{request_id}/approve");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&approval_uri)
                .header(header::COOKIE, &admin_cookie)
                .header("x-csrf-token", &admin_csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "expires_at": FUTURE_EXPIRATION,
                        "proxy_address_ids": [],
                        "reason": "测试空 Proxy 地址审批"
                    })
                    .to_string(),
                ))
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
                .uri(approval_uri)
                .header(header::COOKIE, &admin_cookie)
                .header("x-csrf-token", &admin_csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "expires_at": FUTURE_EXPIRATION,
                        "proxy_address_ids": [TEST_PROXY_ADDRESS_ID],
                        "reason": "批准并分配默认 Proxy"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/me")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        json_body(response).await["profile"]["proxy_addresses"],
        json!(["127.0.0.1:8080"])
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "username": "address-approval",
                        "password": "address-approval-password"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let login = json_body(response).await;
    assert_eq!(
        login["profile"]["proxy_addresses"],
        json!(["127.0.0.1:8080"])
    );
    let agent_token = login["agent_access_token"].as_str().unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/proxy-addresses")
                .header(header::COOKIE, &admin_cookie)
                .header("x-csrf-token", &admin_csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"label": "Changed", "address": "changed.example:9443"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let changed_id = json_body(response).await["proxy_address_id"]
        .as_str()
        .unwrap()
        .to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/admin/users/address-approval")
                .header(header::COOKIE, admin_cookie)
                .header("x-csrf-token", admin_csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"proxy_address_ids": [changed_id]}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/agent/me")
                .header(header::AUTHORIZATION, format!("Bearer {agent_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await["profile"]["proxy_addresses"],
        json!(["changed.example:9443"])
    );
}
