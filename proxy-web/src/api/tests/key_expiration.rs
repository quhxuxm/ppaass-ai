use super::common::*;

#[tokio::test]
async fn expired_key_is_hidden_and_can_only_be_restored_by_approval() {
    let (_directory, app) = test_app().await;
    let (admin_cookie, admin_csrf) = login_admin(&app).await;
    create_approved_user(
        &app,
        &admin_cookie,
        &admin_csrf,
        "expired-user",
        "expired-user-password",
    )
    .await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/admin/users/expired-user")
                .header(header::COOKIE, &admin_cookie)
                .header("x-csrf-token", &admin_csrf)
                .header("content-type", "application/json")
                .body(Body::from(json!({"expires_at": 1}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_admin_response_is_redacted(&json_body(response).await);
    let (cookie, csrf) = login_user(&app, "expired-user", "expired-user-password").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/me")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["key_state"], "expired");
    assert!(!body.to_string().contains("public_key_pem"));

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/me/private-key")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(
        !json_body(response)
            .await
            .to_string()
            .contains("PRIVATE KEY")
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/me/rotate-key")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users/expired-user/rotate-key")
                .header(header::COOKIE, &admin_cookie)
                .header("x-csrf-token", &admin_csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    for expires_at in [Value::Null, json!(LATER_FUTURE_EXPIRATION)] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/api/v1/admin/users/expired-user")
                    .header(header::COOKIE, &admin_cookie)
                    .header("x-csrf-token", &admin_csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"expires_at": expires_at}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            matches!(
                response.status(),
                StatusCode::BAD_REQUEST | StatusCode::CONFLICT
            ),
            "过期密钥不能通过 PATCH 恢复"
        );
    }

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
    assert_eq!(response.status(), StatusCode::CREATED);
    let request = json_body(response).await;
    assert_eq!(request["kind"], "rotate");
    let request_id = request["request_id"].as_str().unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/key-requests/{request_id}/approve"))
                .header(header::COOKIE, &admin_cookie)
                .header("x-csrf-token", &admin_csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "expires_at": LATER_FUTURE_EXPIRATION,
                        "proxy_address_ids": [TEST_PROXY_ADDRESS_ID]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["user"]["profile"]["key_version"], 2);
    assert_admin_response_is_redacted(&body);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/me/private-key")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        json_body(response).await["private_key_pem"]
            .as_str()
            .unwrap()
            .contains("PRIVATE KEY")
    );
}

#[tokio::test]
async fn concurrent_key_requests_are_idempotent_and_rejection_allows_retry() {
    let (_directory, app) = test_app().await;
    let (cookie, csrf) = register_user(&app, "request-user", "request-user-password").await;

    let first = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/api/v1/me/key-requests")
            .header(header::COOKIE, &cookie)
            .header("x-csrf-token", &csrf)
            .body(Body::empty())
            .unwrap(),
    );
    let second = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/api/v1/me/key-requests")
            .header(header::COOKIE, &cookie)
            .header("x-csrf-token", &csrf)
            .body(Body::empty())
            .unwrap(),
    );
    let (first, second) = tokio::join!(first, second);
    let first = first.unwrap();
    let second = second.unwrap();
    assert!(
        matches!(
            (first.status(), second.status()),
            (StatusCode::CREATED, StatusCode::OK) | (StatusCode::OK, StatusCode::CREATED)
        ),
        "并发提交必须恰好创建一条待审批申请"
    );
    let first = json_body(first).await;
    let second = json_body(second).await;
    assert_eq!(first["request_id"], second["request_id"]);
    let rejected_request_id = first["request_id"].as_str().unwrap().to_string();

    let (admin_cookie, admin_csrf) = login_admin(&app).await;
    let reject_uri = format!("/api/v1/admin/key-requests/{rejected_request_id}/reject");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&reject_uri)
                .header(header::COOKIE, &admin_cookie)
                .header("x-csrf-token", &admin_csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["request"]["status"], "rejected");
    assert!(body["user"].is_null());
    assert_admin_response_is_redacted(&body);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(reject_uri)
                .header(header::COOKIE, &admin_cookie)
                .header("x-csrf-token", &admin_csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/me/key-request")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(json_body(response).await["request"].is_null());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/me/key-requests")
                .header(header::COOKIE, cookie)
                .header("x-csrf-token", csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_ne!(json_body(response).await["request_id"], rejected_request_id);
}
