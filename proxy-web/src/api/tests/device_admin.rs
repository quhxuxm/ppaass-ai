use super::common::*;

#[tokio::test]
async fn admin_with_an_active_profile_can_manage_keys_records_and_authorize_agent() {
    let (_directory, store, _sessions, _handoffs, _private_keys, app) =
        test_app_with_components().await;
    let (admin_cookie, admin_csrf) = login_admin(&app).await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/me/key-requests")
                .header(header::COOKIE, &admin_cookie)
                .header("x-csrf-token", &admin_csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let request_id = json_body(response).await["request_id"]
        .as_str()
        .unwrap()
        .to_string();
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
                        "expires_at": FUTURE_EXPIRATION,
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
    assert_eq!(body["user"]["account"]["role"], "admin");
    assert_eq!(body["user"]["profile"]["username"], "admin");
    assert_admin_response_is_redacted(&body);

    store
        .record_access(NewAccessRecord {
            username: "admin".to_string(),
            protocol: AccessProtocol::Tcp,
            target_host: "admin-traffic.example".to_string(),
            target_port: 443,
            accessed_at: current_timestamp(),
        })
        .await
        .unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/me/access-records")
                .header(header::COOKIE, &admin_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await["records"][0]["target_host"],
        "admin-traffic.example"
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/me/rotate-key")
                .header(header::COOKIE, &admin_cookie)
                .header("x-csrf-token", &admin_csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["key_version"], 2);

    let (device_code, user_code) = start_device_authorization(&app, "android").await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/device-authorizations/approve")
                .header(header::COOKIE, &admin_cookie)
                .header("x-csrf-token", &admin_csrf)
                .header("content-type", "application/json")
                .body(Body::from(json!({"user_code": user_code}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = poll_device_authorization(&app, &device_code).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["account"]["role"], "admin");
    assert_eq!(body["profile"]["username"], "admin");
    assert_eq!(body["profile"]["key_version"], 2);
    assert!(
        body["private_key_pem"]
            .as_str()
            .unwrap()
            .contains("BEGIN PRIVATE KEY")
    );
}
