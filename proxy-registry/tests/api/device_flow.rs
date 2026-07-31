use super::common::*;

#[tokio::test]
async fn agent_device_flow_rate_limits_and_delivers_credentials_once() {
    let (_directory, app) = test_app().await;
    let (admin_cookie, admin_csrf) = login_admin(&app).await;
    create_approved_user(
        &app,
        &admin_cookie,
        &admin_csrf,
        "agent-alice",
        "agent-alice-password",
    )
    .await;
    let (user_cookie, user_csrf) = login_user(&app, "agent-alice", "agent-alice-password").await;
    let (device_code, user_code) = start_device_authorization(&app, "android").await;

    let response = poll_device_authorization(&app, &device_code).await;
    assert_eq!(response.status(), StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(
        response.headers().get(header::RETRY_AFTER).unwrap(),
        AGENT_DEVICE_POLL_INTERVAL_SECONDS.to_string().as_str()
    );
    assert_eq!(
        json_body(response).await["error"]["code"],
        "authorization_pending"
    );

    let response = poll_device_authorization(&app, &device_code).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(response.headers().contains_key(header::RETRY_AFTER));
    assert_eq!(json_body(response).await["error"]["code"], "slow_down");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/device-authorizations/inspect")
                .header(header::COOKIE, &user_cookie)
                .header("content-type", "application/json")
                .body(Body::from(json!({"user_code": &user_code}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/device-authorizations/inspect")
                .header(header::COOKIE, &user_cookie)
                .header("x-csrf-token", &user_csrf)
                .header("content-type", "application/json")
                .body(Body::from(json!({"user_code": &user_code}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["client_name"], "Test Agent");
    assert_eq!(body["platform"], "android");
    assert_eq!(body["status"], "pending");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/device-authorizations/approve")
                .header(header::COOKIE, &user_cookie)
                .header("x-csrf-token", &user_csrf)
                .header("content-type", "application/json")
                .body(Body::from(json!({"user_code": user_code}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["status"], "authorized");

    let response = poll_device_authorization(&app, &device_code).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("ppaass_session=")
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let body = json_body(response).await;
    assert_eq!(body["account"]["login_name"], "agent-alice");
    assert_eq!(body["account"]["role"], "user");
    assert_eq!(body["profile"]["username"], "agent-alice");
    assert!(
        body["profile"]["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|permission| permission == PRIVATE_KEY_READ_PERMISSION)
    );
    assert!(
        body["private_key_pem"]
            .as_str()
            .unwrap()
            .contains("BEGIN PRIVATE KEY")
    );
    assert!(
        body["public_key_pem"]
            .as_str()
            .unwrap()
            .contains("BEGIN PUBLIC KEY")
    );
    let serialized = body.to_string();
    assert!(serialized.len() < MAX_AGENT_TOKEN_RESPONSE_BYTES);
    for forbidden in ["device_code", "user_code"] {
        assert!(!serialized.contains(forbidden));
    }

    let response = poll_device_authorization(&app, &device_code).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await["error"]["code"],
        "invalid_device_code"
    );
}

#[tokio::test]
async fn failed_credential_construction_does_not_burn_device_code() {
    let (_directory, store, _sessions, _handoffs, _private_keys, app) =
        test_app_with_components().await;
    let (admin_cookie, admin_csrf) = login_admin(&app).await;
    create_approved_user(
        &app,
        &admin_cookie,
        &admin_csrf,
        "retry-device-user",
        "retry-device-password",
    )
    .await;
    let (user_cookie, user_csrf) =
        login_user(&app, "retry-device-user", "retry-device-password").await;
    let (device_code, user_code) = start_device_authorization(&app, "android").await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/device-authorizations/approve")
                .header(header::COOKIE, user_cookie)
                .header("x-csrf-token", user_csrf)
                .header("content-type", "application/json")
                .body(Body::from(json!({"user_code": &user_code}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let broken_agent_events = AgentEventHub::start(store.clone()).await.unwrap();
    let broken_app = build_router(
        AppState {
            instance_id: Arc::from("registry-test-broken"),
            users: store.clone(),
            accounts: store.clone(),
            access_logs: store.clone(),
            device_authorizations: store.clone(),
            proxy_addresses: store.clone(),
            audit_logs: store.clone(),
            passwords: PasswordService::new(1).await.unwrap(),
            sessions: SessionStore::new(false),
            agent_tokens: AgentAccessTokenService::new(MASTER_SECRET).unwrap(),
            agent_events: broken_agent_events,
            web_session_handoffs: AgentWebSessionHandoffStore::new(store.clone()),
            private_keys: PrivateKeyCipher::new(
                "different-test-secret-that-cannot-decrypt-existing-keys",
            )
            .unwrap(),
            allow_registration: true,
            device_authorization_guard: AgentDeviceAuthorizationGuard::default(),
        },
        None,
    );
    let response = poll_device_authorization(&broken_app, &device_code).await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let authorization = store
        .get_agent_device_authorization_by_user_code(
            &hash_agent_user_code(&user_code).unwrap(),
            current_timestamp(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        authorization.status,
        AgentDeviceAuthorizationStatus::Authorized
    );

    let response = poll_device_authorization(&app, &device_code).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        json_body(response).await["private_key_pem"]
            .as_str()
            .unwrap()
            .contains("BEGIN PRIVATE KEY")
    );
}
