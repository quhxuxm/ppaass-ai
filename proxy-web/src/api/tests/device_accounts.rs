use super::common::*;

#[tokio::test]
async fn existing_external_account_session_can_authorize_agent_without_a_password() {
    let (_directory, store, sessions, private_keys, app) = test_app_with_components().await;
    let account = store
        .create_user_account(NewUserAccount {
            account_id: "acc_external_only".to_string(),
            login_name: "external_device_user".to_string(),
            password_hash: None,
            display_name: Some("Historical External User".to_string()),
            email: Some("device@example.test".to_string()),
            avatar_url: None,
            external_identity: Some(ExternalIdentity {
                provider: "retired-provider".to_string(),
                subject: "retired-subject-device-only".to_string(),
            }),
        })
        .await
        .unwrap();
    let request = store
        .submit_key_generation_request(NewKeyGenerationRequest {
            request_id: "keyreq_external_device".to_string(),
            account_id: account.account_id.clone(),
        })
        .await
        .unwrap();
    let stored_keys = generate_stored_keys(&private_keys, &account.login_name, 1)
        .await
        .unwrap();
    let mut profile = NewUser::new(
        &account.login_name,
        stored_keys.public_key_pem,
        UserOrigin::Local,
    );
    profile.permissions = default_web_permissions();
    profile.expires_at = Some(FUTURE_EXPIRATION);
    store
        .approve_key_generation_request(KeyRequestApproval {
            request_id: request.request_id,
            reviewer_account_id: "acc_admin".to_string(),
            expires_at: FUTURE_EXPIRATION,
            material: ApprovedKeyMaterial::Initial {
                profile,
                encrypted_private_key: stored_keys.encrypted_private_key,
            },
        })
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "username": account.login_name,
                        "password": "cannot-login-with-password"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let (device_code, user_code) = start_device_authorization(&app, "windows").await;
    let (browser_session, browser_cookie) = sessions.issue(&account.account_id);
    let browser_cookie = browser_cookie
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/device-authorizations/approve")
                .header(header::COOKIE, browser_cookie)
                .header("x-csrf-token", browser_session.csrf_token)
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
    assert_eq!(body["account"]["account_id"], "acc_external_only");
    assert_eq!(body["profile"]["username"], "external_device_user");
    assert!(
        body["private_key_pem"]
            .as_str()
            .unwrap()
            .contains("BEGIN PRIVATE KEY")
    );
}

#[tokio::test]
async fn agent_device_approval_rejects_admin_missing_keys_and_cross_origin_clients() {
    let (_directory, store, _sessions, _private_keys, app) = test_app_with_components().await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/device-authorizations")
                .header(header::ORIGIN, "https://attacker.example")
                .header("content-type", "application/json")
                .body(Body::from(json!({"platform":"android"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let (admin_cookie, admin_csrf) = login_admin(&app).await;
    let (_admin_device_code, admin_user_code) = start_device_authorization(&app, "android").await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/device-authorizations/approve")
                .header(header::COOKIE, &admin_cookie)
                .header("x-csrf-token", &admin_csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"user_code": admin_user_code}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let (user_cookie, user_csrf) =
        register_user(&app, "waiting-user", "waiting-user-password").await;
    let (waiting_device_code, waiting_user_code) =
        start_device_authorization(&app, "android").await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/device-authorizations/approve")
                .header(header::COOKIE, &user_cookie)
                .header("x-csrf-token", &user_csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"user_code": waiting_user_code}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_body(response).await["error"]["code"],
        "key_request_required"
    );
    let response = poll_device_authorization(&app, &waiting_device_code).await;
    assert_eq!(response.status(), StatusCode::PRECONDITION_REQUIRED);

    create_approved_user(
        &app,
        &admin_cookie,
        &admin_csrf,
        "no-private-read",
        "no-private-read-password",
    )
    .await;
    store
        .update_user(
            "no-private-read",
            UserUpdate {
                permissions: Some(vec![
                    PROXY_CONNECT_TCP_PERMISSION.to_string(),
                    PROXY_CONNECT_UDP_PERMISSION.to_string(),
                ]),
                ..UserUpdate::default()
            },
        )
        .await
        .unwrap();
    let (limited_cookie, limited_csrf) =
        login_user(&app, "no-private-read", "no-private-read-password").await;
    let (_limited_device_code, limited_user_code) =
        start_device_authorization(&app, "windows").await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/device-authorizations/approve")
                .header(header::COOKIE, limited_cookie)
                .header("x-csrf-token", limited_csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"user_code": limited_user_code}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(response).await["error"]["code"], "forbidden");

    for (username, update, expected_status, expected_code) in [
        (
            "disabled-device",
            UserUpdate {
                enabled: Some(false),
                ..UserUpdate::default()
            },
            StatusCode::FORBIDDEN,
            "forbidden",
        ),
        (
            "expired-device",
            UserUpdate {
                expires_at: Some(Some(current_timestamp() - 1)),
                ..UserUpdate::default()
            },
            StatusCode::CONFLICT,
            "key_request_required",
        ),
    ] {
        let password = format!("{username}-password");
        create_approved_user(&app, &admin_cookie, &admin_csrf, username, &password).await;
        store.update_user(username, update).await.unwrap();
        let (cookie, csrf) = login_user(&app, username, &password).await;
        let (_device_code, user_code) = start_device_authorization(&app, "android").await;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/agent/device-authorizations/approve")
                    .header(header::COOKIE, cookie)
                    .header("x-csrf-token", csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(json!({"user_code": user_code}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected_status);
        assert_eq!(json_body(response).await["error"]["code"], expected_code);
    }
}
