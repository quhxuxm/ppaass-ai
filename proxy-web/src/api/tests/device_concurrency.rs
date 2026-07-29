use super::common::*;

#[tokio::test]
async fn concurrent_device_claim_returns_credentials_to_exactly_one_request() {
    let (_directory, _store, sessions, _private_keys, app) = test_app_with_components().await;
    let (admin_cookie, admin_csrf) = login_admin(&app).await;
    create_approved_user(
        &app,
        &admin_cookie,
        &admin_csrf,
        "concurrent-device-user",
        "concurrent-device-password",
    )
    .await;
    let (user_cookie, user_csrf) =
        login_user(&app, "concurrent-device-user", "concurrent-device-password").await;
    let (device_code, user_code) = start_device_authorization(&app, "windows").await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/device-authorizations/approve")
                .header(header::COOKIE, user_cookie)
                .header("x-csrf-token", user_csrf)
                .header("content-type", "application/json")
                .body(Body::from(json!({"user_code": user_code}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let sessions_before_claim = sessions.active_session_count();

    let (left, right) = tokio::join!(
        poll_device_authorization(&app, &device_code),
        poll_device_authorization(&app, &device_code)
    );
    let (success, rejected) = if left.status() == StatusCode::OK {
        (left, right)
    } else {
        (right, left)
    };
    assert_eq!(success.status(), StatusCode::OK);
    assert!(
        json_body(success).await["private_key_pem"]
            .as_str()
            .unwrap()
            .contains("BEGIN PRIVATE KEY")
    );
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(rejected).await["error"]["code"],
        "invalid_device_code"
    );
    assert_eq!(sessions.active_session_count(), sessions_before_claim + 1);
}

#[tokio::test]
async fn public_device_start_flood_is_bounded_and_returns_429() {
    let (_directory, _store, _sessions, _private_keys, app) = test_app_with_components().await;
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..64 {
        let app = app.clone();
        tasks.spawn(async move {
            app.oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/agent/device-authorizations")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "platform": "android",
                            "client_name": "Flood Test Agent"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
        });
    }
    let mut accepted = 0_i64;
    let mut rejected = 0_i64;
    while let Some(result) = tasks.join_next().await {
        let response = result.unwrap();
        match response.status() {
            StatusCode::OK => accepted += 1,
            StatusCode::TOO_MANY_REQUESTS => {
                assert!(response.headers().contains_key(header::RETRY_AFTER));
                assert_eq!(json_body(response).await["error"]["code"], "rate_limited");
                rejected += 1;
            }
            status => panic!("unexpected device start flood status: {status}"),
        }
    }
    assert!(accepted > 0 && accepted <= 40);
    assert!(rejected > 0);
}
