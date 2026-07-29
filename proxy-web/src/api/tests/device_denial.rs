use super::common::*;

#[tokio::test]
async fn denied_agent_device_authorization_cannot_be_claimed() {
    let (_directory, app) = test_app().await;
    let (admin_cookie, admin_csrf) = login_admin(&app).await;
    create_approved_user(
        &app,
        &admin_cookie,
        &admin_csrf,
        "deny-device-user",
        "deny-device-password",
    )
    .await;
    let (user_cookie, user_csrf) =
        login_user(&app, "deny-device-user", "deny-device-password").await;
    let (device_code, user_code) = start_device_authorization(&app, "android").await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/device-authorizations/deny")
                .header(header::COOKIE, user_cookie)
                .header("x-csrf-token", user_csrf)
                .header("content-type", "application/json")
                .body(Body::from(json!({"user_code": user_code}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["status"], "denied");

    let response = poll_device_authorization(&app, &device_code).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(json_body(response).await["error"]["code"], "access_denied");
}

#[tokio::test]
async fn unknown_api_is_json_and_never_cached() {
    let (_directory, app) = test_app().await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v9/missing")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(json_body(response).await["error"]["code"], "not_found");
}

#[test]
fn new_users_receive_proxy_and_key_permissions_by_default() {
    assert_eq!(
        default_web_permissions(),
        vec![
            "key.private.read",
            "key.rotate",
            "proxy.connect.tcp",
            "proxy.connect.udp",
        ]
    );
    assert_eq!(
        with_required_web_permissions(vec![
            "proxy.connect.tcp".to_string(),
            "audit.read".to_string(),
            "audit.read".to_string(),
        ]),
        vec![
            "audit.read",
            "key.private.read",
            "key.rotate",
            "proxy.connect.tcp",
            "proxy.connect.udp",
        ]
    );
}
