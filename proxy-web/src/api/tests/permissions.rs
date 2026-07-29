use super::common::*;

#[tokio::test]
async fn admin_permission_updates_cannot_remove_required_web_capabilities() {
    let (_directory, app) = test_app().await;
    let (cookie, csrf) = login_admin(&app).await;
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
                        "username": "permission-user",
                        "password": "permission-user-password",
                        "expires_at": FUTURE_EXPIRATION,
                        "permissions": ["audit.read"]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        json_body(response).await["user"]["profile"]["permissions"],
        json!([
            "audit.read",
            "key.private.read",
            "key.rotate",
            "proxy.connect.tcp",
            "proxy.connect.udp"
        ])
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/admin/users/permission-user")
                .header(header::COOKIE, cookie)
                .header("x-csrf-token", csrf)
                .header("content-type", "application/json")
                .body(Body::from(json!({"permissions": []}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await["profile"]["permissions"],
        json!([
            "key.private.read",
            "key.rotate",
            "proxy.connect.tcp",
            "proxy.connect.udp"
        ])
    );
}

#[tokio::test]
async fn legacy_database_permission_update_does_not_gain_private_key_capabilities() {
    let (directory, app) = test_app().await;
    let store = SqliteUserRepository::connect(directory.path().join("users.sqlite3"))
        .await
        .unwrap();
    let public_key = RsaKeyPair::generate(2048)
        .unwrap()
        .public_key_to_pem()
        .unwrap();
    store
        .create_user_record(NewUser::new("legacy-user", public_key, UserOrigin::Legacy))
        .await
        .unwrap();

    let (cookie, csrf) = login_admin(&app).await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/admin/users/legacy-user")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"permissions": ["legacy.audit"]}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["profile"]["origin"], "legacy");
    assert_eq!(body["profile"]["permissions"], json!(["legacy.audit"]));
    assert_admin_response_is_redacted(&body);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users/legacy-user/rotate-key")
                .header(header::COOKIE, cookie)
                .header("x-csrf-token", csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_admin_response_is_redacted(&json_body(response).await);
}

#[tokio::test]
async fn active_user_can_rotate_own_key_but_cannot_use_admin_api() {
    let (_directory, app) = test_app().await;
    let (admin_cookie, admin_csrf) = login_admin(&app).await;
    let created = create_approved_user(
        &app,
        &admin_cookie,
        &admin_csrf,
        "rotate-user",
        "rotate-user-password",
    )
    .await;
    assert_admin_response_is_redacted(&created);
    let (cookie, csrf) = login_user(&app, "rotate-user", "rotate-user-password").await;
    let before = app
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
    let before = json_body(before).await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/me/rotate-key")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let after = json_body(response).await;
    assert_eq!(after["key_version"], 2);
    assert_ne!(after["public_key_pem"], before["public_key_pem"]);
    assert_ne!(after["private_key_pem"], before["private_key_pem"]);

    let forbidden = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/users")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
}
