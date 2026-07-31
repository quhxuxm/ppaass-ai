use super::common::*;

#[tokio::test]
async fn registration_and_admin_creation_share_the_eight_character_password_minimum() {
    let (_directory, app) = test_app().await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "username": "short-registration-password",
                        "password": "1234567"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        json_body(response).await["error"]["message"]
            .as_str()
            .unwrap()
            .contains('8')
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "username": "boundary-registration-password",
                        "password": "12345678"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let (admin_cookie, admin_csrf) = login_admin(&app).await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header(header::COOKIE, &admin_cookie)
                .header("x-csrf-token", &admin_csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "username": "short-admin-password",
                        "password": "1234567",
                        "expires_at": FUTURE_EXPIRATION,
                        "proxy_address_ids": [TEST_PROXY_ADDRESS_ID],
                        "audit_reason": "测试短密码"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        json_body(response).await["error"]["message"]
            .as_str()
            .unwrap()
            .contains('8')
    );

    let created = create_approved_user(
        &app,
        &admin_cookie,
        &admin_csrf,
        "boundary-admin-password",
        "abcdefgh",
    )
    .await;
    assert_eq!(
        created["user"]["account"]["login_name"],
        "boundary-admin-password"
    );
    login_user(&app, "boundary-admin-password", "abcdefgh").await;
}

#[tokio::test]
async fn password_login_does_not_reveal_account_existence() {
    let (_directory, store, _sessions, _handoffs, _private_keys, app) =
        test_app_with_components().await;
    register_user(&app, "disabled-user", "disabled-user-password").await;
    let disabled = store
        .get_account_by_login("disabled-user")
        .await
        .unwrap()
        .unwrap();
    store
        .update_managed_user(
            &disabled.account_id,
            ManagedUserUpdate {
                status: Some(AccountStatus::Disabled),
                changed_by: Some(AccountActor {
                    account_id: "acc_admin".to_string(),
                    login_name: "admin".to_string(),
                }),
                audit_reason: Some("测试登录停用账号".to_string()),
                ..ManagedUserUpdate::default()
            },
        )
        .await
        .unwrap();

    let disabled_response = login_from_peer(
        &app,
        "disabled-user",
        "disabled-user-password",
        "203.0.113.101:32001",
    )
    .await;
    let missing_response = login_from_peer(
        &app,
        "missing-user",
        "disabled-user-password",
        "203.0.113.102:32002",
    )
    .await;
    let malformed_response =
        login_from_peer(&app, "", "disabled-user-password", "203.0.113.103:32003").await;
    assert_eq!(disabled_response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(missing_response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(malformed_response.status(), StatusCode::UNAUTHORIZED);
    let disabled_body = json_body(disabled_response).await;
    assert_eq!(json_body(missing_response).await, disabled_body);
    assert_eq!(json_body(malformed_response).await, disabled_body);
}
