use super::common::*;

#[tokio::test]
async fn admin_key_management_is_redacted_but_owner_can_read_keys() {
    let (_directory, app) = test_app().await;
    let (cookie, csrf) = login_admin(&app).await;
    let request_body = json!({
        "username":"bob",
        "password":"bob-secure-password",
        "expires_at": FUTURE_EXPIRATION,
        "proxy_address_ids": [TEST_PROXY_ADDRESS_ID]
    })
    .to_string();
    let missing_csrf = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header(header::COOKIE, &cookie)
                .header("content-type", "application/json")
                .body(Body::from(request_body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_csrf.status(), StatusCode::FORBIDDEN);

    let missing_expiration = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"username":"missing-expiry","password":"safe-user-password"})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        missing_expiration.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );

    let past_expiration = app
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
                        "username":"past-expiry",
                        "password":"safe-user-password",
                        "expires_at":1,
                        "proxy_address_ids": [TEST_PROXY_ADDRESS_ID]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(past_expiration.status(), StatusCode::BAD_REQUEST);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(request_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = json_body(response).await;
    assert_eq!(body["user"]["profile"]["username"], "bob");
    assert_eq!(body["user"]["profile"]["key_version"], 1);
    assert_admin_response_is_redacted(&body);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/users")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_admin_response_is_redacted(&json_body(response).await);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/users/bob")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_admin_response_is_redacted(&json_body(response).await);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/admin/users/bob")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(json!({"display_name": "Bob"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_admin_response_is_redacted(&json_body(response).await);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users/bob/rotate-key")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", &csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["key_version"], 2);
    assert_eq!(body["user"]["profile"]["key_version"], 2);
    assert_admin_response_is_redacted(&body);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/users/bob/private-key")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_admin_response_is_redacted(&json_body(response).await);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"username":"bob","password":"bob-secure-password"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let owner_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/me/private-key")
                .header(header::COOKIE, owner_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert!(
        body["public_key_pem"]
            .as_str()
            .unwrap()
            .contains("BEGIN PUBLIC KEY")
    );
    assert!(
        body["proxy_identity_public_key_pem"]
            .as_str()
            .unwrap()
            .contains("BEGIN PUBLIC KEY")
    );
    assert!(
        body["private_key_pem"]
            .as_str()
            .unwrap()
            .contains("BEGIN PRIVATE KEY")
    );
}
