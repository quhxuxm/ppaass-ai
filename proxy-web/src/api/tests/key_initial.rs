use super::common::*;

#[tokio::test]
async fn legacy_empty_json_key_request_body_is_accepted() {
    let (_directory, app) = test_app().await;
    let (cookie, csrf) = register_user(&app, "legacy-empty", "legacy-empty-safe-password").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/me/key-requests")
                .header(header::COOKIE, cookie)
                .header("x-csrf-token", csrf)
                .header("content-type", "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    assert!(json_body(response).await["request_message"].is_null());
}

#[tokio::test]
async fn initial_key_request_requires_approval_before_owner_can_read_keys() {
    let (_directory, app) = test_app().await;
    let (cookie, csrf) = register_user(&app, "alice", "alice-safe-password").await;

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
    assert_eq!(body["key_state"], "missing");
    assert!(body["profile"].is_null());
    assert!(body["pending_request"].is_null());
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
    let body = json_body(response).await;
    assert!(!body.to_string().contains("PUBLIC KEY"));
    assert!(!body.to_string().contains("PRIVATE KEY"));

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

    let missing_csrf = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/me/key-requests")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_csrf.status(), StatusCode::FORBIDDEN);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/me/key-requests")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(json!({"message": "好".repeat(501)}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let request_message = "请在今晚前审批 <script>alert(1)</script>";
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/me/key-requests")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", &csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"message": format!("  {request_message}  ")}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let request = json_body(response).await;
    let request_id = request["request_id"].as_str().unwrap().to_string();
    assert_eq!(request["kind"], "initial");
    assert_eq!(request["status"], "pending");
    assert_eq!(request["request_message"], request_message);

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
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["request_id"], request_id);

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
    assert_eq!(
        json_body(response).await["request"]["request_id"],
        request_id
    );

    let (admin_cookie, admin_csrf) = login_admin(&app).await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/key-requests")
                .header(header::COOKIE, &admin_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["requests"][0]["request_id"], request_id);
    assert_eq!(body["requests"][0]["request_message"], request_message);
    assert_admin_response_is_redacted(&body);

    let approve_uri = format!("/api/v1/admin/key-requests/{request_id}/approve");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&approve_uri)
                .header(header::COOKIE, &admin_cookie)
                .header("x-csrf-token", &admin_csrf)
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&approve_uri)
                .header(header::COOKIE, &admin_cookie)
                .header("x-csrf-token", &admin_csrf)
                .header("content-type", "application/json")
                .body(Body::from(json!({"expires_at": 1}).to_string()))
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
                .uri(approve_uri)
                .header(header::COOKIE, &admin_cookie)
                .header("x-csrf-token", &admin_csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"expires_at": FUTURE_EXPIRATION}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["request"]["status"], "approved");
    assert_eq!(body["request"]["request_message"], request_message);
    assert_eq!(body["user"]["profile"]["key_version"], 1);
    assert_admin_response_is_redacted(&body);

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
    let body = json_body(response).await;
    assert_eq!(body["key_state"], "active");
    assert!(
        body["profile"]["public_key_pem"]
            .as_str()
            .unwrap()
            .contains("BEGIN PUBLIC KEY")
    );
    assert!(body["pending_request"].is_null());

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
    let body = json_body(response).await;
    assert!(
        body["public_key_pem"]
            .as_str()
            .unwrap()
            .contains("PUBLIC KEY")
    );
    assert!(
        body["private_key_pem"]
            .as_str()
            .unwrap()
            .contains("PRIVATE KEY")
    );
    assert!(
        body["proxy_identity_public_key_pem"]
            .as_str()
            .unwrap()
            .contains("BEGIN PUBLIC KEY")
    );
}
