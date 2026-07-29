use super::common::*;

#[tokio::test]
async fn access_records_are_owner_scoped_redacted_and_retention_is_admin_managed() {
    let (directory, app) = test_app().await;
    let (admin_cookie, admin_csrf) = login_admin(&app).await;
    create_approved_user(
        &app,
        &admin_cookie,
        &admin_csrf,
        "access-alice",
        "access-alice-password",
    )
    .await;
    create_approved_user(
        &app,
        &admin_cookie,
        &admin_csrf,
        "access-bob",
        "access-bob-password",
    )
    .await;

    let store = SqliteUserRepository::connect(directory.path().join("users.sqlite3"))
        .await
        .unwrap();
    let now = current_timestamp();
    for record in [
        NewAccessRecord {
            username: "access-alice".to_string(),
            protocol: AccessProtocol::Udp,
            target_host: "CURRENT.EXAMPLE".to_string(),
            target_port: 8443,
            accessed_at: now - 1,
        },
        NewAccessRecord {
            username: "access-alice".to_string(),
            protocol: AccessProtocol::Tcp,
            target_host: "current.example".to_string(),
            target_port: 443,
            accessed_at: now,
        },
        NewAccessRecord {
            username: "access-alice".to_string(),
            protocol: AccessProtocol::Udp,
            target_host: "two-days-old.example".to_string(),
            target_port: 53,
            accessed_at: now - 2 * SECONDS_PER_DAY,
        },
        NewAccessRecord {
            username: "access-bob".to_string(),
            protocol: AccessProtocol::Tcp,
            target_host: "bob-private.example".to_string(),
            target_port: 8443,
            accessed_at: now,
        },
    ] {
        store.record_access(record).await.unwrap();
    }

    let (alice_cookie, _alice_csrf) =
        login_user(&app, "access-alice", "access-alice-password").await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/me/access-records?limit=10&since=0")
                .header(header::COOKIE, &alice_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["retention_days"], 7);
    assert_eq!(body["records"].as_array().unwrap().len(), 2);
    assert_eq!(body.as_object().unwrap().len(), 2);
    for record in body["records"].as_array().unwrap() {
        let object = record.as_object().unwrap();
        assert_eq!(object.len(), 5);
        for field in [
            "target_host",
            "target_port",
            "protocol",
            "access_count",
            "accessed_at",
        ] {
            assert!(object.contains_key(field));
        }
    }
    assert_eq!(body["records"][0]["target_host"], "current.example");
    assert_eq!(body["records"][0]["target_port"], 443);
    assert_eq!(body["records"][0]["protocol"], "tcp");
    assert_eq!(body["records"][0]["access_count"], 2);
    let serialized = body.to_string();
    for forbidden in ["access-alice", "access-bob", "bob-private", "record_id"] {
        assert!(
            !serialized.contains(forbidden),
            "访问记录响应不应包含 {forbidden}: {serialized}"
        );
    }

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/me/access-records?username=access-bob")
                .header(header::COOKIE, &alice_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/me/access-records?limit={}",
                    MAX_ACCESS_LOG_QUERY_LIMIT + 1
                ))
                .header(header::COOKIE, &alice_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/me/access-records?since={}", now + 1))
                .header(header::COOKIE, &alice_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        json_body(response).await["records"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/access-log-settings")
                .header(header::COOKIE, &alice_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/access-log-settings")
                .header(header::COOKIE, &admin_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["retention_days"], 7);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/admin/access-log-settings")
                .header(header::COOKIE, &admin_cookie)
                .header("content-type", "application/json")
                .body(Body::from(json!({"retention_days": 1}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    for retention_days in [0, MAX_ACCESS_LOG_RETENTION_DAYS + 1] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/api/v1/admin/access-log-settings")
                    .header(header::COOKIE, &admin_cookie)
                    .header("x-csrf-token", &admin_csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"retention_days": retention_days}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/admin/access-log-settings")
                .header(header::COOKIE, &admin_cookie)
                .header("x-csrf-token", &admin_csrf)
                .header("content-type", "application/json")
                .body(Body::from(json!({"retention_days": 1}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["retention_days"], 1);
    assert!(body["purged_records"].as_u64().unwrap() >= 1);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/me/access-records?limit=10&since=0")
                .header(header::COOKIE, alice_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = json_body(response).await;
    assert_eq!(body["retention_days"], 1);
    assert_eq!(body["records"].as_array().unwrap().len(), 1);
    assert_eq!(body["records"][0]["target_host"], "current.example");
}
