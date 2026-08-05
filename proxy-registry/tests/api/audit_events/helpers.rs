use super::super::common::*;

pub(super) async fn get_audits(app: &Router, cookie: &str) -> Response {
    get_audits_at(app, cookie, "/api/v1/admin/audit-events?limit=100").await
}

pub(super) async fn get_audits_at(app: &Router, cookie: &str, uri: &str) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

pub(super) async fn patch_user_permissions(
    app: &Router,
    cookie: &str,
    csrf: &str,
    body: Value,
) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/admin/users/audit-user")
                .header(header::COOKIE, cookie)
                .header("x-csrf-token", csrf)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

pub(super) async fn set_proxy_enabled(
    app: &Router,
    cookie: &str,
    csrf: &str,
    proxy_id: &str,
    reason: Option<&str>,
) -> Response {
    set_proxy_status(app, cookie, csrf, proxy_id, false, reason).await
}

pub(super) async fn set_proxy_status(
    app: &Router,
    cookie: &str,
    csrf: &str,
    proxy_id: &str,
    enabled: bool,
    reason: Option<&str>,
) -> Response {
    let body = match reason {
        Some(reason) => json!({"enabled": enabled, "audit_reason": reason}),
        None => json!({"enabled": enabled}),
    };
    app.clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/admin/proxy-addresses/{proxy_id}"))
                .header(header::COOKIE, cookie)
                .header("x-csrf-token", csrf)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

pub(super) async fn submit_key_request(app: &Router, cookie: &str, csrf: &str) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/me/key-requests")
                .header(header::COOKIE, cookie)
                .header("x-csrf-token", csrf)
                .header("content-type", "application/json")
                .body(Body::from(json!({"message": "审计集成测试"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    json_body(response).await["request_id"]
        .as_str()
        .unwrap()
        .to_string()
}

pub(super) async fn decide_key_request(
    app: &Router,
    cookie: &str,
    csrf: &str,
    request_id: &str,
    action: &str,
    body: Value,
) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/key-requests/{request_id}/{action}"))
                .header(header::COOKIE, cookie)
                .header("x-csrf-token", csrf)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}
