use super::common::*;
use sqlx::{Connection, SqliteConnection};

#[tokio::test]
async fn active_user_must_be_disabled_before_admin_can_delete_it() {
    let (directory, app) = test_app().await;
    let (cookie, csrf) = login_admin(&app).await;
    create_approved_user(&app, &cookie, &csrf, "delete-user", "delete-user-password").await;

    let response = delete_user(&app, &cookie, &csrf, "delete-user").await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_body(response).await["error"]["code"],
        "account_not_disabled"
    );

    let response = patch_user(
        &app,
        &cookie,
        &csrf,
        "delete-user",
        json!({"status": "disabled"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = delete_user(&app, &cookie, &csrf, "delete-user").await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let mut database =
        SqliteConnection::connect(directory.path().join("users.sqlite3").to_str().unwrap())
            .await
            .unwrap();
    let audit: (String, String) = sqlx::query_as(
        "SELECT target_login_name, admin_login_name \
         FROM account_disable_audits ORDER BY audit_id DESC LIMIT 1",
    )
    .fetch_one(&mut database)
    .await
    .unwrap();
    assert_eq!(audit, ("delete-user".to_string(), "admin".to_string()));
}

#[tokio::test]
async fn non_root_admin_can_be_disabled_and_deleted() {
    let (_directory, app) = test_app().await;
    let (bootstrap_cookie, bootstrap_csrf) = login_admin(&app).await;
    create_approved_user(
        &app,
        &bootstrap_cookie,
        &bootstrap_csrf,
        "second-admin",
        "second-admin-password",
    )
    .await;
    let response = patch_user(
        &app,
        &bootstrap_cookie,
        &bootstrap_csrf,
        "second-admin",
        json!({"role": "admin"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = patch_user(
        &app,
        &bootstrap_cookie,
        &bootstrap_csrf,
        "second-admin",
        json!({"status": "disabled"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = delete_user(&app, &bootstrap_cookie, &bootstrap_csrf, "second-admin").await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn unapproved_user_without_proxy_addresses_can_be_disabled_and_deleted() {
    let (_directory, app) = test_app().await;
    let (admin_cookie, admin_csrf) = login_admin(&app).await;
    register_user(&app, "unassigned-user", "unassigned-user-password").await;

    let response = patch_user(
        &app,
        &admin_cookie,
        &admin_csrf,
        "unassigned-user",
        json!({"status": "disabled"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["account"]["status"], "disabled");
    assert!(body["profile"].is_null());
    assert_eq!(body["proxy_addresses"], json!([]));

    let response = delete_user(&app, &admin_cookie, &admin_csrf, "unassigned-user").await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn root_admin_cannot_be_disabled_demoted_or_deleted() {
    let (_directory, app) = test_app().await;
    let (cookie, csrf) = login_admin(&app).await;
    for body in [
        json!({"status": "disabled"}),
        json!({"role": "user"}),
        json!({"role": "user", "status": "disabled"}),
    ] {
        let response = patch_user(&app, &cookie, &csrf, "admin", body).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            json_body(response).await["error"]["code"],
            "root_admin_protected"
        );
    }
    let response = delete_user(&app, &cookie, &csrf, "admin").await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_body(response).await["error"]["code"],
        "root_admin_protected"
    );
}

async fn patch_user(
    app: &Router,
    cookie: &str,
    csrf: &str,
    username: &str,
    mut body: Value,
) -> Response {
    body.as_object_mut()
        .unwrap()
        .insert("audit_reason".to_string(), json!("管理员测试操作"));
    app.clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/admin/users/{username}"))
                .header(header::COOKIE, cookie)
                .header("x-csrf-token", csrf)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn delete_user(app: &Router, cookie: &str, csrf: &str, username: &str) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/admin/users/{username}"))
                .header(header::COOKIE, cookie)
                .header("x-csrf-token", csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}
