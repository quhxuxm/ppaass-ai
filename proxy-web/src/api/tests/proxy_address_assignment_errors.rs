use super::common::*;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

#[tokio::test]
async fn migrated_unassigned_profile_fails_agent_login_and_sync_with_stable_code() {
    let (_directory, store, _sessions, _keys, app) = test_app_with_components().await;
    let (admin_cookie, admin_csrf) = login_admin(&app).await;
    create_approved_user(
        &app,
        &admin_cookie,
        &admin_csrf,
        "migrated-unassigned",
        "migrated-unassigned-password",
    )
    .await;

    let login = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "username": "migrated-unassigned",
                        "password": "migrated-unassigned-password"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let token = json_body(login).await["agent_access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(SqliteConnectOptions::new().filename(store.path()))
        .await
        .unwrap();
    sqlx::query(
        "DELETE FROM account_proxy_addresses \
         WHERE account_id = (SELECT account_id FROM web_accounts WHERE login_name = ?)",
    )
    .bind("migrated-unassigned")
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;

    let sync = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/agent/me")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_proxy_address_not_assigned(sync).await;

    let login = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "username": "migrated-unassigned",
                        "password": "migrated-unassigned-password"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_proxy_address_not_assigned(login).await;
}

async fn assert_proxy_address_not_assigned(response: Response) {
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_body(response).await["error"]["code"],
        "proxy_address_not_assigned"
    );
}
