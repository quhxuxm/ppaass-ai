use super::common::*;

const SELECT_PERMISSION: &str = "agent.proxy_entry.select";

#[tokio::test]
async fn selection_requires_permission_and_revocation_restores_admin_assignment() {
    let (_directory, app) = test_app().await;
    let (admin_cookie, admin_csrf) = login_admin(&app).await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/proxy-addresses")
                .header(header::COOKIE, &admin_cookie)
                .header("x-csrf-token", &admin_csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "label": "Singapore Edge",
                        "address": "select.example:9443"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let created_id = json_body(response).await["proxy_address_id"]
        .as_str()
        .unwrap()
        .to_string();
    create_approved_user(
        &app,
        &admin_cookie,
        &admin_csrf,
        "entry-selector",
        "entry-selector-password",
    )
    .await;

    let login = agent_login(&app).await;
    let denied = select_entry(
        &app,
        login["agent_access_token"].as_str().unwrap(),
        &created_id,
    )
    .await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    let response =
        update_permissions(&app, &admin_cookie, &admin_csrf, json!([SELECT_PERMISSION])).await;
    assert_eq!(response.status(), StatusCode::OK);
    let login = agent_login(&app).await;
    assert_eq!(
        login["profile"]["proxy_entries"].as_array().unwrap().len(),
        2
    );
    assert!(login["profile"]["selected_proxy_entry_id"].is_null());
    let token = login["agent_access_token"].as_str().unwrap();
    let selected = select_entry(&app, token, &created_id).await;
    assert_eq!(selected.status(), StatusCode::OK);
    let selected = json_body(selected).await;
    assert_eq!(selected["profile"]["selected_proxy_entry_id"], created_id);
    assert_eq!(
        selected["profile"]["proxy_addresses"],
        json!(["select.example:9443"])
    );

    let response = update_permissions(&app, &admin_cookie, &admin_csrf, json!([])).await;
    assert_eq!(response.status(), StatusCode::OK);
    let token = selected["agent_access_token"].as_str().unwrap();
    let synced = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/agent/me")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(synced.status(), StatusCode::OK);
    let synced = json_body(synced).await;
    assert!(synced["profile"].get("proxy_entries").is_none());
    assert_eq!(
        synced["profile"]["proxy_addresses"],
        json!(["127.0.0.1:8080"])
    );
}

async fn agent_login(app: &Router) -> Value {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "username": "entry-selector",
                        "password": "entry-selector-password"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await
}

async fn select_entry(app: &Router, token: &str, proxy_entry_id: &str) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/agent/proxy-entry")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"proxy_entry_id": proxy_entry_id}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn update_permissions(
    app: &Router,
    cookie: &str,
    csrf: &str,
    permissions: Value,
) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/v1/admin/users/entry-selector")
                .header(header::COOKIE, cookie)
                .header("x-csrf-token", csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "permissions": permissions,
                        "audit_reason": "测试 Entry 自选权限"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
}
