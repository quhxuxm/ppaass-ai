use super::common::*;
use base64::Engine;
use futures::StreamExt;

#[tokio::test]
async fn avatar_update_is_published_and_returned_to_android_agent_endpoints() {
    let (_directory, app) = test_app().await;
    let (admin_cookie, admin_csrf) = login_admin(&app).await;
    create_approved_user(
        &app,
        &admin_cookie,
        &admin_csrf,
        "avatar-sync-user",
        "avatar-sync-password",
    )
    .await;
    let (user_cookie, user_csrf) =
        login_user(&app, "avatar-sync-user", "avatar-sync-password").await;
    let initial =
        json_body(agent_login(&app, "avatar-sync-user", "avatar-sync-password").await).await;
    let token = initial["agent_access_token"].as_str().unwrap();

    let events = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/agent/events")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::ACCEPT, "text/event-stream")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(events.status(), StatusCode::OK);
    let mut stream = events.into_body().into_data_stream();
    let initial_event = next_event(&mut stream).await;
    assert!(initial_event.contains("event: sync"), "{initial_event:?}");

    let avatar = test_avatar_data_url();
    let update = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/me/profile")
                .header(header::COOKIE, user_cookie)
                .header("x-csrf-token", user_csrf)
                .header("content-type", "application/json")
                .body(Body::from(json!({"avatar_data_url": avatar}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(update.status(), StatusCode::OK);

    let changed = next_event(&mut stream).await;
    assert!(changed.contains("event: profile_changed"), "{changed:?}");

    let synced = json_body(agent_profile(&app, token).await).await;
    assert_eq!(synced["account"]["avatar_url"], avatar);
    let relogin =
        json_body(agent_login(&app, "avatar-sync-user", "avatar-sync-password").await).await;
    assert_eq!(relogin["account"]["avatar_url"], avatar);
}

async fn next_event<S>(stream: &mut S) -> String
where
    S: futures::Stream<Item = std::result::Result<axum::body::Bytes, axum::Error>> + Unpin,
{
    let event = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    std::str::from_utf8(&event).unwrap().to_string()
}

async fn agent_login(app: &Router, username: &str, password: &str) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"username": username, "password": password}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn agent_profile(app: &Router, token: &str) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/agent/me")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

fn test_avatar_data_url() -> String {
    let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
    png.extend_from_slice(&64_u32.to_be_bytes());
    png.extend_from_slice(&64_u32.to_be_bytes());
    format!(
        "data:image/png;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(png)
    )
}
