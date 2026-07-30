use super::common::*;
use base64::Engine;

async fn update_profile(app: &Router, cookie: &str, csrf: &str, body: Value) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/me/profile")
                .header(header::COOKIE, cookie)
                .header("x-csrf-token", csrf)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

fn png_data_url(width: u32, height: u32) -> String {
    let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
    png.extend_from_slice(&width.to_be_bytes());
    png.extend_from_slice(&height.to_be_bytes());
    format!(
        "data:image/png;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(png)
    )
}

fn padded_png_data_url(width: u32, height: u32, bytes: usize) -> String {
    let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
    png.extend_from_slice(&width.to_be_bytes());
    png.extend_from_slice(&height.to_be_bytes());
    png.resize(bytes, 0);
    format!(
        "data:image/png;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(png)
    )
}

#[tokio::test]
async fn user_updates_nickname_and_bounded_avatar() {
    let (_directory, app) = test_app().await;
    let (cookie, csrf) = register_user(&app, "profile-user", "profile-password").await;
    let avatar = png_data_url(64, 64);
    let response = update_profile(
        &app,
        &cookie,
        &csrf,
        json!({"display_name":"小代理","avatar_data_url":avatar}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let updated = json_body(response).await;
    assert_eq!(updated["display_name"], "小代理");
    assert_eq!(updated["avatar_url"], avatar);

    let me = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/me")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(me.status(), StatusCode::OK);
    let me = json_body(me).await;
    assert_eq!(me["account"]["display_name"], "小代理");
    assert_eq!(me["account"]["avatar_url"], avatar);
}

#[tokio::test]
async fn profile_rejects_long_nickname_and_large_dimensions() {
    let (_directory, app) = test_app().await;
    let (cookie, csrf) = register_user(&app, "invalid-profile", "profile-password").await;

    let nickname = update_profile(
        &app,
        &cookie,
        &csrf,
        json!({"display_name":"超过六个中文字"}),
    )
    .await;
    assert_eq!(nickname.status(), StatusCode::BAD_REQUEST);

    let avatar = update_profile(
        &app,
        &cookie,
        &csrf,
        json!({"avatar_data_url":png_data_url(65, 64)}),
    )
    .await;
    assert_eq!(avatar.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn profile_route_accepts_a_valid_avatar_larger_than_the_default_body_limit() {
    let (_directory, app) = test_app().await;
    let (cookie, csrf) = register_user(&app, "large-avatar", "profile-password").await;
    let avatar = padded_png_data_url(64, 64, 40 * 1024);
    let response = update_profile(&app, &cookie, &csrf, json!({"avatar_data_url":avatar})).await;
    assert_eq!(response.status(), StatusCode::OK);
}
