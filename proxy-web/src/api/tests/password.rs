use super::common::*;

async fn change_password(
    app: &Router,
    cookie: &str,
    csrf: Option<&str>,
    current_password: &str,
    new_password: &str,
) -> Response {
    let mut request = Request::builder()
        .method("PUT")
        .uri("/api/v1/me/password")
        .header(header::COOKIE, cookie)
        .header("content-type", "application/json");
    if let Some(csrf) = csrf {
        request = request.header("x-csrf-token", csrf);
    }
    app.clone()
        .oneshot(
            request
                .body(Body::from(
                    json!({
                        "current_password": current_password,
                        "new_password": new_password
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn session_is_authenticated(app: &Router, cookie: &str) -> bool {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/session")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await["authenticated"]
        .as_bool()
        .unwrap()
}

#[tokio::test]
async fn user_changes_password_and_all_old_sessions_are_invalidated() {
    let (_directory, store, sessions, _handoffs, _private_keys, app) =
        test_app_with_components().await;
    let old_password = "original-password";
    let new_password = "replacement-password";
    let (first_cookie, first_csrf) = register_user(&app, "password-user", old_password).await;
    let (second_cookie, _second_csrf) = login_user(&app, "password-user", old_password).await;
    let old_account = store
        .get_account_by_login("password-user")
        .await
        .unwrap()
        .unwrap();

    let wrong = change_password(
        &app,
        &first_cookie,
        Some(&first_csrf),
        "not-the-current-password",
        new_password,
    )
    .await;
    assert_eq!(wrong.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(wrong).await["error"]["code"],
        "current_password_invalid"
    );
    assert!(session_is_authenticated(&app, &first_cookie).await);

    let short = change_password(
        &app,
        &first_cookie,
        Some(&first_csrf),
        old_password,
        "short",
    )
    .await;
    assert_eq!(short.status(), StatusCode::BAD_REQUEST);
    assert!(session_is_authenticated(&app, &first_cookie).await);

    let changed = change_password(
        &app,
        &first_cookie,
        Some(&first_csrf),
        old_password,
        new_password,
    )
    .await;
    assert_eq!(changed.status(), StatusCode::NO_CONTENT);
    assert!(
        changed
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    assert_eq!(sessions.active_session_count(), 0);
    assert!(!session_is_authenticated(&app, &first_cookie).await);
    assert!(!session_is_authenticated(&app, &second_cookie).await);

    let stale_cookie = sessions
        .issue(&old_account)
        .1
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    assert!(!session_is_authenticated(&app, &stale_cookie).await);

    let old_login = login_from_peer(&app, "password-user", old_password, "192.0.2.20:10001").await;
    assert_eq!(old_login.status(), StatusCode::UNAUTHORIZED);
    let new_login = login_from_peer(&app, "password-user", new_password, "192.0.2.21:10002").await;
    assert_eq!(new_login.status(), StatusCode::OK);
}

#[tokio::test]
async fn password_change_requires_csrf_and_preserves_password_on_rejection() {
    let (_directory, app) = test_app().await;
    let old_password = "csrf-old-password";
    let new_password = "csrf-new-password";
    let (cookie, _csrf) = register_user(&app, "csrf-password-user", old_password).await;

    let response = change_password(&app, &cookie, None, old_password, new_password).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(session_is_authenticated(&app, &cookie).await);
    let login = login_from_peer(&app, "csrf-password-user", old_password, "192.0.2.22:10003").await;
    assert_eq!(login.status(), StatusCode::OK);
}
