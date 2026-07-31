use super::common::*;

const USERNAME: &str = "handoff-user";
const PASSWORD: &str = "handoff-user-password";
const HANDOFF_PREFIX: &str = "/api/v1/auth/agent-handoff?code=";

#[tokio::test]
async fn agent_handoff_establishes_web_session_once_and_rejects_tampering() {
    let (_directory, _store, sessions, _handoffs, _private_keys, app) =
        test_app_with_components().await;
    let (admin_cookie, admin_csrf) = login_admin(&app).await;
    assert_session_source(&app, &admin_cookie, false, "admin").await;
    create_approved_user(&app, &admin_cookie, &admin_csrf, USERNAME, PASSWORD).await;
    let token = agent_access_token(&app, USERNAME, PASSWORD).await;
    let handoff_path = issue_handoff(&app, &token).await;
    assert!(handoff_path.starts_with(HANDOFF_PREFIX));
    assert_eq!(handoff_path.len(), HANDOFF_PREFIX.len() + 43);
    assert_eq!(sessions.active_session_count(), 1);

    let response = consume_handoff_as_fetch(&app, &handoff_path).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    assert_eq!(sessions.active_session_count(), 1);

    let mut tampered = handoff_path.as_bytes()[HANDOFF_PREFIX.len()..].to_vec();
    tampered[0] = if tampered[0] == b'A' { b'B' } else { b'A' };
    let tampered_path = format!(
        "{HANDOFF_PREFIX}{}",
        std::str::from_utf8(&tampered).unwrap()
    );
    let response = consume_handoff(&app, &tampered_path).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    assert_eq!(sessions.active_session_count(), 1);

    let response = consume_handoff(&app, &handoff_path).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/");
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(
        response.headers().get("referrer-policy").unwrap(),
        "no-referrer"
    );
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    assert_eq!(sessions.active_session_count(), 2);

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
    let session = json_body(response).await;
    assert_eq!(session["authenticated"], true);
    assert_eq!(session["account"]["login_name"], USERNAME);
    assert_eq!(session["agent_handoff"], true);

    let replay = consume_handoff(&app, &handoff_path).await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    assert!(!replay.headers().contains_key(header::SET_COOKIE));
    assert_eq!(sessions.active_session_count(), 2);
}

#[tokio::test]
async fn handoff_rechecks_disabled_account_before_issuing_cookie() {
    let (_directory, _store, sessions, _handoffs, _private_keys, app) =
        test_app_with_components().await;
    let (admin_cookie, admin_csrf) = login_admin(&app).await;
    create_approved_user(&app, &admin_cookie, &admin_csrf, USERNAME, PASSWORD).await;
    let token = agent_access_token(&app, USERNAME, PASSWORD).await;
    let handoff_path = issue_handoff(&app, &token).await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/admin/users/{USERNAME}"))
                .header(header::COOKIE, admin_cookie)
                .header("x-csrf-token", admin_csrf)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "status": "disabled",
                        "audit_reason": "测试停用后交接失效"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = consume_handoff(&app, &handoff_path).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    assert_eq!(sessions.active_session_count(), 1);
}

#[tokio::test]
async fn native_handoff_creation_rejects_browser_origin_requests() {
    let (_directory, app) = test_app().await;
    let (admin_cookie, admin_csrf) = login_admin(&app).await;
    create_approved_user(&app, &admin_cookie, &admin_csrf, USERNAME, PASSWORD).await;
    let token = agent_access_token(&app, USERNAME, PASSWORD).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/web-session-handoffs")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::ORIGIN, "https://attacker.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(!response.headers().contains_key(header::SET_COOKIE));
}

async fn agent_access_token(app: &Router, username: &str, password: &str) -> String {
    let response = app
        .clone()
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
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await["agent_access_token"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn issue_handoff(app: &Router, token: &str) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agent/web-session-handoffs")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let body = json_body(response).await;
    assert_eq!(body["expires_in"], AGENT_WEB_SESSION_HANDOFF_TTL_SECONDS);
    body["handoff_path"].as_str().unwrap().to_string()
}

async fn consume_handoff(app: &Router, path: &str) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header("sec-fetch-site", "cross-site")
                .header("sec-fetch-mode", "navigate")
                .header("sec-fetch-dest", "document")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn consume_handoff_as_fetch(app: &Router, path: &str) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header("sec-fetch-site", "cross-site")
                .header("sec-fetch-mode", "cors")
                .header("sec-fetch-dest", "empty")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn assert_session_source(app: &Router, cookie: &str, agent_handoff: bool, username: &str) {
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
    let session = json_body(response).await;
    assert_eq!(session["authenticated"], true);
    assert_eq!(session["account"]["login_name"], username);
    assert_eq!(session["agent_handoff"], agent_handoff);
}
