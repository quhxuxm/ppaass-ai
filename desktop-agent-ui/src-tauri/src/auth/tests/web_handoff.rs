use tokio::net::TcpListener;

use super::super::{
    account_management_handoff_url, normalize_proxy_web_url, request_account_management_handoff,
};
use super::{read_http_request, write_http_response};

#[tokio::test(flavor = "current_thread")]
async fn web_session_handoff_posts_agent_bearer_and_accepts_same_origin_path() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_http_request(&mut stream).await;
        assert!(
            request.starts_with("POST /api/v1/agent/web-session-handoffs HTTP/1.1"),
            "{request}"
        );
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: bearer agent-handoff-token"));
        assert!(!request.to_ascii_lowercase().contains("\r\norigin:"));
        write_http_response(
            &mut stream,
            "200 OK",
            &[],
            r#"{"handoff_path":"/api/v1/auth/agent-handoff?code=one-time","expires_in":60}"#,
        )
        .await;
    });

    let url =
        request_account_management_handoff(&format!("http://{address}"), "agent-handoff-token")
            .await
            .unwrap();
    assert_eq!(
        url.as_str(),
        format!("http://{address}/api/v1/auth/agent-handoff?code=one-time")
    );
    server.await.unwrap();
}

#[test]
fn web_session_handoff_rejects_non_relative_or_cross_origin_values() {
    let base = normalize_proxy_web_url("https://proxy.example.com").unwrap();
    for value in [
        "",
        "api/v1/auth/handoff",
        "//attacker.example/handoff",
        "/\\attacker.example/handoff",
        "https://proxy.example.com/api/v1/auth/handoff",
        "/api/v1/auth/other?code=safe",
        "/api/v1/auth/agent-handoff",
        "/api/v1/auth/agent-handoff?code=safe#secret",
    ] {
        assert!(
            account_management_handoff_url(&base, value).is_err(),
            "accepted {value:?}"
        );
    }
    assert_eq!(
        account_management_handoff_url(&base, "/api/v1/auth/agent-handoff?code=safe")
            .unwrap()
            .as_str(),
        "https://proxy.example.com/api/v1/auth/agent-handoff?code=safe"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn web_session_handoff_rejects_expired_or_unauthorized_responses() {
    for (status, body, expected) in [
        (
            "200 OK",
            r#"{"handoff_path":"/api/v1/auth/agent-handoff?code=old","expires_in":0}"#,
            "有效期无效",
        ),
        (
            "401 Unauthorized",
            r#"{"error":{"code":"unauthorized","message":"denied"}}"#,
            "凭据已失效",
        ),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_http_request(&mut stream).await;
            assert!(!request.contains("denied"));
            write_http_response(&mut stream, status, &[], body).await;
        });

        let error =
            request_account_management_handoff(&format!("http://{address}"), "secret-agent-token")
                .await
                .unwrap_err();
        assert!(error.contains(expected), "{error}");
        assert!(!error.contains("secret-agent-token"));
        server.await.unwrap();
    }
}
