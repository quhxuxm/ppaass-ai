use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use desktop_agent_ui::auth::{apply_permission_snapshot, fetch_agent_permission_snapshot};
use desktop_agent_ui::models::{AgentAuthAccount, AgentAuthAccountStatus};

async fn respond_once(status: &str, body: String) -> (String, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let status = status.to_string();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = vec![0_u8; 8192];
        let bytes = stream.read(&mut request).await.unwrap();
        let request = String::from_utf8(request[..bytes].to_vec()).unwrap();
        let response = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        request
    });
    (format!("http://{address}"), task)
}

#[tokio::test(flavor = "current_thread")]
async fn permission_sync_uses_bearer_auth_and_accepts_a_rolling_token() {
    let body = serde_json::json!({
        "account": {
            "role": "user",
            "status": "active",
            "linked_username": "alice"
        },
        "profile": {
            "username": "alice",
            "permissions": [
                "agent.packet_capture",
                "agent.egress.edit",
                "agent.proxy_entry.select"
            ],
            "proxy_addresses": ["proxy.example.com:443"],
            "proxy_entries": [{
                "proxy_entry_id": "pxy_shanghai",
                "label": "上海 · 尊享节点",
                "address": "proxy.example.com:443",
                "description": "低延迟线路",
                "icon_key": "building",
                "entry_id": "entry_shanghai",
                "online": true
            }],
            "selected_proxy_entry_id": "pxy_shanghai",
            "enabled": true,
            "key_version": 7,
            "expires_at": 4_000_000_000_i64
        },
        "key_state": "active",
        "agent_access_token": "B".repeat(43),
        "agent_access_token_expires_at": 4_000_000_000_i64,
        "refresh_after_seconds": 5
    })
    .to_string();
    let (base_url, server) = respond_once("200 OK", body).await;
    let snapshot = fetch_agent_permission_snapshot(&base_url, &"A".repeat(43), "alice")
        .await
        .unwrap();
    let request = server.await.unwrap().to_ascii_lowercase();
    assert!(request.starts_with("get /api/v1/agent/me http/1.1"));
    assert!(request.contains(&format!("authorization: bearer {}", "a".repeat(43))));
    assert!(snapshot.token.matches_value(&"B".repeat(43)));
    assert_eq!(snapshot.token.refresh_after_seconds, 60);

    let current = AgentAuthAccount {
        username: "alice".to_string(),
        display_name: None,
        avatar_url: None,
        role: "user".to_string(),
        permissions: Vec::new(),
        key_version: 7,
        expires_at: None,
    };
    let (updated, status, error) = apply_permission_snapshot(&current, &snapshot);
    assert_eq!(
        updated.permissions,
        [
            "agent.packet_capture",
            "agent.egress.edit",
            "agent.proxy_entry.select"
        ]
    );
    let selection = snapshot.proxy_entry_selection();
    assert_eq!(selection.entries.len(), 1);
    assert_eq!(
        selection.selected_proxy_entry_id.as_deref(),
        Some("pxy_shanghai")
    );
    assert!(!serde_json::to_string(&selection)
        .unwrap()
        .contains("proxy.example.com"));
    assert_eq!(status, AgentAuthAccountStatus::Active);
    assert!(error.is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_sync_token_requests_relogin_without_discarding_local_state() {
    let body = serde_json::json!({
        "error": {"code": "unauthorized", "message": "expired"}
    })
    .to_string();
    let (base_url, server) = respond_once("401 Unauthorized", body).await;
    let failure = fetch_agent_permission_snapshot(&base_url, &"A".repeat(43), "alice")
        .await
        .err()
        .expect("invalid token must fail permission sync");
    server.await.unwrap();
    assert!(failure.credentials_invalid);
    assert!(failure.message.contains("重新登录"));
}

#[tokio::test(flavor = "current_thread")]
async fn unassigned_proxy_conflict_is_a_typed_fail_closed_error() {
    let body = serde_json::json!({
        "error": {"code": "proxy_address_not_assigned", "message": "missing"}
    })
    .to_string();
    let (base_url, server) = respond_once("409 Conflict", body).await;
    let failure = fetch_agent_permission_snapshot(&base_url, &"A".repeat(43), "alice")
        .await
        .err()
        .expect("unassigned address must fail");
    server.await.unwrap();

    assert!(failure.proxy_address_not_assigned);
    assert!(!failure.credentials_invalid);
    assert_eq!(failure.message, "管理员未分配 Proxy 地址");
}

#[tokio::test(flavor = "current_thread")]
async fn ordinary_and_oversized_errors_do_not_clear_the_last_assignment() {
    for (status, body) in [
        (
            "503 Service Unavailable",
            serde_json::json!({"error": {"code": "temporary", "message": "retry"}}).to_string(),
        ),
        ("409 Conflict", "x".repeat(64 * 1024 + 1)),
    ] {
        let (base_url, server) = respond_once(status, body).await;
        let failure = fetch_agent_permission_snapshot(&base_url, &"A".repeat(43), "alice")
            .await
            .err()
            .expect("non-success response must fail");
        server.await.unwrap();

        assert!(!failure.proxy_address_not_assigned);
        assert!(!failure.credentials_invalid);
        assert!(failure.message.contains("保留上次已验证权限"));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn successful_profile_without_proxy_addresses_is_fail_closed() {
    let body = serde_json::json!({
        "account": {
            "role": "user",
            "status": "active",
            "linked_username": "alice"
        },
        "profile": {
            "username": "alice",
            "permissions": [],
            "enabled": true,
            "key_version": 7,
            "expires_at": 4_000_000_000_i64
        },
        "key_state": "active",
        "agent_access_token": "B".repeat(43),
        "agent_access_token_expires_at": 4_000_000_000_i64,
        "refresh_after_seconds": 300
    })
    .to_string();
    let (base_url, server) = respond_once("200 OK", body).await;
    let failure = fetch_agent_permission_snapshot(&base_url, &"A".repeat(43), "alice")
        .await
        .err()
        .expect("missing address must fail");
    server.await.unwrap();

    assert!(failure.proxy_address_not_assigned);
    assert_eq!(failure.message, "管理员未分配 Proxy 地址");
}
