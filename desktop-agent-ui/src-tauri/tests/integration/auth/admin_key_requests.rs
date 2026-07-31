use tokio::net::TcpListener;

use super::{read_http_request, write_http_response};
use desktop_agent_ui::auth::{
    approve_agent_admin_key_request, fetch_agent_admin_key_request_inbox,
    reject_agent_admin_key_request,
};

const TOKEN: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn account() -> serde_json::Value {
    serde_json::json!({
        "account_id": "acct_alice",
        "login_name": "alice@example.com",
        "role": "user",
        "status": "active",
        "linked_username": null,
        "display_name": "Alice",
        "email": "alice@example.com",
        "avatar_url": "data:image/png;base64,iVBORw0KGgo=",
        "auth_version": 1,
        "last_login_at": null,
        "created_at": 1_800_000_000_i64,
        "updated_at": 1_800_000_001_i64
    })
}

fn key_request(status: &str) -> serde_json::Value {
    let pending = status == "pending";
    serde_json::json!({
        "request_id": "kreq_1",
        "account": account(),
        "proxy_address_ids": ["pxy_current"],
        "request_message": "需要在出差前更新",
        "kind": "rotate",
        "status": status,
        "expected_key_version": 7,
        "reviewer_account_id": if pending {
            serde_json::Value::Null
        } else {
            serde_json::json!("acct_admin")
        },
        "reviewer_login_name": if pending {
            serde_json::Value::Null
        } else {
            serde_json::json!("admin")
        },
        "rejection_reason": if status == "rejected" {
            serde_json::json!("请补充用途说明")
        } else {
            serde_json::Value::Null
        },
        "requested_at": 1_800_000_002_i64,
        "reviewed_at": if pending {
            serde_json::Value::Null
        } else {
            serde_json::json!(1_800_000_003_i64)
        },
        "approved_expires_at": if status == "approved" {
            serde_json::json!(4_000_000_000_i64)
        } else {
            serde_json::Value::Null
        }
    })
}

fn proxy_addresses() -> serde_json::Value {
    serde_json::json!({
        "proxy_addresses": [{
            "proxy_address_id": "pxy_current",
            "label": "生产 Proxy",
            "address": "proxy.example.com:443",
            "enabled": true,
            "created_at": 1_800_000_000_i64,
            "updated_at": 1_800_000_001_i64,
            "entry_id": "entry-production-01",
            "entry_version": "0.1.0",
            "entry_first_registered_at": 1_800_000_000_i64,
            "entry_last_heartbeat_at": 1_800_000_010_i64,
            "entry_online": true
        }]
    })
}

async fn serve_admin_gets(listener: TcpListener, requests_body: serde_json::Value) -> Vec<String> {
    let mut captured = Vec::new();
    for _ in 0..2 {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_http_request(&mut stream).await;
        let body = if request.starts_with("GET /api/v1/admin/key-requests ") {
            requests_body.to_string()
        } else if request.starts_with("GET /api/v1/admin/proxy-addresses ") {
            proxy_addresses().to_string()
        } else {
            panic!("unexpected request: {request}");
        };
        write_http_response(&mut stream, "200 OK", &[], &body).await;
        captured.push(request);
    }
    captured
}

#[tokio::test(flavor = "current_thread")]
async fn admin_inbox_uses_bearer_and_maps_requests_without_exposing_token() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_admin_gets(
        listener,
        serde_json::json!({"requests": [key_request("pending")]}),
    ));

    let inbox = fetch_agent_admin_key_request_inbox(&format!("http://{address}"), TOKEN)
        .await
        .unwrap();
    let captured = server.await.unwrap();

    assert_eq!(inbox.requests.len(), 1);
    assert_eq!(inbox.requests[0].username, "alice@example.com");
    assert_eq!(
        inbox.requests[0].avatar_url.as_deref(),
        Some("data:image/png;base64,iVBORw0KGgo=")
    );
    assert_eq!(inbox.requests[0].proxy_address_ids, ["pxy_current"]);
    assert_eq!(inbox.proxy_addresses.len(), 1);
    for request in captured {
        assert!(request
            .to_ascii_lowercase()
            .contains(&format!("authorization: bearer {TOKEN}").to_ascii_lowercase()));
    }
    let serialized = serde_json::to_string(&inbox).unwrap();
    assert!(!serialized.contains(TOKEN));
    assert!(!serialized.contains("auth_version"));
}

#[tokio::test(flavor = "current_thread")]
async fn admin_inbox_rejects_unknown_json_fields() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut request = key_request("pending");
    request
        .as_object_mut()
        .unwrap()
        .insert("unexpected_secret".to_string(), serde_json::json!("no"));
    let server = tokio::spawn(serve_admin_gets(
        listener,
        serde_json::json!({"requests": [request]}),
    ));

    let error = fetch_agent_admin_key_request_inbox(&format!("http://{address}"), TOKEN)
        .await
        .unwrap_err();
    server.await.unwrap();
    assert!(error.message.contains("格式无效"));
}

#[tokio::test(flavor = "current_thread")]
async fn approval_posts_bearer_expiry_and_proxy_selection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_http_request(&mut stream).await;
        let body = serde_json::json!({
            "request": key_request("approved"),
            "user": null
        })
        .to_string();
        write_http_response(&mut stream, "200 OK", &[], &body).await;
        request
    });

    approve_agent_admin_key_request(
        &format!("http://{address}"),
        TOKEN,
        "kreq_1",
        4_000_000_000,
        &["pxy_current".to_string()],
        "审批测试",
    )
    .await
    .unwrap();
    let request = server.await.unwrap();
    let normalized = request.to_ascii_lowercase();
    assert!(request.starts_with("POST /api/v1/admin/key-requests/kreq_1/approve HTTP/1.1"));
    assert!(normalized.contains(&format!("authorization: bearer {TOKEN}").to_ascii_lowercase()));
    assert!(request.contains("\"expires_at\":4000000000"));
    assert!(request.contains("\"proxy_address_ids\":[\"pxy_current\"]"));
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_rejection_is_returned_as_a_typed_conflict() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_http_request(&mut stream).await;
        let body = serde_json::json!({
            "error": {
                "code": "key_request_already_reviewed",
                "message": "already reviewed"
            }
        })
        .to_string();
        write_http_response(&mut stream, "409 Conflict", &[], &body).await;
        request
    });

    let error = reject_agent_admin_key_request(
        &format!("http://{address}"),
        TOKEN,
        "kreq_1",
        "请补充用途说明",
    )
    .await
    .unwrap_err();
    let request = server.await.unwrap();
    assert!(request.starts_with("POST /api/v1/admin/key-requests/kreq_1/reject HTTP/1.1"));
    assert!(request.contains("\"reason\":\"请补充用途说明\""));
    assert!(error.is_conflict());
}
