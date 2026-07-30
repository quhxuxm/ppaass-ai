use protocol::RsaKeyPair;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::super::{
    authenticate_and_download, authenticate_rotate_and_download, validate_device_token,
    AgentDeviceProfile, AgentDeviceTokenResponse, AuthenticationAccount,
};

async fn read_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let bytes = stream.read(&mut buffer).await.unwrap();
        assert!(bytes > 0);
        request.extend_from_slice(&buffer[..bytes]);
        let Some(header_end) = request.windows(4).position(|value| value == b"\r\n\r\n") else {
            continue;
        };
        let header_end = header_end + 4;
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        if request.len() >= header_end + content_length {
            return String::from_utf8(request).unwrap();
        }
    }
}

async fn respond(stream: &mut TcpStream, status: &str, body: &str, cookie: bool) {
    let cookie = if cookie {
        "set-cookie: ppaass_session=test-session; Path=/; HttpOnly; SameSite=Lax\r\n"
    } else {
        ""
    };
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n{cookie}connection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await.unwrap();
}

fn assert_authenticated_request(request: &str, method_and_path: &str) {
    assert!(request.starts_with(method_and_path), "{request}");
    assert!(request
        .to_ascii_lowercase()
        .contains("cookie: ppaass_session=test-session"));
}

#[tokio::test(flavor = "current_thread")]
async fn password_login_accepts_active_user_and_admin_profiles() {
    for role in ["user", "admin"] {
        let pair = RsaKeyPair::generate(2048).unwrap();
        let private_key = pair.private_key_to_pem().unwrap();
        let public_key = pair.public_key_to_pem().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_role = role.to_string();
        let server = tokio::spawn(async move {
            let (mut login_stream, _) = listener.accept().await.unwrap();
            let login_request = read_request(&mut login_stream).await;
            assert!(login_request.starts_with("POST /api/v1/agent/login HTTP/1.1"));
            assert!(login_request.contains(r#""username":"alice""#));
            let login_body = serde_json::json!({
                "account": {
                    "role": server_role,
                    "status": "active",
                    "linked_username": "alice"
                },
                "profile": {
                    "username": "alice",
                    "permissions": ["key.private.read", "key.rotate"],
                    "proxy_addresses": ["proxy.example.com:443"],
                    "enabled": true,
                    "key_version": 8,
                    "expires_at": 4_000_000_000_i64
                },
                "public_key_pem": public_key.clone(),
                "proxy_identity_public_key_pem": public_key,
                "private_key_pem": private_key,
                "agent_access_token": "A".repeat(43),
                "agent_access_token_expires_at": 4_000_000_000_i64,
                "refresh_after_seconds": 300
            })
            .to_string();
            respond(&mut login_stream, "200 OK", &login_body, false).await;
        });

        let downloaded =
            authenticate_and_download(&format!("http://{address}"), "alice", "password")
                .await
                .unwrap();
        assert_eq!(downloaded.account.role, role);
        assert!(downloaded
            .account
            .permissions
            .iter()
            .any(|permission| permission == "key.rotate"));
        assert!(downloaded.agent_access_token.is_some());
        server.await.unwrap();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn rotation_uses_csrf_and_returns_only_validated_next_version() {
    let pair = RsaKeyPair::generate(2048).unwrap();
    let private_key = pair.private_key_to_pem().unwrap();
    let public_key = pair.public_key_to_pem().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut login_stream, _) = listener.accept().await.unwrap();
        let _login_request = read_request(&mut login_stream).await;
        let login_body = serde_json::json!({
            "account": {
                "role": "admin",
                "status": "active",
                "linked_username": "alice"
            },
            "csrf_token": "csrf-rotate",
            "session_expires_at": 4_000_000_000_i64
        })
        .to_string();
        respond(&mut login_stream, "200 OK", &login_body, true).await;

        let (mut me_stream, _) = listener.accept().await.unwrap();
        let me_request = read_request(&mut me_stream).await;
        assert_authenticated_request(&me_request, "GET /api/v1/me HTTP/1.1");
        let me_body = serde_json::json!({
            "profile": {
                "username": "alice",
                "permissions": ["key.private.read", "key.rotate"],
                "proxy_addresses": ["proxy.example.com:443"],
                "enabled": true,
                "key_version": 8,
                "expires_at": 4_000_000_000_i64
            },
            "key_state": "active",
            "pending_request": null
        })
        .to_string();
        respond(&mut me_stream, "200 OK", &me_body, false).await;

        let (mut rotate_stream, _) = listener.accept().await.unwrap();
        let rotate_request = read_request(&mut rotate_stream).await;
        assert_authenticated_request(&rotate_request, "POST /api/v1/me/rotate-key HTTP/1.1");
        assert!(rotate_request.contains("x-csrf-token: csrf-rotate"));
        let rotate_body = serde_json::json!({
            "username": "alice",
            "public_key_pem": public_key.clone(),
            "proxy_identity_public_key_pem": public_key,
            "private_key_pem": private_key,
            "key_version": 9
        })
        .to_string();
        respond(&mut rotate_stream, "200 OK", &rotate_body, false).await;

        let (mut logout_stream, _) = listener.accept().await.unwrap();
        let logout_request = read_request(&mut logout_stream).await;
        assert_authenticated_request(&logout_request, "POST /api/v1/auth/logout HTTP/1.1");
        respond(&mut logout_stream, "204 No Content", "", false).await;
    });

    let downloaded =
        authenticate_rotate_and_download(&format!("http://{address}"), "alice", "password")
            .await
            .unwrap();
    assert_eq!(downloaded.account.role, "admin");
    assert_eq!(downloaded.account.key_version, 9);
    assert_eq!(downloaded.account.expires_at, Some(4_000_000_000));
    server.await.unwrap();
}

#[test]
fn device_token_accepts_an_admin_with_an_active_profile() {
    let pair = RsaKeyPair::generate(2048).unwrap();
    let private_key_pem = pair.private_key_to_pem().unwrap();
    let public_key_pem = pair.public_key_to_pem().unwrap();
    let downloaded = validate_device_token(
        AgentDeviceTokenResponse {
            account: AuthenticationAccount {
                role: "admin".to_string(),
                status: "active".to_string(),
                linked_username: Some("admin-proxy".to_string()),
                display_name: None,
                avatar_url: None,
            },
            profile: AgentDeviceProfile {
                username: "admin-proxy".to_string(),
                permissions: vec!["key.private.read".to_string(), "key.rotate".to_string()],
                proxy_addresses: Some(vec!["proxy.example.com:443".to_string()]),
                enabled: true,
                key_version: 3,
                expires_at: Some(4_000_000_000),
            },
            public_key_pem: public_key_pem.clone(),
            proxy_identity_public_key_pem: public_key_pem,
            private_key_pem,
            csrf_token: "csrf".to_string(),
            _session_expires_at: Some(4_000_000_000),
            agent_access_token: "A".repeat(43),
            agent_access_token_expires_at: 4_000_000_000,
            refresh_after_seconds: 300,
        },
        "https://proxy.example.com".to_string(),
    )
    .unwrap();

    assert_eq!(downloaded.account.role, "admin");
    assert_eq!(downloaded.account.username, "admin-proxy");
    assert_eq!(downloaded.account.key_version, 3);
}

#[tokio::test(flavor = "current_thread")]
async fn expired_key_rotation_directs_the_user_to_admin_approval() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut login_stream, _) = listener.accept().await.unwrap();
        let _login_request = read_request(&mut login_stream).await;
        let login_body = serde_json::json!({
            "account": {
                "role": "user",
                "status": "active",
                "linked_username": "alice"
            },
            "csrf_token": "csrf-expired",
            "session_expires_at": 4_000_000_000_i64
        })
        .to_string();
        respond(&mut login_stream, "200 OK", &login_body, true).await;

        let (mut me_stream, _) = listener.accept().await.unwrap();
        let _me_request = read_request(&mut me_stream).await;
        let me_body = serde_json::json!({
            "profile": {
                "username": "alice",
                "permissions": ["key.private.read", "key.rotate"],
                "proxy_addresses": ["proxy.example.com:443"],
                "enabled": true,
                "key_version": 8,
                "expires_at": 1
            },
            "key_state": "expired",
            "pending_request": null
        })
        .to_string();
        respond(&mut me_stream, "200 OK", &me_body, false).await;

        let (mut logout_stream, _) = listener.accept().await.unwrap();
        let logout_request = read_request(&mut logout_stream).await;
        assert_authenticated_request(&logout_request, "POST /api/v1/auth/logout HTTP/1.1");
        respond(&mut logout_stream, "204 No Content", "", false).await;
    });

    let error = authenticate_rotate_and_download(&format!("http://{address}"), "alice", "password")
        .await
        .err()
        .expect("expired key rotation must fail");
    assert!(error.contains("管理员批准"), "{error}");
    server.await.unwrap();
}
