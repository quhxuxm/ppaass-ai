use std::ffi::OsString;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use protocol::RsaKeyPair;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use super::{
    build_proxy_web_client, device_verification_url, load_persisted_agent_login_from_dir,
    managed_private_key_file_name, normalize_proxy_web_url, persist_agent_login_to_dir,
    poll_device_authorization, registration_page_url, remove_other_managed_private_keys,
    start_device_authorization, validate_device_code, validate_key_pair,
    validate_proxy_identity_public_key, write_private_key_to_dir, DeviceAuthorizationPoll,
    PROXY_IDENTITY_PUBLIC_KEY_FILE,
};
use crate::models::{AgentAuthAccount, AgentAuthAccountStatus};

struct ProxyEnvironmentGuard {
    previous: Vec<(&'static str, Option<OsString>)>,
}

impl ProxyEnvironmentGuard {
    fn install(proxy_url: &str) -> Self {
        let variables = ["HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"];
        let previous = variables
            .iter()
            .map(|name| (*name, std::env::var_os(name)))
            .collect();
        std::env::set_var("HTTP_PROXY", proxy_url);
        std::env::set_var("http_proxy", proxy_url);
        std::env::remove_var("NO_PROXY");
        std::env::remove_var("no_proxy");
        Self { previous }
    }
}

impl Drop for ProxyEnvironmentGuard {
    fn drop(&mut self) {
        for (name, value) in self.previous.drain(..) {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

async fn respond_once(listener: TcpListener, body: &'static str) {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut request = [0_u8; 4096];
    let request_bytes = stream.read(&mut request).await.unwrap();
    assert!(request_bytes > 0);
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await.unwrap();
}

async fn read_http_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 2048];
    loop {
        let bytes = stream.read(&mut buffer).await.unwrap();
        assert!(bytes > 0, "connection closed before request was complete");
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

async fn write_http_response(
    stream: &mut TcpStream,
    status: &str,
    headers: &[(&str, &str)],
    body: &str,
) {
    let extra_headers = headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect::<String>();
    let response = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n{extra_headers}connection: close\r\n\r\n{body}",
            body.len()
        );
    stream.write_all(response.as_bytes()).await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn proxy_web_client_ignores_http_proxy_environment() {
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_address = target_listener.local_addr().unwrap();
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = proxy_listener.local_addr().unwrap();
    let target_task = tokio::spawn(respond_once(target_listener, "proxy-web"));
    let proxy_task = tokio::spawn(respond_once(proxy_listener, "environment-proxy"));

    let environment = ProxyEnvironmentGuard::install(&format!("http://{proxy_address}"));
    let client = build_proxy_web_client().unwrap();
    drop(environment);

    let response = timeout(
        Duration::from_secs(3),
        client
            .get(format!("http://{target_address}/healthz"))
            .send(),
    )
    .await
    .expect("Proxy Web request timed out")
    .unwrap();
    assert_eq!(response.text().await.unwrap(), "proxy-web");
    target_task.await.unwrap();
    proxy_task.abort();
    let _ = proxy_task.await;
}

#[test]
fn proxy_web_url_only_allows_loopback_http() {
    assert!(normalize_proxy_web_url("http://127.0.0.1:8787").is_ok());
    assert!(normalize_proxy_web_url("http://localhost:8787/").is_ok());
    assert!(normalize_proxy_web_url("http://[::1]:8787").is_ok());
    assert!(normalize_proxy_web_url("https://proxy.example.com").is_ok());
    assert!(normalize_proxy_web_url("http://proxy.example.com").is_err());
    assert!(normalize_proxy_web_url("https://proxy.example.com/path").is_err());
    assert!(normalize_proxy_web_url("file:///tmp/proxy").is_err());
}

#[test]
fn registration_page_url_uses_the_validated_proxy_web_root() {
    let url = registration_page_url("http://127.0.0.1:8787").unwrap();
    assert_eq!(url.as_str(), "http://127.0.0.1:8787/?mode=register");

    assert!(registration_page_url("http://proxy.example.com").is_err());
    assert!(registration_page_url("https://proxy.example.com/path").is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn starts_windows_device_authorization_without_exposing_endpoint_overrides() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_http_request(&mut stream).await;
        assert!(request.starts_with("POST /api/v1/agent/device-authorizations HTTP/1.1"));
        assert!(request.contains(r#""platform":"windows""#));
        assert!(request.contains(r#""client_name":"PPAASS Windows Agent""#));
        let body = serde_json::json!({
            "device_code": "A".repeat(43),
            "user_code": "ABCD-EFGH-JKMN",
            "verification_uri": "/#agent-authorize",
            "verification_uri_complete": "/#agent-authorize=ABCD-EFGH-JKMN",
            "expires_in": 600,
            "interval": 5
        })
        .to_string();
        write_http_response(&mut stream, "200 OK", &[], &body).await;
    });

    let started = start_device_authorization(&format!("http://{address}"))
        .await
        .unwrap();
    assert_eq!(started.device_code.as_str(), "A".repeat(43));
    assert_eq!(started.user_code, "ABCD-EFGH-JKMN");
    assert_eq!(started.interval_seconds, 5);
    assert_eq!(
        started.verification_url.as_str(),
        format!("http://{address}/#agent-authorize=ABCD-EFGH-JKMN")
    );
    server.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn device_authorization_poll_honors_pending_and_slow_down_retry_after() {
    for (status, code, retry_after, expected_slow_down) in [
        (
            "428 Precondition Required",
            "authorization_pending",
            "7",
            false,
        ),
        ("429 Too Many Requests", "slow_down", "11", true),
        ("429 Too Many Requests", "rate_limited", "13", true),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_http_request(&mut stream).await;
            assert!(request.starts_with("POST /api/v1/agent/device-authorizations/token HTTP/1.1"));
            let body = serde_json::json!({
                "error": {
                    "code": code,
                    "message": "waiting"
                }
            })
            .to_string();
            write_http_response(&mut stream, status, &[("retry-after", retry_after)], &body).await;
        });

        let result = poll_device_authorization(&format!("http://{address}"), &"A".repeat(43), 5)
            .await
            .unwrap();
        match result {
            DeviceAuthorizationPoll::Pending {
                slow_down,
                retry_after_seconds,
            } => {
                assert_eq!(slow_down, expected_slow_down);
                assert_eq!(retry_after_seconds, retry_after.parse::<u32>().unwrap());
            }
            DeviceAuthorizationPoll::Authorized(_) => {
                panic!("pending response must not authorize the Agent")
            }
        }
        server.await.unwrap();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn device_authorization_poll_handles_all_terminal_errors() {
    for (status, code, expected_message) in [
        ("403 Forbidden", "access_denied", "拒绝"),
        ("400 Bad Request", "expired_token", "过期"),
        ("400 Bad Request", "invalid_device_code", "无效"),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _request = read_http_request(&mut stream).await;
            let body = serde_json::json!({
                "error": {
                    "code": code,
                    "message": "terminal"
                }
            })
            .to_string();
            write_http_response(&mut stream, status, &[], &body).await;
        });

        let error = poll_device_authorization(&format!("http://{address}"), &"A".repeat(43), 5)
            .await
            .err()
            .expect("terminal response must fail");
        assert!(error.contains(expected_message), "{error}");
        server.await.unwrap();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn device_authorization_validates_key_pair_and_logs_out_temporary_session() {
    let pair = RsaKeyPair::generate(2048).unwrap();
    let private_key = pair.private_key_to_pem().unwrap();
    let public_key = pair.public_key_to_pem().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut token_stream, _) = listener.accept().await.unwrap();
        let token_request = read_http_request(&mut token_stream).await;
        assert!(
            token_request.starts_with("POST /api/v1/agent/device-authorizations/token HTTP/1.1")
        );
        let body = serde_json::json!({
            "account": {
                "role": "user",
                "status": "active",
                "linked_username": "alice"
            },
            "profile": {
                "username": "alice",
                "permissions": ["key.private.read"],
                "key_version": 9,
                "expires_at": 4_000_000_000_i64
            },
            "public_key_pem": public_key.clone(),
            "proxy_identity_public_key_pem": public_key,
            "private_key_pem": private_key,
            "csrf_token": "csrf-device-token",
            "session_expires_at": 4_000_000_000_i64
        })
        .to_string();
        write_http_response(
            &mut token_stream,
            "200 OK",
            &[(
                "set-cookie",
                "ppaass_session=device-session; Path=/; HttpOnly; SameSite=Lax",
            )],
            &body,
        )
        .await;

        let (mut logout_stream, _) = listener.accept().await.unwrap();
        let logout_request = read_http_request(&mut logout_stream).await;
        assert!(logout_request.starts_with("POST /api/v1/auth/logout HTTP/1.1"));
        assert!(logout_request
            .to_ascii_lowercase()
            .contains("cookie: ppaass_session=device-session"));
        assert!(logout_request
            .to_ascii_lowercase()
            .contains("x-csrf-token: csrf-device-token"));
        write_http_response(&mut logout_stream, "204 No Content", &[], "").await;
    });

    let result = poll_device_authorization(&format!("http://{address}"), &"A".repeat(43), 5)
        .await
        .unwrap();
    match result {
        DeviceAuthorizationPoll::Authorized(downloaded) => {
            assert_eq!(downloaded.account.username, "alice");
            assert_eq!(downloaded.account.key_version, 9);
            assert!(downloaded.private_key_pem.contains("BEGIN PRIVATE KEY"));
        }
        DeviceAuthorizationPoll::Pending { .. } => {
            panic!("authorized response must deliver credentials")
        }
    }
    server.await.unwrap();
}

mod credential_tests;
