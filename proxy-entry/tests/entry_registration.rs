mod support;

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    routing::post,
};
use proxy_control_protocol::{
    CONTROL_PROTOCOL_VERSION, ENTRY_REGISTRATION_PATH, EntryRegistrationRequest,
    EntryRegistrationResponse,
};
use proxy_entry::server::ProxyServer;
use tokio::sync::Mutex;

const TEST_TOKEN: &str = "0123456789abcdef0123456789abcdef";

#[derive(Clone, Default)]
struct RegistrationState {
    attempts: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<(String, EntryRegistrationRequest)>>>,
}

async fn register_entry(
    State(state): State<RegistrationState>,
    headers: HeaderMap,
    Json(request): Json<EntryRegistrationRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    state.requests.lock().await.push((authorization, request));
    let attempt = state.attempts.fetch_add(1, Ordering::AcqRel) + 1;
    if attempt == 1 {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "retry" })),
        );
    }
    (
        StatusCode::OK,
        Json(
            serde_json::to_value(EntryRegistrationResponse {
                registry_instance_id: "registry-test".to_string(),
                protocol_version: CONTROL_PROTOCOL_VERSION,
                received_at: 1_785_490_000,
            })
            .unwrap(),
        ),
    )
}

#[tokio::test]
async fn registration_starts_after_listening_and_retries_in_background() {
    let state = RegistrationState::default();
    let app = Router::new()
        .route(ENTRY_REGISTRATION_PATH, post(register_entry))
        .with_state(state.clone());
    let registry_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let registry_address = registry_listener.local_addr().unwrap();
    let registry_task = tokio::spawn(async move { axum::serve(registry_listener, app).await });

    let directory = tempfile::TempDir::new().unwrap();
    let token_path = directory.path().join("control-token");
    std::fs::write(&token_path, TEST_TOKEN).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut config = support::proxy_config("");
    config.registry_url = format!("http://{registry_address}");
    config.registry_control_token_path = token_path.display().to_string();
    config.advertised_address = "Proxy.Example.com:443".to_string();

    let server = ProxyServer::new(config).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(state.attempts.load(Ordering::Acquire), 0);

    let entry_task = tokio::spawn(server.run());
    tokio::time::timeout(Duration::from_secs(4), async {
        while state.attempts.load(Ordering::Acquire) < 2 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("Entry 应在首次注册失败后继续后台重试");
    assert!(!entry_task.is_finished(), "注册失败不应停止 Entry 服务");

    let requests = state.requests.lock().await;
    assert_eq!(requests.len(), 2);
    for (authorization, request) in requests.iter() {
        assert_eq!(authorization, &format!("Bearer {TEST_TOKEN}"));
        assert_eq!(request.entry_id, "entry-test");
        assert_eq!(request.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(request.protocol_version, CONTROL_PROTOCOL_VERSION);
        assert_eq!(request.advertised_address, "proxy.example.com:443");
    }
    drop(requests);

    entry_task.abort();
    registry_task.abort();
}
