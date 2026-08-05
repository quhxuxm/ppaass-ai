mod support;

use protocol::{Address, TransportProtocol};
use proxy_control_protocol::AccessEvent;
use proxy_entry::access_log::{AccessRecorder, access_target};
use proxy_entry::control_plane::{
    AccessEventSink, load_control_token, validate_advertised_address, validate_entry_id,
    validate_registry_url,
};
use proxy_entry::error::{ProxyError, Result};
use proxy_entry::server::ProxyServer;
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};

#[derive(Default)]
struct RetrySink {
    batch_ids: Mutex<Vec<String>>,
    delivered: Notify,
}

#[async_trait::async_trait]
impl AccessEventSink for RetrySink {
    async fn submit_access_batch(&self, batch_id: &str, _events: &[AccessEvent]) -> Result<()> {
        let mut ids = self.batch_ids.lock().await;
        ids.push(batch_id.to_string());
        if ids.len() == 1 {
            return Err(ProxyError::ControlPlane("模拟响应丢失".to_string()));
        }
        self.delivered.notify_one();
        Ok(())
    }
}

#[test]
fn maps_real_targets_without_virtual_addresses() {
    assert_eq!(
        access_target(&Address::Domain {
            host: "example.com".to_string(),
            port: 443,
        }),
        Some(("example.com".to_string(), 443))
    );
    assert_eq!(
        access_target(&Address::Ipv4 {
            addr: [192, 0, 2, 1],
            port: 53,
        }),
        Some(("192.0.2.1".to_string(), 53))
    );
    assert_eq!(access_target(&Address::ProxyDns { port: 53 }), None);
    assert_eq!(access_target(&Address::UdpRelay), None);
}

#[tokio::test]
async fn retries_a_batch_with_the_same_id() {
    let sink = Arc::new(RetrySink::default());
    let recorder = AccessRecorder::start(sink.clone());
    recorder.record(
        "alice",
        TransportProtocol::Tcp,
        &Address::Domain {
            host: "example.com".to_string(),
            port: 443,
        },
    );
    tokio::time::timeout(std::time::Duration::from_secs(3), sink.delivered.notified())
        .await
        .unwrap();

    let batch_ids = sink.batch_ids.lock().await;
    assert_eq!(batch_ids.len(), 2);
    assert_eq!(batch_ids[0], batch_ids[1]);
}

#[test]
fn registry_url_accepts_http_and_https() {
    assert!(validate_registry_url("https://registry.example.com").is_ok());
    assert!(validate_registry_url("http://127.0.0.1:8797").is_ok());
    assert!(validate_registry_url("http://localhost:8797").is_ok());
    assert!(validate_registry_url("http://registry.example.com").is_ok());
    assert!(validate_registry_url("https://registry.example.com?token=bad").is_err());
    assert!(validate_registry_url("ftp://registry.example.com").is_err());
    assert!(validate_registry_url("https://").is_err());
}

#[test]
fn advertised_address_requires_a_normalized_host_and_nonzero_port() {
    assert_eq!(
        validate_advertised_address("Proxy.Example.com:443").unwrap(),
        "proxy.example.com:443"
    );
    assert_eq!(
        validate_advertised_address("192.0.2.1:80").unwrap(),
        "192.0.2.1:80"
    );
    assert_eq!(
        validate_advertised_address("[2001:db8::1]:8443").unwrap(),
        "[2001:db8::1]:8443"
    );
    for invalid in [
        "proxy.example.com",
        "proxy.example.com:0",
        "proxy.example.com:65536",
        "2001:db8::1:443",
        "bad_host.example.com:443",
        "-proxy.example.com:443",
        "https://proxy.example.com:443",
    ] {
        assert!(
            validate_advertised_address(invalid).is_err(),
            "{invalid} should be rejected"
        );
    }
}

#[tokio::test]
async fn server_construction_does_not_require_a_reachable_registry() {
    let directory = tempfile::TempDir::new().unwrap();
    let token_path = directory.path().join("control-token");
    std::fs::write(&token_path, "0123456789abcdef0123456789abcdef").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut config = support::proxy_config("");
    config.registry_url = "http://127.0.0.1:9".to_string();
    config.registry_control_token_path = token_path.display().to_string();
    config.authorization_database_path = directory
        .path()
        .join("nested")
        .join("authorization.sqlite3")
        .display()
        .to_string();

    tokio::time::timeout(std::time::Duration::from_secs(2), ProxyServer::new(config))
        .await
        .expect("构造 Entry 不应等待 Registry 网络连接")
        .expect("Registry 离线不应阻止 Entry 构造");
}

#[test]
fn entry_id_rejects_unsafe_or_empty_values() {
    assert!(validate_entry_id("entry-production:1").is_ok());
    assert!(validate_entry_id("").is_err());
    assert!(validate_entry_id("../entry").is_err());
    assert!(
        validate_entry_id(&"x".repeat(proxy_control_protocol::MAX_ENTRY_ID_BYTES + 1)).is_err()
    );
}

#[test]
fn control_token_file_is_trimmed_and_validated() {
    let directory = tempfile::TempDir::new().unwrap();
    let path = directory.path().join("control-token");
    let token = "0123456789abcdef0123456789abcdef";
    std::fs::write(&path, format!("{token}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert_eq!(load_control_token(&path).unwrap(), token);

    std::fs::write(&path, "too-short").unwrap();
    assert!(load_control_token(&path).is_err());
}
