use android_agent::{AndroidAgentConfig, AndroidTunConfig};
use common::{QuicPolicy, TransportMode};

#[test]
fn tun_allows_quic_by_default() {
    let config = AndroidTunConfig::default();

    assert_eq!(config.effective_quic_policy(), QuicPolicy::Allow);
}

#[test]
fn agent_transport_defaults_to_udp() {
    let config: AndroidAgentConfig = serde_json::from_str(
        r#"{"proxy_addrs":["127.0.0.1:8080"],"username":"u","private_key_pem":"key"}"#,
    )
    .unwrap();
    assert_eq!(config.transport_mode, TransportMode::Udp);
}

#[test]
fn agent_debug_redacts_private_key() {
    let config: AndroidAgentConfig = serde_json::from_str(
        r#"{"proxy_addrs":["127.0.0.1:8080"],"username":"u","private_key_pem":"super-secret-private-key"}"#,
    )
    .unwrap();

    let rendered = format!("{config:?}");
    assert!(rendered.contains("private_key_pem: <redacted>"));
    assert!(rendered.contains("proxy_address_count: 1"));
    assert!(!rendered.contains("super-secret-private-key"));
    assert!(!rendered.contains("127.0.0.1:8080"));
}

#[test]
fn proxy_addresses_are_selected_round_robin() {
    let config: AndroidAgentConfig = serde_json::from_str(
        r#"{"proxy_addrs":["proxy-a:8080","proxy-b:8080"],"username":"u","private_key_pem":"key"}"#,
    )
    .unwrap();

    assert_eq!(config.proxy_address_at(0), "proxy-a:8080");
    assert_eq!(config.proxy_address_at(1), "proxy-b:8080");
    assert_eq!(config.proxy_address_at(2), "proxy-a:8080");
}

#[test]
fn agent_transport_accepts_auto() {
    let config: AndroidAgentConfig = serde_json::from_str(
        r#"{"proxy_addrs":["127.0.0.1:8080"],"username":"u","private_key_pem":"key","transport_mode":"auto"}"#,
    )
    .unwrap();
    assert_eq!(config.transport_mode, TransportMode::Auto);
}

#[test]
fn udp_session_pool_defaults_to_four_and_is_bounded() {
    let default_config: AndroidAgentConfig = serde_json::from_str(
        r#"{"proxy_addrs":["127.0.0.1:8080"],"username":"u","private_key_pem":"key"}"#,
    )
    .unwrap();
    assert_eq!(default_config.effective_udp_session_pool_size(), 4);

    let disabled: AndroidAgentConfig = serde_json::from_str(
        r#"{"proxy_addrs":["127.0.0.1:8080"],"username":"u","private_key_pem":"key","udp_session_pool_size":0}"#,
    )
    .unwrap();
    assert_eq!(disabled.effective_udp_session_pool_size(), 1);

    let excessive: AndroidAgentConfig = serde_json::from_str(
        r#"{"proxy_addrs":["127.0.0.1:8080"],"username":"u","private_key_pem":"key","udp_session_pool_size":64}"#,
    )
    .unwrap();
    assert_eq!(excessive.effective_udp_session_pool_size(), 8);
}

#[test]
fn rejects_removed_quic_transport_mode() {
    let result = serde_json::from_str::<AndroidAgentConfig>(
        r#"{"proxy_addrs":["127.0.0.1:8080"],"username":"u","private_key_pem":"key","transport_mode":"quic"}"#,
    );

    assert!(result.is_err());
}

#[test]
fn rejects_removed_quic_connection_pool_field() {
    let result = serde_json::from_str::<AndroidAgentConfig>(
        r#"{"proxy_addrs":["127.0.0.1:8080"],"username":"u","private_key_pem":"key","transport_mode":"udp","quic_connection_pool_size":4}"#,
    );

    assert!(result.is_err());
}

#[test]
fn explicit_quic_policy_blocks_quic() {
    let config: AndroidTunConfig = serde_json::from_str(r#"{"quic_policy":"block"}"#).unwrap();

    assert_eq!(config.effective_quic_policy(), QuicPolicy::Block);
}
