use common::{QuicPolicy, TransportMode};
use desktop_agent_be::config::*;
use protocol::CompressionMode;
use std::fs;
use std::path::Path;

const MINIMAL_AGENT_CONFIG: &str = r#"
listen_addr = "0.0.0.0:10080"
username = "user1"
private_key_path = "keys/user1.pem"
"#;

#[test]
fn compression_mode_defaults_to_none() {
    let config: AgentConfig = toml::from_str(MINIMAL_AGENT_CONFIG).unwrap();

    assert_eq!(config.get_compression_mode(), CompressionMode::None);
    assert_eq!(config.transport_mode, TransportMode::Udp);
}

#[test]
fn proxy_registry_url_is_optional_for_backend_library_and_test_harness() {
    let config: AgentConfig = toml::from_str(MINIMAL_AGENT_CONFIG).unwrap();

    assert_eq!(config.proxy_registry_url, None);
}

#[test]
fn proxy_registry_url_is_parsed_when_configured() {
    let config: AgentConfig = toml::from_str(
        &(MINIMAL_AGENT_CONFIG.to_owned() + "proxy_registry_url = \"https://proxy.example.com\"\n"),
    )
    .unwrap();

    assert_eq!(
        config.proxy_registry_url.as_deref(),
        Some("https://proxy.example.com")
    );
}

#[test]
fn transport_mode_accepts_auto_udp_and_tcp() {
    let auto: AgentConfig =
        toml::from_str(&(MINIMAL_AGENT_CONFIG.to_owned() + "transport_mode = \"auto\"\n")).unwrap();
    assert_eq!(auto.transport_mode, TransportMode::Auto);

    let udp: AgentConfig =
        toml::from_str(&(MINIMAL_AGENT_CONFIG.to_owned() + "transport_mode = \"udp\"\n")).unwrap();
    assert_eq!(udp.transport_mode, TransportMode::Udp);

    let config: AgentConfig =
        toml::from_str(&(MINIMAL_AGENT_CONFIG.to_owned() + "transport_mode = \"tcp\"\n")).unwrap();
    assert_eq!(config.transport_mode, TransportMode::Tcp);
}

#[test]
fn removed_quic_transport_mode_is_rejected() {
    let result = toml::from_str::<AgentConfig>(
        &(MINIMAL_AGENT_CONFIG.to_owned() + "transport_mode = \"quic\"\n"),
    );

    assert!(result.is_err());
}

#[test]
fn udp_session_pool_defaults_to_four_and_is_bounded() {
    let default_config: AgentConfig = toml::from_str(MINIMAL_AGENT_CONFIG).unwrap();
    assert_eq!(default_config.effective_udp_session_pool_size(), 4);

    let disabled: AgentConfig =
        toml::from_str(&(MINIMAL_AGENT_CONFIG.to_owned() + "udp_session_pool_size = 0\n")).unwrap();
    assert_eq!(disabled.effective_udp_session_pool_size(), 1);

    let excessive: AgentConfig =
        toml::from_str(&(MINIMAL_AGENT_CONFIG.to_owned() + "udp_session_pool_size = 64\n"))
            .unwrap();
    assert_eq!(excessive.effective_udp_session_pool_size(), 8);
}

#[test]
fn removed_quic_connection_pool_field_is_rejected() {
    let result = toml::from_str::<AgentConfig>(
        &(MINIMAL_AGENT_CONFIG.to_owned() + "quic_connection_pool_size = 4\n"),
    );

    assert!(result.is_err());
}

#[test]
fn removed_proxy_addrs_config_field_is_rejected() {
    let result = toml::from_str::<AgentConfig>(
        &(MINIMAL_AGENT_CONFIG.to_owned() + "proxy_addrs = [\"proxy.example.com:443\"]\n"),
    );

    assert!(result.is_err());
}

#[test]
fn parses_compression_mode() {
    let config: AgentConfig =
        toml::from_str(&(MINIMAL_AGENT_CONFIG.to_owned() + r#"compression_mode = "lz4""#)).unwrap();

    assert_eq!(config.get_compression_mode(), CompressionMode::Lz4);
}

#[test]
fn tun_uses_platform_quic_default() {
    let config: AgentConfig = toml::from_str(MINIMAL_AGENT_CONFIG).unwrap();

    let expected = if cfg!(windows) {
        QuicPolicy::Block
    } else {
        QuicPolicy::Allow
    };
    assert_eq!(config.tun.effective_quic_policy(), expected);
}

#[test]
fn tun_proxies_udp_by_default() {
    let config: AgentConfig = toml::from_str(MINIMAL_AGENT_CONFIG).unwrap();

    assert!(config.tun.proxy_udp);
}

#[test]
fn tun_proxies_dns_by_default() {
    let config: AgentConfig = toml::from_str(
        &(MINIMAL_AGENT_CONFIG.to_owned()
            + r#"
[tun]
enabled = true
"#),
    )
    .unwrap();

    assert!(config.tun.enabled);
    assert!(config.tun.proxy_dns);
}

#[cfg(windows)]
#[test]
fn windows_tun_captures_ipv6_by_default() {
    let config: AgentConfig = toml::from_str(MINIMAL_AGENT_CONFIG).unwrap();

    assert_eq!(config.tun.ipv6.as_deref(), Some("fd00:10:10:10::1/64"));
}

#[cfg(not(windows))]
#[test]
fn non_windows_tun_keeps_ipv6_opt_in() {
    let config: AgentConfig = toml::from_str(MINIMAL_AGENT_CONFIG).unwrap();

    assert_eq!(config.tun.ipv6, None);
}

#[test]
fn tun_preserves_explicitly_disabled_dns_proxy() {
    let config: AgentConfig = toml::from_str(
        &(MINIMAL_AGENT_CONFIG.to_owned()
            + r#"
[tun]
enabled = true
proxy_dns = false
"#),
    )
    .unwrap();

    assert!(config.tun.enabled);
    assert!(!config.tun.proxy_dns);
}

#[test]
fn tun_can_disable_udp_proxying() {
    let config: AgentConfig = toml::from_str(
        &(MINIMAL_AGENT_CONFIG.to_owned()
            + r#"
[tun]
proxy_udp = false
"#),
    )
    .unwrap();

    assert!(!config.tun.proxy_udp);
}

#[test]
fn tun_rejects_removed_helper_field_names() {
    for removed_field in [
        "helper_enabled = true",
        "helper_socket = \"/tmp/legacy-helper.sock\"",
        "helper_fallback_to_privilege = true",
    ] {
        let result = toml::from_str::<AgentConfig>(
            &(MINIMAL_AGENT_CONFIG.to_owned()
                + &format!(
                    r#"
[tun]
proxy_dns = true
{removed_field}
"#
                )),
        );

        assert!(
            result.is_err(),
            "removed TUN helper field must be rejected: {removed_field}"
        );
    }
}

#[test]
fn checked_in_agent_configs_use_only_current_fields() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    for relative_path in [
        "config/agent.toml",
        "tests/fixtures/config/agent-integration.toml",
        "tests/fixtures/config/agent-yamux.toml",
    ] {
        let raw = fs::read_to_string(workspace.join(relative_path)).unwrap();
        let mut value = toml::from_str::<toml::Value>(&raw).unwrap();
        let root = value.as_table_mut().unwrap();
        root.insert(
            "username".to_string(),
            toml::Value::String("config-test".to_string()),
        );
        root.insert(
            "private_key_path".to_string(),
            toml::Value::String("keys/config-test.pem".to_string()),
        );

        toml::from_str::<AgentConfig>(&toml::to_string(&value).unwrap()).unwrap();
    }
}

#[test]
fn packet_capture_has_default_file() {
    let config: AgentConfig = toml::from_str(MINIMAL_AGENT_CONFIG).unwrap();

    assert_eq!(config.tun.packet_capture.file, "captures/ppaass-tun.pcap");
}

#[test]
fn parses_packet_capture_settings() {
    let config: AgentConfig = toml::from_str(
        &(MINIMAL_AGENT_CONFIG.to_owned()
            + r#"
[tun.packet_capture]
file = "captures/debug.pcap"
"#),
    )
    .unwrap();

    assert_eq!(config.tun.packet_capture.file, "captures/debug.pcap");
}

#[test]
fn explicit_quic_policy_blocks_quic() {
    let config: AgentConfig = toml::from_str(
        &(MINIMAL_AGENT_CONFIG.to_owned()
            + r#"
[tun]
quic_policy = "block"
"#),
    )
    .unwrap();

    assert_eq!(config.tun.effective_quic_policy(), QuicPolicy::Block);
}
