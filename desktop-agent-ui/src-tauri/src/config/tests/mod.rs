use super::{
    apply_managed_credentials_to_config, bundled_agent_config_resource,
    clear_managed_credentials_from_config, enforce_managed_identity, load_config_from_path,
    proxy_web_url_from_config, redact_managed_identity, summarize_config,
    toggle_tun_enabled_in_config, upsert_toml_bool, write_config_file,
};
use crate::models::LoadedAgentConfig;
use std::fs;

#[test]
fn write_config_file_overwrites_readonly_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.toml");
    fs::write(&path, "username = \"old\"\n").unwrap();

    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&path, permissions).unwrap();

    write_config_file(&path, "username = \"new\"\n").unwrap();

    assert_eq!(fs::read_to_string(&path).unwrap(), "username = \"new\"\n");
    assert!(!fs::metadata(&path).unwrap().permissions().readonly());
}

#[test]
fn toggle_tun_enabled_in_config_flips_current_value() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.toml");
    fs::write(&path, "[tun]\nenabled = false\n").unwrap();

    let loaded = toggle_tun_enabled_in_config(Some(&path)).unwrap();
    assert!(loaded.summary.tun_enabled);
    assert!(loaded.summary.tun_proxy_dns);
    assert!(fs::read_to_string(&path)
        .unwrap()
        .contains("enabled = true"));

    let loaded = toggle_tun_enabled_in_config(Some(&path)).unwrap();
    assert!(!loaded.summary.tun_enabled);
    assert!(fs::read_to_string(&path)
        .unwrap()
        .contains("enabled = false"));

    fs::write(&path, "[tun]\nenabled = false\nproxy_dns = false\n").unwrap();
    let explicitly_disabled_dns = toggle_tun_enabled_in_config(Some(&path)).unwrap();
    assert!(explicitly_disabled_dns.summary.tun_enabled);
    assert!(!explicitly_disabled_dns.summary.tun_proxy_dns);
    assert!(fs::read_to_string(&path)
        .unwrap()
        .contains("proxy_dns = false"));
}

#[test]
fn summarize_config_preserves_udp_yamux_settings() {
    let summary = summarize_config(
        r#"
listen_addr = "0.0.0.0:10080"
username = "user1"
private_key_path = "keys/user1.pem"

[yamux.udp]
sessions = 3
max_streams_per_session = 32
open_stream_timeout_secs = 5
keepalive_interval_secs = 0
connection_write_timeout_secs = 9
stream_window_size_kb = 1024
"#,
    )
    .unwrap();

    assert_eq!(summary.udp_yamux_sessions, 3);
    assert_eq!(summary.udp_yamux_max_streams_per_session, 32);
    assert_eq!(summary.udp_yamux_open_stream_timeout_secs, 5);
    assert_eq!(summary.udp_yamux_keepalive_interval_secs, 0);
    assert_eq!(summary.udp_yamux_connection_write_timeout_secs, 9);
    assert_eq!(summary.udp_yamux_stream_window_size_kb, 1024);
}

#[test]
fn summarize_config_defaults_to_udp_and_clamps_udp_session_pool_size() {
    let base = r#"
listen_addr = "0.0.0.0:10080"
username = "user1"
private_key_path = "keys/user1.pem"
"#;

    let default_summary = summarize_config(base).unwrap();
    assert_eq!(default_summary.transport_mode, "udp");
    assert_eq!(
        summarize_config(&format!("{base}transport_mode = \"auto\"\n"))
            .unwrap()
            .transport_mode,
        "auto"
    );
    assert_eq!(default_summary.udp_session_pool_size, 4);
    assert_eq!(
        summarize_config(&format!("{base}udp_session_pool_size = 0\n"))
            .unwrap()
            .udp_session_pool_size,
        1
    );
    assert_eq!(
        summarize_config(&format!("{base}udp_session_pool_size = 64\n"))
            .unwrap()
            .udp_session_pool_size,
        8
    );
    assert_eq!(
        summarize_config(&format!("{base}udp_session_pool_size = 6\n"))
            .unwrap()
            .udp_session_pool_size,
        6
    );
}

#[test]
fn summarize_config_rejects_removed_quic_transport_configuration() {
    let removed_mode = summarize_config("transport_mode = \"quic\"\n");
    assert!(removed_mode.is_err());

    let removed_pool = summarize_config("quic_connection_pool_size = 4\n");
    assert!(removed_pool.is_err());
}

#[test]
fn summarize_config_rejects_removed_tun_helper_fields() {
    for (removed, current) in [
        ("helper_enabled", "macos_helper_enabled"),
        ("helper_socket", "macos_helper_socket"),
        (
            "helper_fallback_to_privilege",
            "macos_helper_fallback_to_privilege",
        ),
    ] {
        let error = summarize_config(&format!("[tun]\n{removed} = true\n")).unwrap_err();

        assert!(error.contains(current));
    }
}

#[test]
fn summarize_config_rejects_removed_proxy_addresses_field() {
    let error = summarize_config("proxy_addrs = [\"proxy.example.com:443\"]\n").unwrap_err();

    assert!(error.contains("proxy_addrs 已移除"));
}

#[test]
fn summarize_config_allows_tun_quic_by_default() {
    let summary = summarize_config(
        r#"
listen_addr = "0.0.0.0:10080"
username = "user1"
private_key_path = "keys/user1.pem"
"#,
    )
    .unwrap();

    assert_eq!(summary.tun_quic_policy, "allow");
}

#[test]
fn summarize_config_proxies_tun_udp_by_default() {
    let summary = summarize_config(
        r#"
listen_addr = "0.0.0.0:10080"
username = "user1"
private_key_path = "keys/user1.pem"
"#,
    )
    .unwrap();

    assert!(summary.tun_proxy_udp);
}

#[test]
fn summarize_config_uses_default_tun_dns_proxy() {
    let summary = summarize_config(
        r#"
listen_addr = "0.0.0.0:10080"

[tun]
enabled = true
"#,
    )
    .unwrap();

    assert!(summary.tun_enabled);
    assert!(summary.tun_proxy_dns);
}

#[test]
fn summarize_config_preserves_explicitly_disabled_tun_dns_proxy() {
    let summary = summarize_config(
        r#"
listen_addr = "0.0.0.0:10080"

[tun]
enabled = true
proxy_dns = false
"#,
    )
    .unwrap();

    assert!(summary.tun_enabled);
    assert!(!summary.tun_proxy_dns);
}

#[test]
fn summarize_config_reads_disabled_tun_udp_proxy() {
    let summary = summarize_config(
        r#"
listen_addr = "0.0.0.0:10080"
username = "user1"
private_key_path = "keys/user1.pem"

[tun]
proxy_udp = false
"#,
    )
    .unwrap();

    assert!(!summary.tun_proxy_udp);
}

#[test]
fn summarize_config_reads_block_policy() {
    let summary = summarize_config(
        r#"
listen_addr = "0.0.0.0:10080"
username = "user1"
private_key_path = "keys/user1.pem"

[tun]
quic_policy = "block"
"#,
    )
    .unwrap();

    assert_eq!(summary.tun_quic_policy, "block");
}

#[test]
fn summarize_config_reads_packet_capture() {
    let summary = summarize_config(
        r#"
listen_addr = "0.0.0.0:10080"
username = "user1"
private_key_path = "keys/user1.pem"

[tun.packet_capture]
file = "captures/debug.pcap"
"#,
    )
    .unwrap();

    assert_eq!(summary.tun_packet_capture_file, "captures/debug.pcap");
}

mod identity_tests;
