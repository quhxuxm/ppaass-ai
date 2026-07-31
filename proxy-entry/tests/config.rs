use proxy_entry::config::{
    PERMISSION_PROXY_CONNECT_TCP, PERMISSION_PROXY_CONNECT_UDP, ProxyConfig, UserConfig,
};
use std::path::PathBuf;

fn parse_config(extra: &str) -> Result<ProxyConfig, toml::de::Error> {
    toml::from_str(&format!(
        r#"
listen_addr = "127.0.0.1:0"
entry_id = "entry-test"
advertised_address = "proxy.example.com:443"
registry_url = "http://127.0.0.1:8797"
registry_control_token_path = "control-token"
{extra}
"#
    ))
}

fn user_with_expiry(expires_at: Option<&str>) -> UserConfig {
    UserConfig {
        username: "user1".to_string(),
        public_key_pem: "public-key".to_string(),
        expires_at: expires_at.map(str::to_string),
        permissions: vec![
            PERMISSION_PROXY_CONNECT_TCP.to_string(),
            PERMISSION_PROXY_CONNECT_UDP.to_string(),
        ],
        enabled: true,
        key_version: None,
    }
}

#[test]
fn relay_and_control_defaults_are_bounded() {
    let config = parse_config("tcp_relay_idle_timeout_secs = 60").unwrap();

    assert_eq!(config.tcp_relay_idle_timeout_secs, 60);
    assert_eq!(config.tcp_relay_half_close_idle_timeout_secs, 30);
    assert_eq!(config.yamux_session_idle_timeout_secs, 300);
    assert_eq!(config.udp_relay_channel_size, 64);
    assert_eq!(config.udp_relay_max_flows, 256);
    assert_eq!(config.udp_session_limit, 4096);
    assert_eq!(config.udp_session_limit_per_username, 64);
    assert_eq!(config.effective_udp_session_limit_per_username(), 64);
    assert_eq!(config.udp_session_channel_size, 256);
    assert_eq!(config.udp_session_max_flows, 256);
    assert_eq!(config.udp_session_authorization_recheck_secs, 5);
    assert_eq!(config.control_request_timeout_secs, 10);
    assert_eq!(config.authorization_cache_max_age_secs, 5);
}

#[test]
fn control_plane_fields_are_required() {
    for raw in [
        r#"listen_addr = "127.0.0.1:0""#,
        "listen_addr = \"127.0.0.1:0\"\nentry_id = \"entry-test\"",
        "listen_addr = \"127.0.0.1:0\"\nentry_id = \"entry-test\"\n\
         registry_url = \"http://127.0.0.1:8797\"\n\
         registry_control_token_path = \"control-token\"",
        "listen_addr = \"127.0.0.1:0\"\nentry_id = \"entry-test\"\n\
         advertised_address = \"proxy.example.com:443\"",
        "listen_addr = \"127.0.0.1:0\"\nentry_id = \"entry-test\"\n\
         advertised_address = \"proxy.example.com:443\"\n\
         registry_url = \"http://127.0.0.1:8797\"",
    ] {
        assert!(toml::from_str::<ProxyConfig>(raw).is_err());
    }
}

#[test]
fn removed_sqlite_fields_are_rejected() {
    assert!(
        parse_config(
            "users_database_path = \"users.sqlite3\"\n\
             access_log_database_path = \"access.sqlite3\""
        )
        .is_err()
    );
}

#[test]
fn removed_registry_control_url_field_is_rejected() {
    assert!(parse_config("registry_control_url = \"http://127.0.0.1:8797\"").is_err());
}

#[test]
fn removed_forward_fields_are_rejected() {
    for field in [
        "forward_mode = true",
        r#"upstream_proxy_addrs = ["127.0.0.1:8080"]"#,
        r#"upstream_username = "upstream-user""#,
        r#"upstream_private_key_path = "upstream-private-key.pem""#,
    ] {
        assert!(parse_config(field).is_err(), "{field} should be rejected");
    }
}

#[test]
fn checked_in_proxy_configs_use_only_current_fields() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    for relative in [
        "config/proxy-entry.toml",
        "tests/fixtures/config/proxy-entry-integration.toml",
        "tests/fixtures/config/proxy-entry-yamux.toml",
    ] {
        let raw = std::fs::read_to_string(workspace.join(relative)).unwrap();
        toml::from_str::<ProxyConfig>(&raw).unwrap();
    }
}

#[test]
fn udp_limits_are_configurable() {
    let config = parse_config(
        "udp_session_max_flows = 17\nudp_session_limit = 32\n\
         udp_session_limit_per_username = 64\nudp_relay_max_flows = 23",
    )
    .unwrap();

    assert_eq!(config.udp_session_max_flows, 17);
    assert_eq!(config.udp_session_limit_per_username, 64);
    assert_eq!(config.effective_udp_session_limit_per_username(), 32);
    assert_eq!(config.udp_relay_max_flows, 23);
}

#[test]
fn authorization_intervals_are_limited_to_five_seconds() {
    for value in [1, 3, 5] {
        let config = parse_config(&format!(
            "udp_session_authorization_recheck_secs = {value}\n\
             authorization_cache_max_age_secs = {value}"
        ))
        .unwrap();
        assert_eq!(config.udp_session_authorization_recheck_secs, value);
        assert_eq!(config.authorization_cache_max_age_secs, value);
    }
    for value in [0, 6, u64::MAX] {
        assert!(
            parse_config(&format!("udp_session_authorization_recheck_secs = {value}")).is_err()
        );
        assert!(parse_config(&format!("authorization_cache_max_age_secs = {value}")).is_err());
    }
}

#[test]
fn missing_expires_at_never_expires() {
    assert!(!user_with_expiry(None).is_expired_at(i64::MAX).unwrap());
}

#[test]
fn expires_when_current_time_reaches_configured_time() {
    let user = user_with_expiry(Some("2030-01-01T00:00:00Z"));
    assert!(!user.is_expired_at(1_893_455_999).unwrap());
    assert!(user.is_expired_at(1_893_456_000).unwrap());
}

#[test]
fn rejects_invalid_expires_at() {
    assert!(
        user_with_expiry(Some("2030-01-01 00:00:00"))
            .expires_at_unix_timestamp()
            .is_err()
    );
}
