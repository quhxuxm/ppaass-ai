use super::*;

fn parse_config(extra: &str) -> Result<ProxyConfig, toml::de::Error> {
    toml::from_str(&format!(
        r#"
listen_addr = "127.0.0.1:0"
entry_id = "entry-test"
registry_control_url = "http://127.0.0.1:8797"
registry_control_token_path = "control-token"
{extra}
"#
    ))
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
        r#"
listen_addr = "127.0.0.1:0"
entry_id = "entry-test"
"#,
        r#"
listen_addr = "127.0.0.1:0"
entry_id = "entry-test"
registry_control_url = "http://127.0.0.1:8797"
"#,
    ] {
        assert!(toml::from_str::<ProxyConfig>(raw).is_err());
    }
}

#[test]
fn removed_sqlite_fields_are_rejected() {
    assert!(
        parse_config(
            r#"
users_database_path = "users.sqlite3"
access_log_database_path = "access.sqlite3"
"#
        )
        .is_err()
    );
}

#[test]
fn checked_in_proxy_configs_use_only_current_fields() {
    for raw in [
        include_str!("../../../../config/local/proxy-entry.toml"),
        include_str!("../../../../config/remote/proxy-entry.toml"),
        include_str!("../../../../config/local/proxy-entry-forward.toml"),
        include_str!("../../../../config/local/proxy-entry-yamux-test.toml"),
    ] {
        toml::from_str::<ProxyConfig>(raw).unwrap();
    }
}

#[test]
fn udp_limits_are_configurable() {
    let config = parse_config(
        r#"
udp_session_max_flows = 17
udp_session_limit = 32
udp_session_limit_per_username = 64
udp_relay_max_flows = 23
"#,
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
