use super::*;

#[test]
fn tcp_relay_idle_timeout_defaults_to_recycle_stalled_streams() {
    let config: ProxyConfig = toml::from_str(
        r#"
	listen_addr = "127.0.0.1:0"
	users_database_path = "users.sqlite3"
	access_log_database_path = "access.sqlite3"
	tcp_relay_idle_timeout_secs = 60
	"#,
    )
    .unwrap();

    assert_eq!(config.tcp_relay_idle_timeout_secs, 60);
    assert_eq!(config.tcp_relay_half_close_idle_timeout_secs, 30);
    assert_eq!(config.yamux_session_idle_timeout_secs, 300);
}

#[test]
fn udp_relay_queue_defaults_are_bounded() {
    let config: ProxyConfig = toml::from_str(
        r#"
listen_addr = "127.0.0.1:0"
users_database_path = "users.sqlite3"
access_log_database_path = "access.sqlite3"
"#,
    )
    .unwrap();

    assert_eq!(config.udp_relay_channel_size, 64);
    assert_eq!(config.udp_relay_max_flows, 256);
    assert_eq!(config.udp_session_limit, 4096);
    assert_eq!(config.udp_session_limit_per_username, 64);
    assert_eq!(config.effective_udp_session_limit_per_username(), 64);
    assert_eq!(config.udp_session_channel_size, 256);
    assert_eq!(config.udp_session_max_flows, 256);
    assert_eq!(config.udp_session_authorization_recheck_secs, 5);
    assert_eq!(config.users_database_path, "users.sqlite3");
    assert_eq!(config.access_log_database_path, "access.sqlite3");
    assert!(!config.access_log_database_group_writable);
}

#[test]
fn separate_access_database_mode_is_explicitly_configurable() {
    let config: ProxyConfig = toml::from_str(
        r#"
listen_addr = "127.0.0.1:0"
users_database_path = "data/proxy-users.sqlite3"
access_log_database_path = "data/proxy-access.sqlite3"
access_log_database_group_writable = true
"#,
    )
    .unwrap();

    assert_eq!(config.access_log_database_path, "data/proxy-access.sqlite3");
    assert!(config.access_log_database_group_writable);
}

#[test]
fn sqlite_user_and_access_database_paths_are_required() {
    assert!(
        toml::from_str::<ProxyConfig>(
            r#"
listen_addr = "127.0.0.1:0"
"#
        )
        .is_err()
    );
    assert!(
        toml::from_str::<ProxyConfig>(
            r#"
listen_addr = "127.0.0.1:0"
users_database_path = "users.sqlite3"
"#
        )
        .is_err()
    );
}

#[test]
fn removed_users_toml_path_is_rejected() {
    let result = toml::from_str::<ProxyConfig>(
        r#"
listen_addr = "127.0.0.1:0"
users_path = "users.toml"
users_database_path = "users.sqlite3"
access_log_database_path = "access.sqlite3"
"#,
    );

    assert!(result.is_err());
}

#[test]
fn checked_in_proxy_configs_use_only_current_fields() {
    for raw in [
        include_str!("../../../../config/local/proxy.toml"),
        include_str!("../../../../config/remote/proxy.toml"),
        include_str!("../../../../config/local/proxy-forward.toml"),
        include_str!("../../../../config/local/proxy-yamux-test.toml"),
        include_str!("../../../../config/proxy-e2e.local.toml"),
    ] {
        toml::from_str::<ProxyConfig>(raw).unwrap();
    }
}

#[test]
fn udp_session_max_flows_is_configurable() {
    let config: ProxyConfig = toml::from_str(
        r#"
listen_addr = "127.0.0.1:0"
users_database_path = "users.sqlite3"
access_log_database_path = "access.sqlite3"
udp_session_max_flows = 17
"#,
    )
    .unwrap();

    assert_eq!(config.udp_session_max_flows, 17);
}

#[test]
fn per_username_udp_session_limit_is_configurable_and_capped_globally() {
    let config: ProxyConfig = toml::from_str(
        r#"
listen_addr = "127.0.0.1:0"
users_database_path = "users.sqlite3"
access_log_database_path = "access.sqlite3"
udp_session_limit = 32
udp_session_limit_per_username = 64
"#,
    )
    .unwrap();

    assert_eq!(config.udp_session_limit_per_username, 64);
    assert_eq!(config.effective_udp_session_limit_per_username(), 32);
}

#[test]
fn udp_session_authorization_recheck_is_limited_to_five_seconds() {
    for value in [1, 3, 5] {
        let config: ProxyConfig = toml::from_str(&format!(
            r#"
listen_addr = "127.0.0.1:0"
users_database_path = "users.sqlite3"
access_log_database_path = "access.sqlite3"
udp_session_authorization_recheck_secs = {value}
"#
        ))
        .unwrap();
        assert_eq!(config.udp_session_authorization_recheck_secs, value);
    }
    for value in [0, 6, u64::MAX] {
        assert!(
            toml::from_str::<ProxyConfig>(&format!(
                r#"
listen_addr = "127.0.0.1:0"
users_database_path = "users.sqlite3"
access_log_database_path = "access.sqlite3"
udp_session_authorization_recheck_secs = {value}
"#
            ))
            .is_err()
        );
    }
}

#[test]
fn udp_relay_max_flows_is_configurable() {
    let config: ProxyConfig = toml::from_str(
        r#"
listen_addr = "127.0.0.1:0"
users_database_path = "users.sqlite3"
access_log_database_path = "access.sqlite3"
udp_relay_max_flows = 23
"#,
    )
    .unwrap();

    assert_eq!(config.udp_relay_max_flows, 23);
}
