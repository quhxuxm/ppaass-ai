use common::{
    YAMUX_SESSION_STREAM_CAPACITY_EXHAUSTED_MESSAGE, YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE,
};
use desktop_agent_be::config::AgentConfig;
use desktop_agent_be::yamux_session::manager::{
    YamuxSessionManager, is_yamux_session_capacity_error, is_yamux_target_connect_error,
};
use std::sync::Arc;

const MINIMAL_AGENT_CONFIG: &str = r#"
listen_addr = "127.0.0.1:10080"
username = "user1"
private_key_path = "keys/user1.pem"
"#;

#[test]
fn yamux_capacity_errors_are_not_target_connect_errors() {
    assert!(!is_yamux_target_connect_error(
        YAMUX_SESSION_STREAM_CAPACITY_EXHAUSTED_MESSAGE
    ));
    assert!(is_yamux_session_capacity_error(
        YAMUX_SESSION_STREAM_CAPACITY_EXHAUSTED_MESSAGE
    ));
}

#[test]
fn yamux_response_timeouts_do_not_close_session() {
    assert!(is_yamux_target_connect_error(
        YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE
    ));
    assert!(is_yamux_target_connect_error("连接目标响应超时"));
}

#[test]
fn only_udp_manager_allocates_native_udp_pool() {
    let config: AgentConfig = toml::from_str(MINIMAL_AGENT_CONFIG).unwrap();
    let config = Arc::new(config);
    let proxy_addrs = Arc::new(vec!["127.0.0.1:8080".to_string()]);
    let tcp_manager = YamuxSessionManager::new(config.clone(), proxy_addrs.clone());
    let udp_manager = YamuxSessionManager::new_udp(config, proxy_addrs);

    assert_eq!(tcp_manager.native_udp_session_pool_size(), 0);
    assert_eq!(udp_manager.native_udp_session_pool_size(), 4);
    let slots: Vec<_> = (0..10)
        .map(|_| udp_manager.next_udp_session_slot())
        .collect();
    assert_eq!(slots, vec![0, 1, 2, 3, 0, 1, 2, 3, 0, 1]);
}

#[test]
fn tcp_transport_mode_does_not_allocate_native_udp_pool() {
    let config: AgentConfig =
        toml::from_str(&(MINIMAL_AGENT_CONFIG.to_owned() + "transport_mode = \"tcp\"\n")).unwrap();
    let manager = YamuxSessionManager::new_udp(
        Arc::new(config),
        Arc::new(vec!["127.0.0.1:8080".to_string()]),
    );

    assert_eq!(manager.native_udp_session_pool_size(), 0);
}

#[test]
fn auto_fallback_state_is_isolated_per_udp_session_slot() {
    let config: AgentConfig =
        toml::from_str(&(MINIMAL_AGENT_CONFIG.to_owned() + "transport_mode = \"auto\"\n")).unwrap();
    let manager = YamuxSessionManager::new_udp(
        Arc::new(config),
        Arc::new(vec!["127.0.0.1:8080".to_string()]),
    );

    assert_eq!(manager.auto_udp_fallback_slot_count(), 4);
    manager.set_auto_udp_fallback(1, true);
    assert!(!manager.auto_udp_fallback(0));
    assert!(manager.auto_udp_fallback(1));
    assert!(!manager.auto_udp_fallback(2));
}
