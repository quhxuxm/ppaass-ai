use std::sync::Arc;

use android_agent::yamux_session::{
    AndroidYamuxSessionManager, ProxyStreamRoute, is_native_udp_timeout,
    is_yamux_actual_target_connect_error, proxy_stream_route,
};
use android_agent::{AndroidAgentConfig, AndroidAgentError};
use common::{
    TransportMode, YAMUX_OPEN_STREAM_TIMEOUT_MESSAGE,
    YAMUX_SESSION_STREAM_CAPACITY_EXHAUSTED_MESSAGE, YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE,
};
use protocol::TransportProtocol;
use tokio_util::sync::CancellationToken;

const MINIMAL_AGENT_CONFIG: &str = r#"{
        "proxy_addrs": ["127.0.0.1:8080"],
        "username": "user1",
        "private_key_pem": "key"
    }"#;

#[test]
fn yamux_session_errors_do_not_close_session_for_target_timeouts() {
    assert!(is_yamux_actual_target_connect_error(
        YAMUX_TARGET_CONNECT_RESPONSE_TIMEOUT_MESSAGE
    ));
    assert!(is_yamux_actual_target_connect_error("连接目标响应超时"));
    assert!(!is_yamux_actual_target_connect_error(
        YAMUX_OPEN_STREAM_TIMEOUT_MESSAGE
    ));
    assert!(!is_yamux_actual_target_connect_error(
        YAMUX_SESSION_STREAM_CAPACITY_EXHAUSTED_MESSAGE
    ));
}

#[test]
fn actual_target_connect_error_is_reported_directly() {
    assert!(is_yamux_actual_target_connect_error(
        "连接失败: Connection refused"
    ));
}

#[test]
fn udp_session_pool_round_robins_across_independent_sockets() {
    let config: AndroidAgentConfig = serde_json::from_str(MINIMAL_AGENT_CONFIG).unwrap();
    let manager = AndroidYamuxSessionManager::new_udp(Arc::new(config), CancellationToken::new());

    assert_eq!(manager.udp_session_pool_size(), 4);
    let slots: Vec<_> = (0..10).map(|_| manager.next_udp_session_slot()).collect();
    assert_eq!(slots, vec![0, 1, 2, 3, 0, 1, 2, 3, 0, 1]);
}

#[test]
fn udp_mode_routes_only_udp_over_native_udp() {
    assert_eq!(
        proxy_stream_route(
            TransportMode::Udp,
            TransportProtocol::Tcp,
            TransportProtocol::Tcp,
        ),
        Some(ProxyStreamRoute::DirectTcp)
    );
    assert_eq!(
        proxy_stream_route(
            TransportMode::Udp,
            TransportProtocol::Udp,
            TransportProtocol::Udp,
        ),
        Some(ProxyStreamRoute::NativeUdp)
    );
}

#[test]
fn tcp_mode_keeps_udp_on_yamux_and_tcp_on_direct_framed_tcp() {
    assert_eq!(
        proxy_stream_route(
            TransportMode::Tcp,
            TransportProtocol::Tcp,
            TransportProtocol::Tcp,
        ),
        Some(ProxyStreamRoute::DirectTcp)
    );
    assert_eq!(
        proxy_stream_route(
            TransportMode::Tcp,
            TransportProtocol::Udp,
            TransportProtocol::Udp,
        ),
        Some(ProxyStreamRoute::Yamux)
    );
}

#[test]
fn auto_mode_routes_udp_through_runtime_fallback_path() {
    assert_eq!(
        proxy_stream_route(
            TransportMode::Auto,
            TransportProtocol::Udp,
            TransportProtocol::Udp,
        ),
        Some(ProxyStreamRoute::Auto)
    );
    assert!(is_native_udp_timeout(&AndroidAgentError::Connection(
        "原生 UDP 认证响应超时".into()
    )));
    assert!(!is_native_udp_timeout(&AndroidAgentError::Connection(
        "authentication failed".into()
    )));
}

#[test]
fn tcp_manager_never_allocates_a_native_udp_pool() {
    let config: AndroidAgentConfig = serde_json::from_str(MINIMAL_AGENT_CONFIG).unwrap();
    let manager =
        AndroidYamuxSessionManager::new_tcp_direct(Arc::new(config), CancellationToken::new());

    assert_eq!(manager.udp_session_pool_size(), 0);
}

#[test]
fn manager_rejects_cross_protocol_routes() {
    assert_eq!(
        proxy_stream_route(
            TransportMode::Udp,
            TransportProtocol::Tcp,
            TransportProtocol::Udp,
        ),
        None
    );
    assert_eq!(
        proxy_stream_route(
            TransportMode::Udp,
            TransportProtocol::Udp,
            TransportProtocol::Tcp,
        ),
        None
    );
}

#[test]
fn auto_fallback_state_is_isolated_per_udp_session_slot() {
    let config: AndroidAgentConfig = serde_json::from_str(
        r#"{
                "proxy_addrs": ["127.0.0.1:8080"],
                "username": "user1",
                "private_key_pem": "key",
                "transport_mode": "auto"
            }"#,
    )
    .unwrap();
    let manager = AndroidYamuxSessionManager::new_udp(Arc::new(config), CancellationToken::new());

    assert_eq!(manager.udp_fallback_slot_count(), 4);
    manager.set_udp_fallback_to_yamux(2, true);
    assert!(!manager.udp_fallback_to_yamux(1));
    assert!(manager.udp_fallback_to_yamux(2));
    assert!(!manager.udp_fallback_to_yamux(3));
}
