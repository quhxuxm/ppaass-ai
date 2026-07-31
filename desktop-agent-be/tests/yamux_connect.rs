use common::TransportMode;
use desktop_agent_be::error::AgentError;
use desktop_agent_be::yamux_session::manager::{
    ProxyStreamRoute, is_native_udp_timeout, proxy_stream_route,
};
use protocol::TransportProtocol;

#[test]
fn udp_mode_routes_tcp_direct_and_udp_over_native_udp() {
    assert_eq!(
        proxy_stream_route(
            TransportMode::Udp,
            TransportProtocol::Tcp,
            TransportProtocol::Tcp,
        ),
        ProxyStreamRoute::DirectTcp
    );
    assert_eq!(
        proxy_stream_route(
            TransportMode::Udp,
            TransportProtocol::Udp,
            TransportProtocol::Udp,
        ),
        ProxyStreamRoute::NativeUdp
    );
}

#[test]
fn tcp_mode_routes_tcp_direct_and_udp_over_yamux() {
    assert_eq!(
        proxy_stream_route(
            TransportMode::Tcp,
            TransportProtocol::Tcp,
            TransportProtocol::Tcp,
        ),
        ProxyStreamRoute::DirectTcp
    );
    assert_eq!(
        proxy_stream_route(
            TransportMode::Tcp,
            TransportProtocol::Udp,
            TransportProtocol::Udp,
        ),
        ProxyStreamRoute::Yamux
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
        ProxyStreamRoute::Auto
    );
    assert!(is_native_udp_timeout(&AgentError::Connection(
        "原生 UDP 认证响应超时".into()
    )));
    assert!(!is_native_udp_timeout(&AgentError::Connection(
        "authentication failed".into()
    )));
}

#[test]
fn mismatched_manager_is_rejected_before_transport_selection() {
    assert_eq!(
        proxy_stream_route(
            TransportMode::Udp,
            TransportProtocol::Tcp,
            TransportProtocol::Udp,
        ),
        ProxyStreamRoute::InvalidManager
    );
    assert_eq!(
        proxy_stream_route(
            TransportMode::Udp,
            TransportProtocol::Udp,
            TransportProtocol::Tcp,
        ),
        ProxyStreamRoute::InvalidManager
    );
}
