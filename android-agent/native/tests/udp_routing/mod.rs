use android_agent::netstack::{UdpRoute, classify_udp_route};
use common::QuicPolicy;

#[test]
fn ordinary_udp_preserves_direct_and_proxy_routing() {
    assert_eq!(
        classify_udp_route(3478, QuicPolicy::Allow, false),
        UdpRoute::Proxy
    );
    assert_eq!(
        classify_udp_route(3478, QuicPolicy::Allow, true),
        UdpRoute::Direct
    );
}

#[test]
fn quic_allow_routes_udp443_by_direct_access_rules() {
    assert_eq!(
        classify_udp_route(443, QuicPolicy::Allow, false),
        UdpRoute::Proxy
    );
    assert_eq!(
        classify_udp_route(443, QuicPolicy::Allow, true),
        UdpRoute::Direct
    );
}

#[test]
fn explicit_quic_block_overrides_direct_access_routing() {
    for direct_access_match in [false, true] {
        assert_eq!(
            classify_udp_route(443, QuicPolicy::Block, direct_access_match),
            UdpRoute::Block
        );
    }
}
