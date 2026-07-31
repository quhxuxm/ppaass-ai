use common::QuicPolicy;
use desktop_agent_be::tun_handler::tasks::{
    UdpRoute, classify_udp_route, should_consult_udp_domain_cache, should_start_udp_relay,
    tun_packet_is_safe_for_netstack,
};

fn ipv4_packet(protocol: u8, payload: &[u8]) -> Vec<u8> {
    let total_len = 20 + payload.len();
    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
    packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
    packet[20..].copy_from_slice(payload);
    packet
}

fn udp_payload(data: &[u8], declared_len: Option<u16>) -> Vec<u8> {
    let mut payload = vec![0_u8; 8 + data.len()];
    let udp_len = declared_len.unwrap_or(payload.len() as u16);
    payload[0..2].copy_from_slice(&50_000_u16.to_be_bytes());
    payload[2..4].copy_from_slice(&443_u16.to_be_bytes());
    payload[4..6].copy_from_slice(&udp_len.to_be_bytes());
    payload[8..].copy_from_slice(data);
    payload
}

#[test]
fn tun_packet_guard_keeps_valid_udp_and_tcp() {
    assert!(tun_packet_is_safe_for_netstack(&ipv4_packet(
        17,
        &udp_payload(b"media", None),
    )));
    assert!(tun_packet_is_safe_for_netstack(&ipv4_packet(
        6,
        b"tcp payload",
    )));
}

#[test]
fn tun_packet_guard_drops_fragments_and_invalid_udp_lengths() {
    let mut fragment = ipv4_packet(17, b"fragment bytes");
    fragment[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
    assert!(!tun_packet_is_safe_for_netstack(&fragment));

    let invalid_udp = ipv4_packet(17, &udp_payload(b"short", Some(400)));
    assert!(!tun_packet_is_safe_for_netstack(&invalid_udp));
}

#[test]
fn ordinary_udp_proxy_switch_preserves_old_routing_or_forces_direct() {
    assert_eq!(
        classify_udp_route(3478, QuicPolicy::Allow, true, false),
        UdpRoute::Proxy
    );
    assert_eq!(
        classify_udp_route(3478, QuicPolicy::Allow, true, true),
        UdpRoute::Direct
    );
    assert_eq!(
        classify_udp_route(3478, QuicPolicy::Allow, false, false),
        UdpRoute::Direct
    );
    assert_eq!(
        classify_udp_route(3478, QuicPolicy::Block, false, true),
        UdpRoute::Direct
    );
}

#[test]
fn quic_allow_routes_direct_matches_direct_and_other_targets_to_proxy() {
    assert_eq!(
        classify_udp_route(443, QuicPolicy::Allow, false, false),
        UdpRoute::Proxy
    );
    assert_eq!(
        classify_udp_route(443, QuicPolicy::Allow, false, true),
        UdpRoute::Direct
    );
    assert_eq!(
        classify_udp_route(443, QuicPolicy::Allow, true, false),
        UdpRoute::Proxy
    );
}

#[test]
fn explicit_quic_block_overrides_udp_and_direct_access_routing() {
    for proxy_udp in [false, true] {
        for direct_access_match in [false, true] {
            assert_eq!(
                classify_udp_route(443, QuicPolicy::Block, proxy_udp, direct_access_match,),
                UdpRoute::Block
            );
        }
    }
}

#[test]
fn relay_and_domain_cache_stay_available_for_quic() {
    assert!(should_start_udp_relay(false, QuicPolicy::Allow));
    assert!(!should_start_udp_relay(false, QuicPolicy::Block));
    assert!(should_start_udp_relay(true, QuicPolicy::Block));

    assert!(should_consult_udp_domain_cache(false, 443));
    assert!(!should_consult_udp_domain_cache(false, 3478));
    assert!(should_consult_udp_domain_cache(true, 3478));
}
