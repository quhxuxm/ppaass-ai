use desktop_agent_be::tun_handler::network::{
    TunNetworks, is_tun_local_udp_target, reject_tun_target,
};
use std::net::Ipv4Addr;

#[test]
fn tun_local_udp_target_matches_source_and_target_inside_tun_network() {
    let networks = TunNetworks::new(Ipv4Addr::new(10, 10, 10, 1), 24, None);
    let source = "10.10.10.1:137".parse().unwrap();
    let target = "10.10.10.1:137".parse().unwrap();

    assert!(is_tun_local_udp_target(source, target, networks));
}

#[test]
fn reversed_external_to_tun_target_is_not_local_udp_noise() {
    let networks = TunNetworks::new(Ipv4Addr::new(10, 10, 10, 1), 24, None);
    let source = "8.8.8.8:443".parse().unwrap();
    let target = "10.10.10.1:443".parse().unwrap();

    assert!(!is_tun_local_udp_target(source, target, networks));
    assert!(reject_tun_target("UDP", source, target, networks).is_err());
}
