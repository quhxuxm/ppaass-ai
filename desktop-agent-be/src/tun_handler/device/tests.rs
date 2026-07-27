#[cfg(target_os = "macos")]
use super::tun_ipv4_destination;
#[cfg(target_os = "macos")]
use super::tun_ipv4_interface_prefix;
use super::tun_ipv4_peer;
use std::net::Ipv4Addr;

#[test]
fn tun_ipv4_peer_uses_sibling_address_for_default_subnet() {
    assert_eq!(
        tun_ipv4_peer(Ipv4Addr::new(10, 10, 10, 1), 24),
        Some(Ipv4Addr::new(10, 10, 10, 2))
    );
}

#[test]
fn tun_ipv4_peer_can_use_first_host_when_adapter_uses_second_host() {
    assert_eq!(
        tun_ipv4_peer(Ipv4Addr::new(10, 10, 10, 2), 24),
        Some(Ipv4Addr::new(10, 10, 10, 1))
    );
}

#[test]
fn tun_ipv4_peer_rejects_point_to_point_subnets() {
    assert_eq!(tun_ipv4_peer(Ipv4Addr::new(10, 10, 10, 1), 31), None);
    assert_eq!(tun_ipv4_peer(Ipv4Addr::new(10, 10, 10, 1), 32), None);
}

#[cfg(target_os = "macos")]
#[test]
fn macos_tun_destination_uses_virtual_peer() {
    assert_eq!(
        tun_ipv4_destination(Ipv4Addr::new(10, 10, 10, 1), 24),
        Some(Ipv4Addr::new(10, 10, 10, 2))
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_tun_interface_uses_host_prefix() {
    assert_eq!(tun_ipv4_interface_prefix(24), 32);
}
