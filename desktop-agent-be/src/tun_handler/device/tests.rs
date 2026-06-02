#[cfg(target_os = "macos")]
use super::tun_ipv4_destination;
#[cfg(target_os = "macos")]
use super::tun_ipv4_interface_prefix;
#[cfg(target_os = "macos")]
use std::net::Ipv4Addr;

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
