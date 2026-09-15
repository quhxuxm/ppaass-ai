use desktop_agent_be::tun_handler::route::ipv4_networks_overlap;
use std::net::Ipv4Addr;

#[test]
fn detects_vmware_network_overlapping_the_legacy_tun_subnet() {
    assert!(ipv4_networks_overlap(
        Ipv4Addr::new(10, 10, 10, 1),
        24,
        Ipv4Addr::new(10, 10, 10, 254),
        24,
    ));
}

#[test]
fn accepts_the_new_tun_default_beside_common_vmware_subnets() {
    let tun_ip = Ipv4Addr::new(198, 18, 0, 1);

    for vmware_ip in [
        Ipv4Addr::new(10, 10, 10, 1),
        Ipv4Addr::new(172, 16, 20, 1),
        Ipv4Addr::new(192, 168, 126, 1),
    ] {
        assert!(!ipv4_networks_overlap(tun_ip, 15, vmware_ip, 24));
    }
}

#[test]
fn detects_overlap_when_a_virtual_network_contains_the_tun_network() {
    assert!(ipv4_networks_overlap(
        Ipv4Addr::new(198, 18, 0, 1),
        15,
        Ipv4Addr::new(198, 18, 1, 1),
        24,
    ));
}
