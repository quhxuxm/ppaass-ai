use common::BindInterface;
use desktop_agent_be::tun_handler::direct_egress::{
    select_direct_source_ip, select_initial_direct_bind_interface,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn interface(index: u32) -> BindInterface {
    BindInterface {
        name: None,
        index: Some(index),
    }
}

#[cfg(windows)]
#[test]
fn windows_keeps_the_physical_interface_after_split_default_is_installed() {
    let captured_wifi = interface(21);
    let detected_tun = interface(20);

    assert_eq!(
        select_initial_direct_bind_interface(Some(captured_wifi.clone()), Some(detected_tun)),
        Some(captured_wifi)
    );
}

#[cfg(not(windows))]
#[test]
fn non_windows_prefers_the_detected_default_interface() {
    let captured_proxy_interface = interface(21);
    let detected_default = interface(22);

    assert_eq!(
        select_initial_direct_bind_interface(
            Some(captured_proxy_interface),
            Some(detected_default.clone())
        ),
        Some(detected_default)
    );
}

#[test]
fn captured_source_ip_must_match_the_target_address_family() {
    let ipv4 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    let ipv6 = IpAddr::V6(Ipv6Addr::LOCALHOST);

    assert_eq!(select_direct_source_ip(Some(ipv4), ipv4), Some(ipv4));
    assert_eq!(select_direct_source_ip(Some(ipv4), ipv6), None);
    assert_eq!(select_direct_source_ip(Some(ipv6), ipv4), None);
    assert_eq!(select_direct_source_ip(None, ipv4), None);
}
