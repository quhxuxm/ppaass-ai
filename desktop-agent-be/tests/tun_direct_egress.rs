use common::BindInterface;
use desktop_agent_be::tun_handler::direct_egress::select_initial_direct_bind_interface;

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
