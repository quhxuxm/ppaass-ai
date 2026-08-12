use desktop_agent_be::tun_handler::proxy_fallback_address;
use protocol::Address;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

#[test]
fn cached_domain_fallback_preserves_target_port() {
    let target = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 443);

    assert_eq!(
        proxy_fallback_address(target, Some("accounts.google.com")),
        Some(Address::Domain {
            host: "accounts.google.com".to_string(),
            port: 443,
        })
    );
}

#[test]
fn missing_cached_domain_has_no_fallback() {
    let target = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 443);

    assert_eq!(proxy_fallback_address(target, None), None);
}

#[test]
fn ipv4_target_keeps_original_proxy_address() {
    let target = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 443);

    assert_eq!(
        proxy_fallback_address(target, Some("accounts.google.com")),
        None
    );
}
