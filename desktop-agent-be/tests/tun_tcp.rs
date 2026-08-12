use desktop_agent_be::tun_handler::proxy_target_address;
use protocol::Address;

#[test]
fn cached_domain_becomes_primary_proxy_target() {
    assert_eq!(
        proxy_target_address(
            Address::Ipv6 {
                addr: [0; 16],
                port: 443,
            },
            Some("accounts.google.com")
        ),
        Address::Domain {
            host: "accounts.google.com".to_string(),
            port: 443,
        }
    );
}

#[test]
fn missing_cached_domain_keeps_original_proxy_target() {
    let original = Address::Ipv6 {
        addr: [0; 16],
        port: 443,
    };

    assert_eq!(proxy_target_address(original.clone(), None), original);
}

#[test]
fn cached_domain_also_replaces_ipv4_proxy_target() {
    assert_eq!(
        proxy_target_address(
            Address::Ipv4 {
                addr: [127, 0, 0, 1],
                port: 443,
            },
            Some("accounts.google.com")
        ),
        Address::Domain {
            host: "accounts.google.com".to_string(),
            port: 443,
        }
    );
}
