use android_agent::netstack::{proxy_target_address, should_prefetch_tls_sni};
use protocol::Address;

#[test]
fn cached_domain_replaces_android_ipv4_proxy_target() {
    assert_eq!(
        proxy_target_address(
            Address::Ipv4 {
                addr: [203, 0, 113, 7],
                port: 443,
            },
            Some("chatgpt.com"),
        ),
        Address::Domain {
            host: "chatgpt.com".to_string(),
            port: 443,
        }
    );
}

#[test]
fn android_prefetches_sni_only_for_ip_tls_targets() {
    assert!(should_prefetch_tls_sni(&Address::Ipv4 {
        addr: [203, 0, 113, 7],
        port: 443,
    }));
    assert!(should_prefetch_tls_sni(&Address::Ipv6 {
        addr: [0; 16],
        port: 443,
    }));
    assert!(!should_prefetch_tls_sni(&Address::Ipv4 {
        addr: [203, 0, 113, 7],
        port: 80,
    }));
    assert!(!should_prefetch_tls_sni(&Address::Domain {
        host: "chatgpt.com".to_string(),
        port: 443,
    }));
}

#[test]
fn missing_domain_keeps_android_proxy_ip() {
    let original = Address::Ipv6 {
        addr: [0; 16],
        port: 443,
    };
    assert_eq!(proxy_target_address(original.clone(), None), original);
}
