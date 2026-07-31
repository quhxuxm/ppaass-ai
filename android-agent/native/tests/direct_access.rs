use std::net::Ipv6Addr;

use android_agent::{DirectAccessChecker, DirectAccessConfig, DirectAccessMode};
use protocol::Address;

fn config(mode: DirectAccessMode, rules: &[&str]) -> DirectAccessConfig {
    DirectAccessConfig {
        mode,
        rules: rules.iter().map(|rule| rule.to_string()).collect(),
    }
}

#[test]
fn proxy_all_never_matches() {
    let checker = DirectAccessChecker::new(&config(DirectAccessMode::ProxyAll, &["10.0.0.0/8"]));
    let address = Address::Ipv4 {
        addr: [10, 1, 2, 3],
        port: 443,
    };

    assert!(!checker.is_direct(&address));
}

#[test]
fn direct_all_matches_regular_targets() {
    let checker = DirectAccessChecker::new(&config(DirectAccessMode::DirectAll, &[]));
    let address = Address::Domain {
        host: "example.com".to_string(),
        port: 443,
    };

    assert!(checker.is_direct(&address));
}

#[test]
fn rules_match_domains_wildcards_ips_and_cidrs() {
    let checker = DirectAccessChecker::new(&config(
        DirectAccessMode::Rules,
        &["example.com", "*.local", "127.0.0.1", "10.0.0.0/8", "::1"],
    ));

    assert!(checker.is_direct(&Address::Domain {
        host: "example.com".to_string(),
        port: 443,
    }));
    assert!(checker.is_direct(&Address::Domain {
        host: "printer.local".to_string(),
        port: 443,
    }));
    assert!(!checker.is_direct(&Address::Domain {
        host: "local".to_string(),
        port: 443,
    }));
    assert!(checker.is_direct(&Address::Ipv4 {
        addr: [127, 0, 0, 1],
        port: 80,
    }));
    assert!(checker.is_direct(&Address::Ipv4 {
        addr: [10, 12, 34, 56],
        port: 80,
    }));
    assert!(checker.is_direct(&Address::Ipv6 {
        addr: Ipv6Addr::LOCALHOST.octets(),
        port: 80,
    }));
}

#[test]
fn domain_only_checks_ignore_ip_rules() {
    let checker = DirectAccessChecker::new(&config(
        DirectAccessMode::Rules,
        &["*.example.com", "10.0.0.0/8"],
    ));

    assert!(checker.is_direct_domain("www.example.com"));
    assert!(!checker.is_direct_domain("10.1.2.3"));
}

#[test]
fn domain_direct_rule_presence_ignores_proxy_all_and_ip_only_rules() {
    let proxy_all = DirectAccessChecker::new(&config(DirectAccessMode::ProxyAll, &["example.com"]));
    assert!(!proxy_all.has_domain_direct_rules());

    let ip_only = DirectAccessChecker::new(&config(DirectAccessMode::Rules, &["10.0.0.0/8"]));
    assert!(!ip_only.has_domain_direct_rules());

    let domain_rule =
        DirectAccessChecker::new(&config(DirectAccessMode::Rules, &["*.example.com"]));
    assert!(domain_rule.has_domain_direct_rules());
}

#[test]
fn google_service_domains_are_forced_proxy_in_rules_mode() {
    let checker = DirectAccessChecker::new(&config(DirectAccessMode::Rules, &["*.cn", "*.com"]));

    assert!(!checker.is_direct_domain("services.googleapis.cn"));
    assert!(!checker.is_direct_domain("www.google.com"));
    assert!(!checker.is_direct_domain("rr1---sn-2x3eenel.xn--ngstr-lra8j.com"));
    assert!(!checker.is_direct(&Address::Domain {
        host: "play.googleapis.com".to_string(),
        port: 443,
    }));
    assert!(checker.is_direct_domain("example.cn"));
}
