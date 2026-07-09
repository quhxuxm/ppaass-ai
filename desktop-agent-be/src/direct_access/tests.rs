use super::*;

#[test]
fn test_proxy_all_mode() {
    let config = DirectAccessConfig {
        mode: DirectAccessMode::ProxyAll,
        rules: vec!["localhost".to_string()],
    };
    let checker = DirectAccessChecker::new(&config);
    let addr = Address::Domain {
        host: "localhost".to_string(),
        port: 80,
    };
    assert!(!checker.is_direct(&addr));
}

#[test]
fn test_direct_all_mode() {
    let config = DirectAccessConfig {
        mode: DirectAccessMode::DirectAll,
        rules: vec![],
    };
    let checker = DirectAccessChecker::new(&config);
    let addr = Address::Domain {
        host: "example.com".to_string(),
        port: 80,
    };
    assert!(checker.is_direct(&addr));
}

#[test]
fn test_exact_domain_match() {
    let config = DirectAccessConfig {
        mode: DirectAccessMode::Rules,
        rules: vec!["localhost".to_string(), "example.com".to_string()],
    };
    let checker = DirectAccessChecker::new(&config);

    assert!(checker.is_direct(&Address::Domain {
        host: "localhost".to_string(),
        port: 80,
    }));
    assert!(checker.is_direct(&Address::Domain {
        host: "example.com".to_string(),
        port: 443,
    }));
    assert!(!checker.is_direct(&Address::Domain {
        host: "google.com".to_string(),
        port: 80,
    }));
}

#[test]
fn test_wildcard_domain_match() {
    let config = DirectAccessConfig {
        mode: DirectAccessMode::Rules,
        rules: vec!["*.local".to_string(), "*.example.com".to_string()],
    };
    let checker = DirectAccessChecker::new(&config);

    assert!(checker.is_direct(&Address::Domain {
        host: "myhost.local".to_string(),
        port: 80,
    }));
    // "*.local" 不匹配 "local" 本身，只匹配子域名
    assert!(!checker.is_direct(&Address::Domain {
        host: "local".to_string(),
        port: 80,
    }));
    assert!(checker.is_direct(&Address::Domain {
        host: "sub.example.com".to_string(),
        port: 80,
    }));
    // "*.example.com" 不匹配 "example.com" 本身
    assert!(!checker.is_direct(&Address::Domain {
        host: "example.com".to_string(),
        port: 80,
    }));
    assert!(!checker.is_direct(&Address::Domain {
        host: "google.com".to_string(),
        port: 80,
    }));
}

#[test]
fn test_exact_ip_match() {
    let config = DirectAccessConfig {
        mode: DirectAccessMode::Rules,
        rules: vec!["127.0.0.1".to_string(), "::1".to_string()],
    };
    let checker = DirectAccessChecker::new(&config);

    assert!(checker.is_direct(&Address::Ipv4 {
        addr: [127, 0, 0, 1],
        port: 80,
    }));
    assert!(!checker.is_direct(&Address::Ipv4 {
        addr: [192, 168, 1, 1],
        port: 80,
    }));

    let mut ipv6_loopback = [0u8; 16];
    ipv6_loopback[15] = 1;
    assert!(checker.is_direct(&Address::Ipv6 {
        addr: ipv6_loopback,
        port: 80,
    }));
}

#[test]
fn test_has_domain_direct_rules_only_when_rules_can_match_domain() {
    let proxy_all = DirectAccessChecker::new(&DirectAccessConfig {
        mode: DirectAccessMode::ProxyAll,
        rules: vec!["example.com".to_string()],
    });
    assert!(!proxy_all.has_domain_direct_rules());

    let ip_only_rules = DirectAccessChecker::new(&DirectAccessConfig {
        mode: DirectAccessMode::Rules,
        rules: vec!["10.0.0.0/8".to_string(), "127.0.0.1".to_string()],
    });
    assert!(!ip_only_rules.has_domain_direct_rules());

    let domain_rules = DirectAccessChecker::new(&DirectAccessConfig {
        mode: DirectAccessMode::Rules,
        rules: vec!["*.example.com".to_string()],
    });
    assert!(domain_rules.has_domain_direct_rules());
}

#[test]
fn test_cidr_v4_match() {
    let config = DirectAccessConfig {
        mode: DirectAccessMode::Rules,
        rules: vec![
            "10.0.0.0/8".to_string(),
            "192.168.0.0/16".to_string(),
            "172.16.0.0/12".to_string(),
        ],
    };
    let checker = DirectAccessChecker::new(&config);

    assert!(checker.is_direct(&Address::Ipv4 {
        addr: [10, 1, 2, 3],
        port: 80,
    }));
    assert!(checker.is_direct(&Address::Ipv4 {
        addr: [10, 255, 255, 255],
        port: 80,
    }));
    assert!(checker.is_direct(&Address::Ipv4 {
        addr: [192, 168, 1, 100],
        port: 80,
    }));
    assert!(checker.is_direct(&Address::Ipv4 {
        addr: [172, 20, 0, 1],
        port: 80,
    }));
    assert!(!checker.is_direct(&Address::Ipv4 {
        addr: [8, 8, 8, 8],
        port: 80,
    }));
    assert!(!checker.is_direct(&Address::Ipv4 {
        addr: [172, 32, 0, 1],
        port: 80,
    }));
}

#[test]
fn test_domain_with_ip_string() {
    let config = DirectAccessConfig {
        mode: DirectAccessMode::Rules,
        rules: vec!["10.0.0.0/8".to_string()],
    };
    let checker = DirectAccessChecker::new(&config);

    // 实际为 IP 字符串的域名应匹配 CIDR 规则
    assert!(checker.is_direct(&Address::Domain {
        host: "10.1.2.3".to_string(),
        port: 80,
    }));
    assert!(!checker.is_direct(&Address::Domain {
        host: "8.8.8.8".to_string(),
        port: 80,
    }));
}

#[test]
fn test_mixed_rules() {
    let config = DirectAccessConfig {
        mode: DirectAccessMode::Rules,
        rules: vec![
            "localhost".to_string(),
            "*.local".to_string(),
            "127.0.0.0/8".to_string(),
            "10.0.0.0/8".to_string(),
            "192.168.0.0/16".to_string(),
            "::1".to_string(),
        ],
    };
    let checker = DirectAccessChecker::new(&config);

    // 域名匹配
    assert!(checker.is_direct(&Address::Domain {
        host: "localhost".to_string(),
        port: 80,
    }));
    assert!(checker.is_direct(&Address::Domain {
        host: "mypc.local".to_string(),
        port: 80,
    }));
    // IP 匹配
    assert!(checker.is_direct(&Address::Ipv4 {
        addr: [127, 0, 0, 1],
        port: 80,
    }));
    assert!(checker.is_direct(&Address::Ipv4 {
        addr: [10, 0, 0, 1],
        port: 80,
    }));
    assert!(checker.is_direct(&Address::Ipv4 {
        addr: [192, 168, 1, 1],
        port: 80,
    }));
    // 应通过代理访问
    assert!(!checker.is_direct(&Address::Domain {
        host: "google.com".to_string(),
        port: 443,
    }));
    assert!(!checker.is_direct(&Address::Ipv4 {
        addr: [8, 8, 8, 8],
        port: 53,
    }));
}

#[test]
fn test_google_service_domains_are_forced_proxy_in_rules_mode() {
    let config = DirectAccessConfig {
        mode: DirectAccessMode::Rules,
        rules: vec!["*.cn".to_string(), "*.com".to_string()],
    };
    let checker = DirectAccessChecker::new(&config);

    assert!(!checker.is_direct_domain("services.googleapis.cn"));
    assert!(!checker.is_direct_domain("www.google.com"));
    assert!(!checker.is_direct_domain("rr1---sn-2x3eenel.xn--ngstr-lra8j.com"));
    assert!(!checker.is_direct(&Address::Domain {
        host: "play.googleapis.com".to_string(),
        port: 443,
    }));
    assert!(checker.is_direct_domain("example.cn"));
}

#[test]
fn test_case_insensitive_domain() {
    let config = DirectAccessConfig {
        mode: DirectAccessMode::Rules,
        rules: vec!["LocalHost".to_string(), "*.Example.COM".to_string()],
    };
    let checker = DirectAccessChecker::new(&config);

    assert!(checker.is_direct(&Address::Domain {
        host: "LOCALHOST".to_string(),
        port: 80,
    }));
    assert!(checker.is_direct(&Address::Domain {
        host: "sub.example.com".to_string(),
        port: 80,
    }));
}

#[test]
fn test_address_to_string() {
    assert_eq!(
        address_to_string(&Address::Domain {
            host: "example.com".to_string(),
            port: 443,
        }),
        "example.com:443"
    );
    assert_eq!(
        address_to_string(&Address::Ipv4 {
            addr: [192, 168, 1, 1],
            port: 80,
        }),
        "192.168.1.1:80"
    );
    assert_eq!(
        address_to_string(&Address::Ipv6 {
            addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            port: 443,
        }),
        "[::1]:443"
    );
}

#[test]
fn test_empty_rules() {
    let config = DirectAccessConfig {
        mode: DirectAccessMode::Rules,
        rules: vec![],
    };
    let checker = DirectAccessChecker::new(&config);

    // 规则模式下没有规则时，任何地址都不应直连
    assert!(!checker.is_direct(&Address::Domain {
        host: "localhost".to_string(),
        port: 80,
    }));
}

#[test]
fn test_invalid_rules_ignored() {
    let config = DirectAccessConfig {
        mode: DirectAccessMode::Rules,
        rules: vec![
            "".to_string(),
            "10.0.0.0/99".to_string(), // 无效前缀
            "localhost".to_string(),   // 有效规则
        ],
    };
    let checker = DirectAccessChecker::new(&config);

    // 只有有效规则应生效
    assert!(checker.is_direct(&Address::Domain {
        host: "localhost".to_string(),
        port: 80,
    }));
}
