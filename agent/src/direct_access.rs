use protocol::Address;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::{debug, info};

/// Mode for determining whether to access targets directly or through proxy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DirectAccessMode {
    /// All traffic goes through proxy (default, existing behavior)
    ProxyAll,
    /// All traffic is accessed directly (bypass proxy completely)
    DirectAll,
    /// Use rules to determine direct vs proxy access
    Rules,
}

impl Default for DirectAccessMode {
    fn default() -> Self {
        Self::ProxyAll
    }
}

/// Configuration for direct access rules
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DirectAccessConfig {
    /// Access mode: proxy_all, direct_all, or rules
    #[serde(default)]
    pub mode: DirectAccessMode,

    /// List of rules for direct access (used when mode = "rules")
    ///
    /// Supported formats:
    /// - Exact domain: "localhost", "example.com"
    /// - Wildcard domain: "*.local", "*.example.com"
    /// - Exact IP: "127.0.0.1", "::1"
    /// - CIDR range: "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"
    #[serde(default)]
    pub rules: Vec<String>,
}

/// A parsed rule for efficient matching at runtime
#[derive(Debug)]
enum ParsedRule {
    /// Exact domain match: "localhost", "example.com"
    ExactDomain(String),
    /// Wildcard domain suffix: "*.local" -> ".local"
    WildcardDomain(String),
    /// Exact IP address match
    ExactIp(IpAddr),
    /// IPv4 CIDR range
    CidrV4 { network: u32, mask: u32 },
    /// IPv6 CIDR range
    CidrV6 { network: u128, mask: u128 },
}

/// Checker that determines whether a target address should be accessed directly
/// (bypassing the proxy) or through the proxy tunnel.
pub struct DirectAccessChecker {
    mode: DirectAccessMode,
    rules: Vec<ParsedRule>,
}

impl DirectAccessChecker {
    /// Create a new checker from configuration.
    /// Rules are parsed once at construction time for efficient matching.
    pub fn new(config: &DirectAccessConfig) -> Self {
        let rules: Vec<ParsedRule> = config
            .rules
            .iter()
            .filter_map(|rule| Self::parse_rule(rule))
            .collect();

        info!(
            "DirectAccessChecker initialized: mode={:?}, {} rules loaded",
            config.mode,
            rules.len()
        );
        for (i, rule) in rules.iter().enumerate() {
            debug!("  Rule[{}]: {:?}", i, rule);
        }

        Self {
            mode: config.mode.clone(),
            rules,
        }
    }

    /// Parse a rule string into a typed ParsedRule
    fn parse_rule(rule: &str) -> Option<ParsedRule> {
        let rule = rule.trim();
        if rule.is_empty() {
            return None;
        }

        // Try CIDR notation (contains '/')
        if let Some(slash_pos) = rule.find('/') {
            let ip_str = &rule[..slash_pos];
            let prefix_str = &rule[slash_pos + 1..];
            let prefix_len: u8 = match prefix_str.parse() {
                Ok(v) => v,
                Err(_) => return None,
            };

            if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                if prefix_len > 32 {
                    return None;
                }
                let network = u32::from(ip);
                let mask = if prefix_len == 0 {
                    0
                } else {
                    !0u32 << (32 - prefix_len)
                };
                return Some(ParsedRule::CidrV4 {
                    network: network & mask,
                    mask,
                });
            }

            if let Ok(ip) = ip_str.parse::<Ipv6Addr>() {
                if prefix_len > 128 {
                    return None;
                }
                let network = u128::from(ip);
                let mask = if prefix_len == 0 {
                    0
                } else {
                    !0u128 << (128 - prefix_len)
                };
                return Some(ParsedRule::CidrV6 {
                    network: network & mask,
                    mask,
                });
            }

            return None;
        }

        // Try exact IP address
        if let Ok(ip) = rule.parse::<IpAddr>() {
            return Some(ParsedRule::ExactIp(ip));
        }

        // Wildcard domain: "*.example.com"
        if let Some(suffix) = rule.strip_prefix("*.") {
            // Store as ".example.com" for suffix matching
            return Some(ParsedRule::WildcardDomain(format!(".{}", suffix.to_lowercase())));
        }

        // Exact domain
        Some(ParsedRule::ExactDomain(rule.to_lowercase()))
    }

    /// Check if the given address should be accessed directly (bypassing proxy).
    /// Returns `true` for direct access, `false` for proxy access.
    pub fn is_direct(&self, address: &Address) -> bool {
        let result = match self.mode {
            DirectAccessMode::ProxyAll => false,
            DirectAccessMode::DirectAll => true,
            DirectAccessMode::Rules => self.matches_any_rule(address),
        };

        debug!(
            "Direct access check for {:?}: {}",
            address,
            if result { "DIRECT" } else { "PROXY" }
        );

        result
    }

    /// Check if the address matches any of the configured rules
    fn matches_any_rule(&self, address: &Address) -> bool {
        match address {
            Address::Domain { host, .. } => {
                let host_lower = host.to_lowercase();

                // First, try to parse the domain as an IP address
                // (sometimes domains are passed as IP strings like "10.0.0.1")
                if let Ok(ip) = host_lower.parse::<IpAddr>() {
                    return self.rules.iter().any(|rule| Self::match_ip(rule, &ip));
                }

                // Match against domain rules
                self.rules
                    .iter()
                    .any(|rule| Self::match_domain(rule, &host_lower))
            }
            Address::Ipv4 { addr, .. } => {
                let ip = IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]));
                self.rules.iter().any(|rule| Self::match_ip(rule, &ip))
            }
            Address::Ipv6 { addr, .. } => {
                let ip = IpAddr::V6(Ipv6Addr::from(*addr));
                self.rules.iter().any(|rule| Self::match_ip(rule, &ip))
            }
        }
    }

    fn match_domain(rule: &ParsedRule, host: &str) -> bool {
        match rule {
            ParsedRule::ExactDomain(domain) => host == domain,
            ParsedRule::WildcardDomain(suffix) => {
                // "*.example.com" (suffix=".example.com") matches "sub.example.com"
                // but NOT "example.com" itself. This follows standard wildcard convention.
                host.ends_with(suffix.as_str()) && host.len() > suffix.len()
            }
            _ => false,
        }
    }

    fn match_ip(rule: &ParsedRule, ip: &IpAddr) -> bool {
        match (rule, ip) {
            (ParsedRule::ExactIp(rule_ip), ip) => rule_ip == ip,
            (ParsedRule::CidrV4 { network, mask }, IpAddr::V4(v4)) => {
                let ip_u32 = u32::from(*v4);
                (ip_u32 & mask) == *network
            }
            (ParsedRule::CidrV6 { network, mask }, IpAddr::V6(v6)) => {
                let ip_u128 = u128::from(*v6);
                (ip_u128 & mask) == *network
            }
            _ => false,
        }
    }
}

/// Convert a protocol Address to a connectable address string
/// suitable for TcpStream::connect() or UdpSocket::connect()
pub fn address_to_string(address: &Address) -> String {
    match address {
        Address::Domain { host, port } => format!("{}:{}", host, port),
        Address::Ipv4 { addr, port } => {
            format!("{}.{}.{}.{}:{}", addr[0], addr[1], addr[2], addr[3], port)
        }
        Address::Ipv6 { addr, port } => {
            let ipv6 = Ipv6Addr::from(*addr);
            format!("[{}]:{}", ipv6, port)
        }
    }
}

#[cfg(test)]
mod tests {
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
        // "*.local" does NOT match "local" itself, only subdomains
        assert!(!checker.is_direct(&Address::Domain {
            host: "local".to_string(),
            port: 80,
        }));
        assert!(checker.is_direct(&Address::Domain {
            host: "sub.example.com".to_string(),
            port: 80,
        }));
        // "*.example.com" does NOT match "example.com" itself
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

        // Domain that is actually an IP string should match CIDR rules
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

        // Domain matches
        assert!(checker.is_direct(&Address::Domain {
            host: "localhost".to_string(),
            port: 80,
        }));
        assert!(checker.is_direct(&Address::Domain {
            host: "mypc.local".to_string(),
            port: 80,
        }));
        // IP matches
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
        // Should go through proxy
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

        // With no rules in Rules mode, nothing should be direct
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
                "10.0.0.0/99".to_string(), // invalid prefix
                "localhost".to_string(),    // valid
            ],
        };
        let checker = DirectAccessChecker::new(&config);

        // Only the valid rule should work
        assert!(checker.is_direct(&Address::Domain {
            host: "localhost".to_string(),
            port: 80,
        }));
    }
}



