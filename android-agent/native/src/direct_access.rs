use protocol::Address;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use tracing::{debug, info};

use crate::android_log;

const FORCE_PROXY_DOMAIN_SUFFIXES: &[&str] = &[
    "google.com",
    "google.cn",
    "googleapis.com",
    "googleapis.cn",
    "googleusercontent.com",
    "gstatic.com",
    "gvt1.com",
    "gvt2.com",
    "youtube.com",
    "youtube-nocookie.com",
    "ytimg.com",
    "googlevideo.com",
    "ggpht.com",
    "xn--ngstr-lra8j.com",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DirectAccessMode {
    #[default]
    ProxyAll,
    DirectAll,
    Rules,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DirectAccessConfig {
    #[serde(default)]
    pub mode: DirectAccessMode,

    #[serde(default)]
    pub rules: Vec<String>,
}

#[derive(Debug)]
enum ParsedRule {
    ExactDomain(String),
    WildcardDomain(String),
    ExactIp(IpAddr),
    CidrV4 { network: u32, mask: u32 },
    CidrV6 { network: u128, mask: u128 },
}

pub struct DirectAccessChecker {
    mode: DirectAccessMode,
    rules: Vec<ParsedRule>,
    proxy_hosts: Vec<String>,
    proxy_ips: Vec<IpAddr>,
}

impl DirectAccessChecker {
    #[cfg(test)]
    pub fn new(config: &DirectAccessConfig) -> Self {
        Self::with_proxy_addrs(config, &[])
    }

    pub fn with_proxy_addrs(config: &DirectAccessConfig, proxy_addrs: &[String]) -> Self {
        let rules: Vec<ParsedRule> = config
            .rules
            .iter()
            .filter_map(|rule| Self::parse_rule(rule))
            .collect();
        let (proxy_hosts, proxy_ips) = Self::parse_proxy_endpoints(proxy_addrs);

        info!(
            "Android direct access checker initialized: mode={:?}, rules={}, proxy_hosts={}, proxy_ips={}",
            config.mode,
            rules.len(),
            proxy_hosts.len(),
            proxy_ips.len()
        );
        android_log::info(format!(
            "Android direct access initialized: mode={:?}, rules={}, proxy_hosts={}, proxy_ips={}",
            config.mode,
            rules.len(),
            proxy_hosts.len(),
            proxy_ips.len()
        ));
        for (i, rule) in rules.iter().enumerate() {
            debug!("Android direct access rule[{i}]: {rule:?}");
        }

        Self {
            mode: config.mode.clone(),
            rules,
            proxy_hosts,
            proxy_ips,
        }
    }

    fn parse_rule(rule: &str) -> Option<ParsedRule> {
        let rule = rule.trim().trim_end_matches('.');
        if rule.is_empty() {
            return None;
        }

        if let Some(slash_pos) = rule.find('/') {
            let ip_str = &rule[..slash_pos];
            let prefix_str = &rule[slash_pos + 1..];
            let prefix_len: u8 = prefix_str.parse().ok()?;

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

        if let Ok(ip) = rule.parse::<IpAddr>() {
            return Some(ParsedRule::ExactIp(ip));
        }

        if let Some(suffix) = rule.strip_prefix("*.") {
            return Some(ParsedRule::WildcardDomain(format!(
                ".{}",
                suffix.to_lowercase()
            )));
        }

        Some(ParsedRule::ExactDomain(rule.to_lowercase()))
    }

    pub fn is_direct(&self, address: &Address) -> bool {
        let result = if self.is_proxy_endpoint(address) {
            true
        } else {
            match self.mode {
                DirectAccessMode::ProxyAll => false,
                DirectAccessMode::DirectAll => true,
                DirectAccessMode::Rules => self.matches_any_rule(address),
            }
        };

        debug!(
            "Android direct access check {:?}: {}",
            address,
            if result { "direct" } else { "proxy" }
        );

        result
    }

    fn is_proxy_endpoint(&self, address: &Address) -> bool {
        match address {
            Address::Domain { host, .. } => {
                let host_lower = Self::normalize_domain(host);
                if self.proxy_hosts.iter().any(|proxy| proxy == &host_lower) {
                    return true;
                }
                host_lower
                    .parse::<IpAddr>()
                    .is_ok_and(|ip| self.proxy_ips.contains(&ip))
            }
            Address::Ipv4 { addr, .. } => {
                self.proxy_ips.contains(&IpAddr::V4(Ipv4Addr::from(*addr)))
            }
            Address::Ipv6 { addr, .. } => {
                self.proxy_ips.contains(&IpAddr::V6(Ipv6Addr::from(*addr)))
            }
            Address::ProxyDns { .. }
            | Address::TcpYamux
            | Address::UdpYamux
            | Address::UdpRelay => false,
        }
    }

    pub fn is_direct_domain(&self, host: &str) -> bool {
        let host_lower = Self::normalize_domain(host);
        match self.mode {
            DirectAccessMode::ProxyAll => false,
            DirectAccessMode::DirectAll => true,
            DirectAccessMode::Rules => {
                !Self::is_force_proxy_domain(&host_lower)
                    && self
                        .rules
                        .iter()
                        .any(|rule| Self::match_domain(rule, &host_lower))
            }
        }
    }

    fn matches_any_rule(&self, address: &Address) -> bool {
        match address {
            Address::Domain { host, .. } => {
                let host_lower = Self::normalize_domain(host);

                if let Ok(ip) = host_lower.parse::<IpAddr>() {
                    return self.rules.iter().any(|rule| Self::match_ip(rule, &ip));
                }

                if Self::is_force_proxy_domain(&host_lower) {
                    return false;
                }

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
            Address::ProxyDns { .. }
            | Address::TcpYamux
            | Address::UdpYamux
            | Address::UdpRelay => false,
        }
    }

    fn match_domain(rule: &ParsedRule, host: &str) -> bool {
        match rule {
            ParsedRule::ExactDomain(domain) => host == domain,
            ParsedRule::WildcardDomain(suffix) => {
                host.ends_with(suffix.as_str()) && host.len() > suffix.len()
            }
            _ => false,
        }
    }

    fn normalize_domain(host: &str) -> String {
        host.trim().trim_end_matches('.').to_lowercase()
    }

    fn parse_proxy_endpoints(proxy_addrs: &[String]) -> (Vec<String>, Vec<IpAddr>) {
        let mut hosts = Vec::new();
        let mut ips = Vec::new();
        for entry in proxy_addrs {
            if let Some(host) = proxy_host(entry) {
                if !hosts.contains(&host) {
                    hosts.push(host);
                }
            }

            let candidate = if entry.contains(':') {
                entry.clone()
            } else {
                format!("{entry}:0")
            };
            match candidate.to_socket_addrs() {
                Ok(iter) => {
                    for socket_addr in iter {
                        let ip = socket_addr.ip();
                        if !ips.contains(&ip) {
                            ips.push(ip);
                        }
                    }
                }
                Err(err) => debug!("Failed to resolve proxy endpoint {entry}: {err}"),
            }
        }
        (hosts, ips)
    }

    fn is_force_proxy_domain(host: &str) -> bool {
        FORCE_PROXY_DOMAIN_SUFFIXES
            .iter()
            .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
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

pub fn address_to_string(address: &Address) -> String {
    match address {
        Address::Domain { host, port } => format!("{host}:{port}"),
        Address::Ipv4 { addr, port } => {
            format!("{}.{}.{}.{}:{}", addr[0], addr[1], addr[2], addr[3], port)
        }
        Address::Ipv6 { addr, port } => {
            let ipv6 = Ipv6Addr::from(*addr);
            format!("[{ipv6}]:{port}")
        }
        Address::ProxyDns { port } => format!("proxy-dns:{port}"),
        Address::TcpYamux => "tcp-yamux".to_string(),
        Address::UdpYamux => "udp-yamux".to_string(),
        Address::UdpRelay => "udp-relay".to_string(),
    }
}

fn proxy_host(entry: &str) -> Option<String> {
    let entry = entry.trim().trim_end_matches('.');
    if entry.is_empty() {
        return None;
    }

    if let Some(rest) = entry.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        return Some(rest[..end].to_lowercase());
    }

    if let Some((host, port)) = entry.rsplit_once(':')
        && port.parse::<u16>().is_ok()
    {
        return Some(host.trim().trim_end_matches('.').to_lowercase());
    }

    Some(entry.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(mode: DirectAccessMode, rules: &[&str]) -> DirectAccessConfig {
        DirectAccessConfig {
            mode,
            rules: rules.iter().map(|rule| rule.to_string()).collect(),
        }
    }

    #[test]
    fn proxy_all_never_matches() {
        let checker =
            DirectAccessChecker::new(&config(DirectAccessMode::ProxyAll, &["10.0.0.0/8"]));
        let address = Address::Ipv4 {
            addr: [10, 1, 2, 3],
            port: 443,
        };

        assert!(!checker.is_direct(&address));
    }

    #[test]
    fn proxy_endpoints_are_direct_even_in_proxy_all_mode() {
        let checker = DirectAccessChecker::with_proxy_addrs(
            &config(DirectAccessMode::ProxyAll, &[]),
            &[
                "140.82.30.214:80".to_string(),
                "proxy.example.com:443".to_string(),
            ],
        );

        assert!(checker.is_direct(&Address::Domain {
            host: "140.82.30.214".to_string(),
            port: 80,
        }));
        assert!(checker.is_direct(&Address::Ipv4 {
            addr: [140, 82, 30, 214],
            port: 443,
        }));
        assert!(checker.is_direct(&Address::Domain {
            host: "proxy.example.com".to_string(),
            port: 80,
        }));
        assert!(!checker.is_direct(&Address::Ipv4 {
            addr: [8, 8, 8, 8],
            port: 53,
        }));
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
    fn google_service_domains_are_forced_proxy_in_rules_mode() {
        let checker =
            DirectAccessChecker::new(&config(DirectAccessMode::Rules, &["*.cn", "*.com"]));

        assert!(!checker.is_direct_domain("services.googleapis.cn"));
        assert!(!checker.is_direct_domain("www.google.com"));
        assert!(!checker.is_direct_domain("rr1---sn-2x3eenel.xn--ngstr-lra8j.com"));
        assert!(!checker.is_direct(&Address::Domain {
            host: "play.googleapis.com".to_string(),
            port: 443,
        }));
        assert!(checker.is_direct_domain("example.cn"));
    }
}
