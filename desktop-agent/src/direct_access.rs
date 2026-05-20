use protocol::Address;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::{debug, info};

/// 确定是直连目标还是通过代理访问的模式
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DirectAccessMode {
    /// 所有流量通过代理（默认，现有行为）
    #[default]
    ProxyAll,
    /// 所有流量直连（完全绕过代理）
    DirectAll,
    /// 使用规则确定直连还是代理访问
    Rules,
}

/// 直连访问规则配置
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DirectAccessConfig {
    /// 访问模式: proxy_all、direct_all 或 rules
    #[serde(default)]
    pub mode: DirectAccessMode,

    /// 直连访问规则列表（当 mode = "rules" 时使用）
    ///
    /// 支持的格式:
    /// - 精确域名: "localhost"、"example.com"
    /// - 通配符域名: "*.local"、"*.example.com"
    /// - 精确 IP: "127.0.0.1"、"::1"
    /// - CIDR 范围: "10.0.0.0/8"、"192.168.0.0/16"、"172.16.0.0/12"
    #[serde(default)]
    pub rules: Vec<String>,
}

/// 运行时高效匹配的已解析规则
#[derive(Debug)]
enum ParsedRule {
    /// 精确域名匹配: "localhost"、"example.com"
    ExactDomain(String),
    /// 通配符域名后缀: "*.local" -> ".local"
    WildcardDomain(String),
    /// 精确 IP 地址匹配
    ExactIp(IpAddr),
    /// IPv4 CIDR 范围
    CidrV4 { network: u32, mask: u32 },
    /// IPv6 CIDR 范围
    CidrV6 { network: u128, mask: u128 },
}

/// 检查器，用于确定目标地址应该直连（绕过代理）还是通过代理隧道访问
pub struct DirectAccessChecker {
    mode: DirectAccessMode,
    rules: Vec<ParsedRule>,
}

impl DirectAccessChecker {
    /// 从配置创建新的检查器。
    /// 规则在构造时一次性解析，以实现高效匹配。
    pub fn new(config: &DirectAccessConfig) -> Self {
        // 无效规则会被跳过，避免一个坏规则让整个 agent 无法启动。
        let rules: Vec<ParsedRule> = config
            .rules
            .iter()
            .filter_map(|rule| Self::parse_rule(rule))
            .collect();

        info!(
            "直连访问检查器已初始化: 模式={:?}, 已加载 {} 条规则",
            config.mode,
            rules.len()
        );
        for (i, rule) in rules.iter().enumerate() {
            debug!("  规则[{}]: {:?}", i, rule);
        }

        Self {
            mode: config.mode.clone(),
            rules,
        }
    }

    /// 将规则字符串解析为类型化的 ParsedRule
    fn parse_rule(rule: &str) -> Option<ParsedRule> {
        let rule = rule.trim();
        if rule.is_empty() {
            return None;
        }

        // 尝试 CIDR 表示法（包含 '/'）
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

        // 尝试精确 IP 地址
        if let Ok(ip) = rule.parse::<IpAddr>() {
            return Some(ParsedRule::ExactIp(ip));
        }

        // 通配符域名: "*.example.com"
        if let Some(suffix) = rule.strip_prefix("*.") {
            // 存储为 ".example.com" 用于后缀匹配
            return Some(ParsedRule::WildcardDomain(format!(
                ".{}",
                suffix.to_lowercase()
            )));
        }

        // 精确域名
        Some(ParsedRule::ExactDomain(rule.to_lowercase()))
    }

    /// 检查给定地址是否应该直连（绕过代理）。
    /// 直连返回 `true`，代理访问返回 `false`。
    pub fn is_direct(&self, address: &Address) -> bool {
        // 模式先决定大方向，rules 模式才进入具体匹配。
        let result = match self.mode {
            DirectAccessMode::ProxyAll => false,
            DirectAccessMode::DirectAll => true,
            DirectAccessMode::Rules => self.matches_any_rule(address),
        };

        debug!(
            "直连访问检查 {:?}: {}",
            address,
            if result { "直连" } else { "代理" }
        );

        result
    }

    /// 检查地址是否匹配任何已配置的规则
    fn matches_any_rule(&self, address: &Address) -> bool {
        match address {
            Address::Domain { host, .. } => {
                let host_lower = host.to_lowercase();

                // 首先尝试将域名解析为 IP 地址
                // （有时域名会以 IP 字符串形式传入，如 "10.0.0.1"）
                if let Ok(ip) = host_lower.parse::<IpAddr>() {
                    return self.rules.iter().any(|rule| Self::match_ip(rule, &ip));
                }

                // 与域名规则进行匹配
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
            Address::ProxyDns { .. } | Address::UdpRelay => false,
        }
    }

    fn match_domain(rule: &ParsedRule, host: &str) -> bool {
        // 域名规则只匹配域名，不尝试反向解析 IP。
        match rule {
            ParsedRule::ExactDomain(domain) => host == domain,
            ParsedRule::WildcardDomain(suffix) => {
                // "*.example.com"（suffix=".example.com"）匹配 "sub.example.com"
                // 但不匹配 "example.com" 本身。遵循标准通配符约定。
                host.ends_with(suffix.as_str()) && host.len() > suffix.len()
            }
            _ => false,
        }
    }

    fn match_ip(rule: &ParsedRule, ip: &IpAddr) -> bool {
        // IP 规则支持精确地址和 CIDR 网段。
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

/// 将协议 Address 转换为可连接的地址字符串，
/// 适用于 TcpStream::connect() 或 UdpSocket::connect()
pub fn address_to_string(address: &Address) -> String {
    // IPv6 必须加方括号才能形成合法 host:port。
    match address {
        Address::Domain { host, port } => format!("{}:{}", host, port),
        Address::Ipv4 { addr, port } => {
            format!("{}.{}.{}.{}:{}", addr[0], addr[1], addr[2], addr[3], port)
        }
        Address::Ipv6 { addr, port } => {
            let ipv6 = Ipv6Addr::from(*addr);
            format!("[{}]:{}", ipv6, port)
        }
        Address::ProxyDns { port } => format!("proxy-dns:{port}"),
        Address::UdpRelay => "udp-relay".to_string(),
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
}
