use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

pub(crate) fn validate_managed_proxy_addresses(
    addresses: &[String],
    allow_empty: bool,
) -> Result<(), String> {
    if (!allow_empty && addresses.is_empty()) || addresses.len() > 32 {
        return Err("认证服务返回的 Proxy 地址列表无效".to_string());
    }
    let mut unique = HashSet::new();
    for address in addresses {
        validate_address_shape(address)?;
        if !unique.insert(address.to_ascii_lowercase()) {
            return Err("认证服务返回了重复的 Proxy 地址".to_string());
        }
        let (host, port) =
            split_managed_proxy_address(address).ok_or_else(invalid_proxy_address_message)?;
        if port.parse::<u16>().ok().filter(|port| *port > 0).is_none()
            || !valid_managed_proxy_host(address, host)
        {
            return Err(invalid_proxy_address_message());
        }
    }
    Ok(())
}

fn validate_address_shape(address: &str) -> Result<(), String> {
    if address.is_empty()
        || address.len() > 512
        || address.chars().any(char::is_whitespace)
        || address.contains("://")
        || address.contains('/')
        || address.contains(['@', '#', '?'])
    {
        return Err(invalid_proxy_address_message());
    }
    Ok(())
}

fn valid_managed_proxy_host(address: &str, host: &str) -> bool {
    if address.starts_with('[') {
        return host.parse::<Ipv6Addr>().is_ok();
    }
    if host.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    valid_ascii_hostname(host)
}

fn valid_ascii_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.is_ascii()
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

fn split_managed_proxy_address(address: &str) -> Option<(&str, &str)> {
    if let Some(rest) = address.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        return Some((host, port));
    }
    address.rsplit_once(':')
}

fn invalid_proxy_address_message() -> String {
    "认证服务返回了无效的 Proxy 地址".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addresses(values: &[&str]) -> Vec<String> {
        values.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn accepts_supported_hosts_and_ports() {
        for value in [
            "proxy.example.com:443",
            "127.0.0.1:1",
            "[2001:db8::1]:65535",
        ] {
            assert!(validate_managed_proxy_addresses(&addresses(&[value]), false).is_ok());
        }
    }

    #[test]
    fn rejects_empty_duplicate_url_path_and_invalid_ports() {
        assert!(validate_managed_proxy_addresses(&[], false).is_err());
        assert!(validate_managed_proxy_addresses(&[], true).is_ok());
        for values in [
            vec!["proxy.example.com:443", "PROXY.example.com:443"],
            vec!["https://proxy.example.com:443"],
            vec!["proxy.example.com/path:443"],
            vec!["proxy.example.com:0"],
            vec!["proxy.example.com:65536"],
            vec!["2001:db8::1:443"],
        ] {
            assert!(validate_managed_proxy_addresses(&addresses(&values), false).is_err());
        }
    }

    #[test]
    fn rejects_invalid_ascii_hostnames() {
        for host in [
            "-bad.example",
            "bad-.example",
            "bad..example",
            "bad_example",
        ] {
            let value = format!("{host}:443");
            assert!(validate_managed_proxy_addresses(&[value], false).is_err());
        }
        let long_label = "a".repeat(64);
        assert!(
            validate_managed_proxy_addresses(&[format!("{long_label}.example:443")], false)
                .is_err()
        );
    }
}
