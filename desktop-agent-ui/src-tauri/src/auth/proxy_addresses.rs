use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::models::AgentProxyEntry;

pub fn validate_managed_proxy_addresses(
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

pub fn validate_agent_proxy_entries(
    entries: &[AgentProxyEntry],
    selected_id: Option<&str>,
) -> Result<(), String> {
    if entries.len() > 128 {
        return Err("认证服务返回的 Proxy Entry 数量过多".to_string());
    }
    let mut ids = HashSet::new();
    for entry in entries {
        if !valid_entry_text(&entry.proxy_entry_id, 128)
            || !valid_entry_text(&entry.label, 256)
            || !valid_entry_text(&entry.description, 512)
            || !valid_entry_text(&entry.icon_key, 256)
            || entry
                .entry_id
                .as_deref()
                .is_some_and(|value| !valid_entry_text(value, 256))
        {
            return Err("认证服务返回了无效的 Proxy Entry 信息".to_string());
        }
        validate_managed_proxy_addresses(std::slice::from_ref(&entry.address), false)?;
        if !ids.insert(entry.proxy_entry_id.as_str()) {
            return Err("认证服务返回了重复的 Proxy Entry".to_string());
        }
    }
    if selected_id.is_some_and(|selected| !ids.contains(selected)) {
        return Err("认证服务返回的当前 Proxy Entry 不在可用列表中".to_string());
    }
    Ok(())
}

fn valid_entry_text(value: &str, max_len: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max_len && !value.chars().any(char::is_control)
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
