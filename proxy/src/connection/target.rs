use crate::config::ProxyConfig;
use crate::error::{ProxyError, Result};
use protocol::Address;
#[cfg(not(windows))]
use std::fs;
use std::net::{IpAddr, SocketAddr};
#[cfg(windows)]
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(windows)]
use std::ptr;
use tracing::debug;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
#[cfg(windows)]
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses,
    IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_TUNNEL, IP_ADAPTER_ADDRESSES_LH,
};
#[cfg(windows)]
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6, SOCKET_ADDRESS,
};
pub(crate) fn target_addr_for_address(
    proxy_config: &ProxyConfig,
    address: &Address,
) -> Result<String> {
    match address {
        Address::ProxyDns { port } => proxy_dns_target_addr(proxy_config, *port),
        Address::UdpRelay => Err(ProxyError::Connection(
            "virtual target address cannot be used as a TCP target".to_string(),
        )),
        _ => Ok(format_target_addr(address)),
    }
}

fn proxy_dns_target_addr(proxy_config: &ProxyConfig, port: u16) -> Result<String> {
    // 显式配置优先，适合 Windows 或容器环境中系统 DNS 不可靠的情况。
    if let Some(addr) = proxy_config
        .dns_upstream_addr
        .as_deref()
        .map(str::trim)
        .filter(|addr| !addr.is_empty())
    {
        let target = endpoint_with_port(addr, port);
        debug!("DNS 请求使用 proxy 配置的上游 DNS：{target}");
        return Ok(target);
    }

    // 未配置时按当前系统 DNS 解析，保持默认行为贴近操作系统。
    let nameserver = system_dns_nameserver()?;
    let target = endpoint_with_port(&nameserver, port);
    debug!("DNS 请求使用 proxy 端默认上游 DNS：{target}");
    Ok(target)
}

fn format_target_addr(address: &Address) -> String {
    // 协议地址统一转成 host:port，供 Tokio lookup_host/connect 使用。
    match address {
        Address::Domain { host, port } => format!("{}:{}", host, port),
        Address::Ipv4 { addr, port } => {
            format!("{}.{}.{}.{}:{}", addr[0], addr[1], addr[2], addr[3], port)
        }
        Address::Ipv6 { addr, port } => {
            format!(
                "[{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}]:{}",
                u16::from_be_bytes([addr[0], addr[1]]),
                u16::from_be_bytes([addr[2], addr[3]]),
                u16::from_be_bytes([addr[4], addr[5]]),
                u16::from_be_bytes([addr[6], addr[7]]),
                u16::from_be_bytes([addr[8], addr[9]]),
                u16::from_be_bytes([addr[10], addr[11]]),
                u16::from_be_bytes([addr[12], addr[13]]),
                u16::from_be_bytes([addr[14], addr[15]]),
                port
            )
        }
        Address::ProxyDns { port } => format!("proxy-dns:{port}"),
        Address::UdpRelay => "udp-relay".to_string(),
    }
}

pub(super) fn relay_target_addr(address: &Address) -> Result<String> {
    match address {
        Address::Domain { .. } | Address::Ipv4 { .. } | Address::Ipv6 { .. } => {
            Ok(format_target_addr(address))
        }
        Address::ProxyDns { .. } | Address::UdpRelay => Err(ProxyError::Connection(
            "UDP relay packet contains virtual target address".to_string(),
        )),
    }
}

#[cfg(not(windows))]
fn system_dns_nameserver() -> Result<String> {
    // Unix 系统优先读取 resolv.conf 中第一个 nameserver。
    let resolv_conf = fs::read_to_string("/etc/resolv.conf").map_err(|e| {
        ProxyError::Configuration(format!("读取系统 DNS 配置 /etc/resolv.conf 失败：{e}"))
    })?;
    resolv_conf
        .lines()
        .find_map(parse_resolv_nameserver)
        .map(str::to_owned)
        .ok_or_else(|| {
            ProxyError::Configuration("系统 DNS 配置中没有可用的 nameserver".to_string())
        })
}

#[cfg(windows)]
fn system_dns_nameserver() -> Result<String> {
    const INITIAL_BUFFER_SIZE: u32 = 15_000;
    const MAX_ATTEMPTS: usize = 3;

    // Windows 下优先使用默认路由所在网卡的 DNS，避免误选 TUN/虚拟网卡 DNS。
    let preferred_if_indices = windows_default_route_if_indices();
    let mut buffer_size = INITIAL_BUFFER_SIZE;

    for _ in 0..MAX_ATTEMPTS {
        // GetAdaptersAddresses 会在缓冲区不足时回填所需大小，最多重试几次。
        let mut buffer = vec![0u8; buffer_size as usize];
        let adapters = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let status = unsafe {
            GetAdaptersAddresses(
                0,
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                ptr::null(),
                adapters,
                &mut buffer_size,
            )
        };

        if status == ERROR_BUFFER_OVERFLOW {
            continue;
        }

        if status != ERROR_SUCCESS {
            return Err(ProxyError::Configuration(format!(
                "读取 Windows 系统 DNS 配置失败：GetAdaptersAddresses 返回 {status}"
            )));
        }

        // 先找默认路由网卡 DNS，找不到再降级到其他可解析网卡。
        if let Some(ip) = unsafe { find_windows_dns_server(adapters, &preferred_if_indices) } {
            return Ok(ip.to_string());
        }

        return Err(ProxyError::Configuration(
            "Windows 系统 DNS 配置中没有可用的 nameserver；可在 proxy.toml 中设置 dns_upstream_addr".to_string(),
        ));
    }

    Err(ProxyError::Configuration(
        "读取 Windows 系统 DNS 配置失败：网卡信息缓冲区持续不足".to_string(),
    ))
}

#[cfg(windows)]
fn windows_default_route_if_indices() -> Vec<u32> {
    // 读取当前默认路由的 if_index，用来给 DNS 网卡选择排序。
    let Ok(mut route_manager) = route_manager::RouteManager::new() else {
        return Vec::new();
    };
    let Ok(routes) = route_manager.list() else {
        return Vec::new();
    };

    let mut indices = Vec::new();
    for route in routes {
        // 只关心 IPv4/IPv6 默认路由。
        if route.prefix() != 0 {
            continue;
        }

        let is_default = match route.destination() {
            IpAddr::V4(addr) => addr.is_unspecified(),
            IpAddr::V6(addr) => addr.is_unspecified(),
        };
        if !is_default {
            continue;
        }

        if let Some(if_index) = route.if_index()
            && !indices.contains(&if_index)
        {
            indices.push(if_index);
        }
    }

    indices
}

#[cfg(windows)]
unsafe fn find_windows_dns_server(
    adapters: *mut IP_ADAPTER_ADDRESSES_LH,
    preferred_if_indices: &[u32],
) -> Option<IpAddr> {
    // 第一轮只查默认路由网卡，第二轮放宽到其他可用物理网卡。
    for preferred_only in [true, false] {
        let mut adapter = adapters;
        while !adapter.is_null() {
            let adapter_ref = unsafe { &*adapter };
            let is_preferred = windows_adapter_matches_if_index(adapter_ref, preferred_if_indices);

            if windows_adapter_can_resolve(adapter_ref)
                && (!preferred_only || is_preferred || preferred_if_indices.is_empty())
            {
                // 同一网卡可能配置多个 DNS，返回第一个可用地址。
                let mut dns = adapter_ref.FirstDnsServerAddress;
                while !dns.is_null() {
                    let dns_ref = unsafe { &*dns };
                    if let Some(ip) = unsafe { socket_address_to_ip(dns_ref.Address) }
                        && dns_ip_is_usable(ip)
                    {
                        return Some(ip);
                    }
                    dns = dns_ref.Next;
                }
            }

            adapter = adapter_ref.Next;
        }
    }

    None
}

#[cfg(windows)]
fn windows_adapter_can_resolve(adapter: &IP_ADAPTER_ADDRESSES_LH) -> bool {
    // 排除未启用、回环和隧道网卡，减少选到 TUN 的概率。
    adapter.OperStatus == IfOperStatusUp
        && adapter.IfType != IF_TYPE_SOFTWARE_LOOPBACK
        && adapter.IfType != IF_TYPE_TUNNEL
}

#[cfg(windows)]
fn windows_adapter_matches_if_index(
    adapter: &IP_ADAPTER_ADDRESSES_LH,
    preferred_if_indices: &[u32],
) -> bool {
    // IPv4 IfIndex 和 IPv6 Ipv6IfIndex 都可能对应默认路由。
    if preferred_if_indices.is_empty() {
        return false;
    }

    let if_index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
    preferred_if_indices.contains(&if_index)
        || (adapter.Ipv6IfIndex != 0 && preferred_if_indices.contains(&adapter.Ipv6IfIndex))
}

#[cfg(windows)]
fn dns_ip_is_usable(ip: IpAddr) -> bool {
    // DNS 上游必须是可路由的单播地址。
    match ip {
        IpAddr::V4(ip) => !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast(),
        IpAddr::V6(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !ip.is_unicast_link_local()
        }
    }
}

#[cfg(windows)]
unsafe fn socket_address_to_ip(address: SOCKET_ADDRESS) -> Option<IpAddr> {
    // Windows API 返回原始 sockaddr 指针，这里按地址族转换成 Rust IpAddr。
    if address.lpSockaddr.is_null() {
        return None;
    }

    let family = unsafe { (*address.lpSockaddr).sa_family };
    match family {
        AF_INET if address.iSockaddrLength as usize >= std::mem::size_of::<SOCKADDR_IN>() => {
            let sockaddr = unsafe { &*(address.lpSockaddr.cast::<SOCKADDR_IN>()) };
            let octets = unsafe { sockaddr.sin_addr.S_un.S_un_b };
            Some(IpAddr::V4(Ipv4Addr::new(
                octets.s_b1,
                octets.s_b2,
                octets.s_b3,
                octets.s_b4,
            )))
        }
        AF_INET6 if address.iSockaddrLength as usize >= std::mem::size_of::<SOCKADDR_IN6>() => {
            let sockaddr = unsafe { &*(address.lpSockaddr.cast::<SOCKADDR_IN6>()) };
            let octets = unsafe { sockaddr.sin6_addr.u.Byte };
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

#[cfg(not(windows))]
fn parse_resolv_nameserver(line: &str) -> Option<&str> {
    // 忽略注释和空白，只接受 nameserver 行的第二列。
    let line = line.split(['#', ';']).next()?.trim();
    let mut parts = line.split_whitespace();
    if parts.next()? != "nameserver" {
        return None;
    }

    parts.next()
}

fn endpoint_with_port(value: &str, default_port: u16) -> String {
    // 配置值可只写 IP/域名，缺省端口由请求的 DNS 端口补齐。
    let value = value.trim();
    if has_explicit_port(value) {
        return value.to_string();
    }

    if let Ok(ip) = value.parse::<IpAddr>() {
        return SocketAddr::new(ip, default_port).to_string();
    }

    if value.contains(':') {
        format!("[{value}]:{default_port}")
    } else {
        format!("{value}:{default_port}")
    }
}

fn has_explicit_port(value: &str) -> bool {
    // 支持 [IPv6]:port 和 host:port；裸 IPv6 不视为带端口。
    if let Some(rest) = value.strip_prefix('[')
        && let Some((_, port)) = rest.rsplit_once("]:")
    {
        return port.parse::<u16>().is_ok();
    }

    if let Some((host, port)) = value.rsplit_once(':') {
        return !host.contains(':') && port.parse::<u16>().is_ok();
    }

    false
}
