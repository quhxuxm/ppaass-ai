use crate::error::{AgentError, Result};
use protocol::Address;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tracing::error;

#[derive(Clone, Copy)]
pub(super) struct TunNetworks {
    ipv4: Ipv4Addr,
    ipv4_prefix: u8,
    ipv6: Option<(Ipv6Addr, u8)>,
}

impl TunNetworks {
    pub(super) fn new(ipv4: Ipv4Addr, ipv4_prefix: u8, ipv6: Option<(Ipv6Addr, u8)>) -> Self {
        // 保存 TUN 自身网段，用于运行时检测目标地址是否异常落回 TUN。
        Self {
            ipv4,
            ipv4_prefix,
            ipv6,
        }
    }

    pub(super) fn contains_ip(self, ip: IpAddr) -> bool {
        // IPv6 未配置时，只检测 IPv4 TUN 网段。
        match ip {
            IpAddr::V4(ip) => ipv4_in_cidr(ip, self.ipv4, self.ipv4_prefix),
            IpAddr::V6(ip) => self
                .ipv6
                .is_some_and(|(network, prefix)| ipv6_in_cidr(ip, network, prefix)),
        }
    }

    pub(super) fn is_ipv4_broadcast(self, ip: IpAddr) -> bool {
        let IpAddr::V4(ip) = ip else {
            return false;
        };
        if self.ipv4_prefix >= 31 {
            return false;
        }

        let mask = ipv4_mask(self.ipv4_prefix);
        let network = u32::from(self.ipv4) & mask;
        let broadcast = network | !mask;
        u32::from(ip) == broadcast
    }
}

pub(super) fn is_tun_local_udp_target(
    source: SocketAddr,
    target: SocketAddr,
    tun_networks: TunNetworks,
) -> bool {
    tun_networks.contains_ip(source.ip()) && tun_networks.contains_ip(target.ip())
}

pub(super) fn reject_tun_target(
    transport: &str,
    source: SocketAddr,
    target: SocketAddr,
    tun_networks: TunNetworks,
) -> Result<()> {
    // 目标落在 TUN 自身网段通常意味着 source/target 被反用，会导致回环。
    if !tun_networks.contains_ip(target.ip()) {
        return Ok(());
    }

    let message = format!(
        "TUN {transport} 目标地址异常：源地址 {source}，目标地址 {target} 落在 TUN 自身网段内；\
         这通常表示源地址和目标地址仍被反向使用"
    );
    error!("{message}");
    Err(AgentError::Connection(message))
}

pub(super) fn address_for_tun_target(target: SocketAddr, proxy_dns: bool) -> (Address, bool) {
    // proxy_dns 开启时，所有 53 端口请求转成协议虚拟地址，由 proxy 端解析上游 DNS。
    if proxy_dns && target.port() == 53 {
        return (
            Address::ProxyDns {
                port: target.port(),
            },
            true,
        );
    }

    (socket_addr_to_address(target), false)
}

pub(super) fn parse_cidr_v4(s: &str) -> Result<(Ipv4Addr, u8)> {
    // TUN IPv4 必须显式写成 CIDR，便于同时配置地址和路由前缀。
    let (ip, prefix) = s
        .split_once('/')
        .ok_or_else(|| AgentError::Connection(format!("无效的 IPv4 CIDR：{s}")))?;
    let ip: Ipv4Addr = ip
        .parse()
        .map_err(|e| AgentError::Connection(format!("无效的 IPv4 地址 {ip}：{e}")))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|e| AgentError::Connection(format!("无效的 IPv4 前缀 {prefix}：{e}")))?;
    if prefix > 32 {
        return Err(AgentError::Connection(format!(
            "无效的 IPv4 前缀 {prefix}：必须小于等于 32"
        )));
    }
    Ok((ip, prefix))
}

pub(super) fn parse_cidr_v6(s: &str) -> Result<(Ipv6Addr, u8)> {
    // IPv6 配置可选，但一旦提供也必须是合法 CIDR。
    let (ip, prefix) = s
        .split_once('/')
        .ok_or_else(|| AgentError::Connection(format!("无效的 IPv6 CIDR：{s}")))?;
    let ip: Ipv6Addr = ip
        .parse()
        .map_err(|e| AgentError::Connection(format!("无效的 IPv6 地址 {ip}：{e}")))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|e| AgentError::Connection(format!("无效的 IPv6 前缀 {prefix}：{e}")))?;
    if prefix > 128 {
        return Err(AgentError::Connection(format!(
            "无效的 IPv6 前缀 {prefix}：必须小于等于 128"
        )));
    }
    Ok((ip, prefix))
}

fn ipv4_in_cidr(ip: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    // prefix 为 0 时整段 IPv4 地址空间都匹配。
    let mask = ipv4_mask(prefix);
    (u32::from(ip) & mask) == (u32::from(network) & mask)
}

fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn ipv6_in_cidr(ip: Ipv6Addr, network: Ipv6Addr, prefix: u8) -> bool {
    // IPv6 使用 u128 掩码做同网段判断。
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (u128::from_be_bytes(ip.octets()) & mask) == (u128::from_be_bytes(network.octets()) & mask)
}

pub(super) fn socket_addr_to_address(addr: SocketAddr) -> Address {
    // 保留 IP 字面量，避免已经解析出的 TUN 目标再次走 DNS。
    match addr.ip() {
        IpAddr::V4(v4) => Address::Ipv4 {
            addr: v4.octets(),
            port: addr.port(),
        },
        IpAddr::V6(v6) => Address::Ipv6 {
            addr: v6.octets(),
            port: addr.port(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tun_local_udp_target_matches_source_and_target_inside_tun_network() {
        let networks = TunNetworks::new(Ipv4Addr::new(10, 10, 10, 1), 24, None);
        let source = "10.10.10.1:137".parse().unwrap();
        let target = "10.10.10.1:137".parse().unwrap();

        assert!(is_tun_local_udp_target(source, target, networks));
    }

    #[test]
    fn reversed_external_to_tun_target_is_not_local_udp_noise() {
        let networks = TunNetworks::new(Ipv4Addr::new(10, 10, 10, 1), 24, None);
        let source = "8.8.8.8:443".parse().unwrap();
        let target = "10.10.10.1:443".parse().unwrap();

        assert!(!is_tun_local_udp_target(source, target, networks));
        assert!(reject_tun_target("UDP", source, target, networks).is_err());
    }
}
