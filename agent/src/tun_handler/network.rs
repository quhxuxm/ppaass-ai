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
        Self {
            ipv4,
            ipv4_prefix,
            ipv6,
        }
    }

    fn contains_ip(self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => ipv4_in_cidr(ip, self.ipv4, self.ipv4_prefix),
            IpAddr::V6(ip) => self
                .ipv6
                .is_some_and(|(network, prefix)| ipv6_in_cidr(ip, network, prefix)),
        }
    }
}

pub(super) fn reject_tun_target(
    transport: &str,
    source: SocketAddr,
    target: SocketAddr,
    tun_networks: TunNetworks,
) -> Result<()> {
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
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(ip) & mask) == (u32::from(network) & mask)
}

fn ipv6_in_cidr(ip: Ipv6Addr, network: Ipv6Addr, prefix: u8) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (u128::from_be_bytes(ip.octets()) & mask) == (u128::from_be_bytes(network.octets()) & mask)
}

fn socket_addr_to_address(addr: SocketAddr) -> Address {
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
