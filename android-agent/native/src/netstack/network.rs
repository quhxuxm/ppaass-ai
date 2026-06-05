use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use protocol::Address;

use crate::error::{AndroidAgentError, Result};

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
    if !tun_networks.contains_ip(target.ip()) {
        return Ok(());
    }

    Err(AndroidAgentError::Connection(format!(
        "TUN {transport} target loop detected: source={source}, target={target}"
    )))
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

pub(super) fn socket_addr_to_address(addr: SocketAddr) -> Address {
    match addr.ip() {
        IpAddr::V4(ip) => Address::Ipv4 {
            addr: ip.octets(),
            port: addr.port(),
        },
        IpAddr::V6(ip) => Address::Ipv6 {
            addr: ip.octets(),
            port: addr.port(),
        },
    }
}

pub(super) fn parse_cidr_v4(value: &str) -> Result<(Ipv4Addr, u8)> {
    let (ip, prefix) = value
        .split_once('/')
        .ok_or_else(|| AndroidAgentError::Connection(format!("invalid IPv4 CIDR: {value}")))?;
    let ip = ip
        .parse()
        .map_err(|e| AndroidAgentError::Connection(format!("invalid IPv4 address {ip}: {e}")))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|e| AndroidAgentError::Connection(format!("invalid IPv4 prefix: {e}")))?;
    if prefix > 32 {
        return Err(AndroidAgentError::Connection(
            "IPv4 prefix must be <= 32".to_string(),
        ));
    }
    Ok((ip, prefix))
}

pub(super) fn parse_cidr_v6(value: &str) -> Result<(Ipv6Addr, u8)> {
    let (ip, prefix) = value
        .split_once('/')
        .ok_or_else(|| AndroidAgentError::Connection(format!("invalid IPv6 CIDR: {value}")))?;
    let ip = ip
        .parse()
        .map_err(|e| AndroidAgentError::Connection(format!("invalid IPv6 address {ip}: {e}")))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|e| AndroidAgentError::Connection(format!("invalid IPv6 prefix: {e}")))?;
    if prefix > 128 {
        return Err(AndroidAgentError::Connection(
            "IPv6 prefix must be <= 128".to_string(),
        ));
    }
    Ok((ip, prefix))
}

fn ipv4_in_cidr(ip: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
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
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (u128::from(ip) & mask) == (u128::from(network) & mask)
}
