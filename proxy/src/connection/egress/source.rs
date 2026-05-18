use if_addrs::{IfAddr, Ifv4Addr, Ifv6Addr, get_if_addrs};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

#[derive(Clone, Copy)]
pub(super) struct BoundSource {
    pub(super) addr: SocketAddr,
    pub(super) interface_index: Option<u32>,
}

#[derive(Clone, Copy)]
struct SourceCandidate {
    source: BoundSource,
    score: u8,
}

pub(super) fn interface_bind_addrs(
    interface: &str,
    dst: SocketAddr,
) -> io::Result<Vec<BoundSource>> {
    let mut interface_exists = false;
    let mut address_family_exists = false;
    let mut candidates = Vec::new();

    for iface in get_if_addrs()? {
        if iface.name != interface {
            continue;
        }

        interface_exists = true;
        match (dst, &iface.addr) {
            (SocketAddr::V4(dst), IfAddr::V4(addr)) => {
                address_family_exists = true;
                if let Some(score) = ipv4_source_score(addr, *dst.ip()) {
                    candidates.push(SourceCandidate {
                        source: BoundSource {
                            addr: SocketAddr::new(IpAddr::V4(addr.ip), 0),
                            interface_index: iface.index,
                        },
                        score,
                    });
                }
            }
            (SocketAddr::V6(dst), IfAddr::V6(addr)) => {
                address_family_exists = true;
                if let Some(score) = ipv6_source_score(addr, *dst.ip()) {
                    candidates.push(SourceCandidate {
                        source: BoundSource {
                            addr: SocketAddr::V6(SocketAddrV6::new(
                                addr.ip,
                                0,
                                0,
                                ipv6_scope_id(addr.ip, iface.index),
                            )),
                            interface_index: iface.index,
                        },
                        score,
                    });
                }
            }
            _ => {}
        }
    }

    if !interface_exists {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("网络设备不存在：{interface}"),
        ));
    }

    if candidates.is_empty() {
        let message = if address_family_exists {
            format!("网络设备 {interface} 没有可用于连接 {dst} 的本地源地址")
        } else {
            format!("网络设备 {interface} 没有匹配目标地址族的本地地址")
        };

        return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, message));
    }

    candidates.sort_by_key(|candidate| candidate.score);
    Ok(candidates
        .into_iter()
        .map(|candidate| candidate.source)
        .collect())
}

pub(super) fn iface_addr_matches_dst(addr: &IfAddr, dst_ip: IpAddr) -> bool {
    match (addr, dst_ip) {
        (IfAddr::V4(addr), IpAddr::V4(dst)) => ipv4_source_score(addr, dst).is_some(),
        (IfAddr::V6(addr), IpAddr::V6(dst)) => ipv6_source_score(addr, dst).is_some(),
        _ => false,
    }
}

fn ipv4_source_score(addr: &Ifv4Addr, dst: Ipv4Addr) -> Option<u8> {
    if addr.ip.is_unspecified() || addr.ip.is_loopback() {
        return None;
    }

    if !dst.is_link_local() && addr.ip.is_link_local() {
        return None;
    }

    if ipv4_same_subnet(addr.ip, addr.netmask, dst) {
        Some(0)
    } else {
        Some(1)
    }
}

fn ipv6_source_score(addr: &Ifv6Addr, dst: Ipv6Addr) -> Option<u8> {
    if addr.ip.is_unspecified() || addr.ip.is_loopback() {
        return None;
    }

    let source_is_link_local = ipv6_is_unicast_link_local(addr.ip);
    let dst_is_link_local = ipv6_is_unicast_link_local(dst);
    if source_is_link_local != dst_is_link_local {
        return None;
    }

    if ipv6_same_subnet(addr.ip, addr.netmask, dst) {
        Some(0)
    } else {
        Some(1)
    }
}

fn ipv4_same_subnet(ip: Ipv4Addr, netmask: Ipv4Addr, dst: Ipv4Addr) -> bool {
    (u32::from(ip) & u32::from(netmask)) == (u32::from(dst) & u32::from(netmask))
}

fn ipv6_same_subnet(ip: Ipv6Addr, netmask: Ipv6Addr, dst: Ipv6Addr) -> bool {
    let ip = ip.octets();
    let netmask = netmask.octets();
    let dst = dst.octets();
    ip.iter()
        .zip(netmask.iter())
        .zip(dst.iter())
        .all(|((ip, netmask), dst)| (ip & netmask) == (dst & netmask))
}

fn ipv6_is_unicast_link_local(ip: Ipv6Addr) -> bool {
    let bytes = ip.octets();
    bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80
}

fn ipv6_scope_id(ip: Ipv6Addr, interface_index: Option<u32>) -> u32 {
    if ipv6_is_unicast_link_local(ip) {
        interface_index.unwrap_or(0)
    } else {
        0
    }
}
