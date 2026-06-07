use if_addrs::{IfAddr, Ifv4Addr, Ifv6Addr, Interface, get_if_addrs};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::{LazyLock, RwLock};
use std::time::{Duration, Instant};

const IF_ADDRS_CACHE_TTL: Duration = Duration::from_secs(2);

static IF_ADDRS_CACHE: LazyLock<RwLock<InterfaceAddrCache>> =
    LazyLock::new(|| RwLock::new(InterfaceAddrCache::default()));

#[derive(Default)]
struct InterfaceAddrCache {
    interfaces: Vec<Interface>,
    refreshed_at: Option<Instant>,
}

impl InterfaceAddrCache {
    fn is_fresh(&self) -> bool {
        self.refreshed_at
            .is_some_and(|refreshed_at| refreshed_at.elapsed() < IF_ADDRS_CACHE_TTL)
    }
}

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
    let interfaces = cached_if_addrs()?;
    match interface_bind_addrs_from_snapshot(interface, dst, &interfaces) {
        Ok(sources) => Ok(sources),
        Err(err) if should_refresh_if_addrs(&err) => {
            let interfaces = refresh_if_addrs()?;
            interface_bind_addrs_from_snapshot(interface, dst, &interfaces)
        }
        Err(err) => Err(err),
    }
}

pub(super) fn cached_if_addrs() -> io::Result<Vec<Interface>> {
    if let Ok(cache) = IF_ADDRS_CACHE.read()
        && cache.is_fresh()
    {
        return Ok(cache.interfaces.clone());
    }

    let mut cache = IF_ADDRS_CACHE
        .write()
        .map_err(|_| io::Error::other("网卡地址缓存锁已损坏"))?;
    if cache.is_fresh() {
        return Ok(cache.interfaces.clone());
    }
    refresh_if_addrs_locked(&mut cache)
}

pub(super) fn refresh_if_addrs() -> io::Result<Vec<Interface>> {
    let mut cache = IF_ADDRS_CACHE
        .write()
        .map_err(|_| io::Error::other("网卡地址缓存锁已损坏"))?;
    refresh_if_addrs_locked(&mut cache)
}

fn refresh_if_addrs_locked(cache: &mut InterfaceAddrCache) -> io::Result<Vec<Interface>> {
    cache.interfaces = get_if_addrs()?;
    cache.refreshed_at = Some(Instant::now());
    Ok(cache.interfaces.clone())
}

fn interface_bind_addrs_from_snapshot(
    interface: &str,
    dst: SocketAddr,
    interfaces: &[Interface],
) -> io::Result<Vec<BoundSource>> {
    // 遍历系统网卡地址，找出指定设备上能连接目标地址族的本地源地址。
    let mut interface_exists = false;
    let mut address_family_exists = false;
    let mut candidates = Vec::new();

    for iface in interfaces {
        // 只处理用户配置或 auto 选中的那一块网卡。
        if iface.name.as_str() != interface {
            continue;
        }

        interface_exists = true;
        match (dst, &iface.addr) {
            (SocketAddr::V4(dst), IfAddr::V4(addr)) => {
                address_family_exists = true;
                // IPv4 候选按“同子网优先”打分。
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
                // IPv6 候选需要处理 link-local scope id。
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

    // 区分“设备不存在”和“设备存在但地址族不匹配”，便于排查配置。
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

    // 分数越低越适合，优先使用同子网地址再尝试其他可达地址。
    candidates.sort_by_key(|candidate| candidate.score);
    Ok(candidates
        .into_iter()
        .map(|candidate| candidate.source)
        .collect())
}

fn should_refresh_if_addrs(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::AddrNotAvailable
    )
}

pub(super) fn iface_addr_matches_dst(addr: &IfAddr, dst_ip: IpAddr) -> bool {
    // auto 模式只需要知道该网卡是否有目标地址族可用源地址。
    match (addr, dst_ip) {
        (IfAddr::V4(addr), IpAddr::V4(dst)) => ipv4_source_score(addr, dst).is_some(),
        (IfAddr::V6(addr), IpAddr::V6(dst)) => ipv6_source_score(addr, dst).is_some(),
        _ => false,
    }
}

fn ipv4_source_score(addr: &Ifv4Addr, dst: Ipv4Addr) -> Option<u8> {
    // 不使用未指定地址、回环地址或与公网目标不兼容的 link-local 地址。
    if addr.ip.is_unspecified() || addr.ip.is_loopback() {
        return None;
    }

    if !dst.is_link_local() && addr.ip.is_link_local() {
        return None;
    }

    // 同子网地址优先级最高，跨子网地址作为备选。
    if ipv4_same_subnet(addr.ip, addr.netmask, dst) {
        Some(0)
    } else {
        Some(1)
    }
}

fn ipv6_source_score(addr: &Ifv6Addr, dst: Ipv6Addr) -> Option<u8> {
    // IPv6 同样拒绝未指定和回环地址。
    if addr.ip.is_unspecified() || addr.ip.is_loopback() {
        return None;
    }

    // link-local 源地址只能连接 link-local 目标，反之亦然。
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
    // IPv6 link-local 地址需要 scope id 才能唯一定位到网卡。
    if ipv6_is_unicast_link_local(ip) {
        interface_index.unwrap_or(0)
    } else {
        0
    }
}
