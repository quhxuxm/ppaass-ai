use std::net::Ipv4Addr;

pub fn ipv4_networks_overlap(
    left_address: Ipv4Addr,
    left_prefix: u8,
    right_address: Ipv4Addr,
    right_prefix: u8,
) -> bool {
    let shared_prefix = left_prefix.min(right_prefix);
    let mask = if shared_prefix == 0 {
        0
    } else {
        u32::MAX << (32 - shared_prefix)
    };
    (u32::from(left_address) & mask) == (u32::from(right_address) & mask)
}

#[cfg(target_os = "macos")]
use super::probe::find_default_route;
#[cfg(target_os = "macos")]
use crate::error::{AgentError, Result};
#[cfg(target_os = "macos")]
use if_addrs::IfAddr;
#[cfg(target_os = "macos")]
use route_manager::RouteManager;
#[cfg(target_os = "macos")]
use std::net::IpAddr;

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct DefaultRoute {
    gateway: Option<IpAddr>,
    if_index: Option<u32>,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalIpv4Network {
    interface_name: String,
    address: Ipv4Addr,
    prefix: u8,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct MacosNetworkTopology {
    ipv4_default: Option<DefaultRoute>,
    ipv6_default: Option<DefaultRoute>,
    local_ipv4_networks: Vec<LocalIpv4Network>,
}

#[cfg(target_os = "macos")]
pub(crate) struct MacosTunTopologyMonitor {
    tun_ipv4: Ipv4Addr,
    tun_prefix: u8,
    tun_if_index: u32,
    previous: MacosNetworkTopology,
}

#[cfg(target_os = "macos")]
pub(crate) enum MacosTunTopologyChange {
    Stable,
    DefaultRouteChanged,
    TunNetworkConflict(String),
}

#[cfg(target_os = "macos")]
impl MacosTunTopologyMonitor {
    pub(crate) fn new(tun_ipv4: Ipv4Addr, tun_prefix: u8, tun_if_index: u32) -> Result<Self> {
        let topology = inspect_macos_topology(tun_if_index)?;
        if let Some(conflict) = find_tun_network_conflict(tun_ipv4, tun_prefix, &topology) {
            return Err(AgentError::Connection(conflict_message(
                tun_ipv4, tun_prefix, &conflict,
            )));
        }
        Ok(Self {
            tun_ipv4,
            tun_prefix,
            tun_if_index,
            previous: topology,
        })
    }

    pub(crate) fn poll(&mut self) -> Result<MacosTunTopologyChange> {
        let current = inspect_macos_topology(self.tun_if_index)?;
        if let Some(conflict) = find_tun_network_conflict(self.tun_ipv4, self.tun_prefix, &current)
        {
            return Ok(MacosTunTopologyChange::TunNetworkConflict(
                conflict_message(self.tun_ipv4, self.tun_prefix, &conflict),
            ));
        }

        let default_route_changed = self.previous.ipv4_default != current.ipv4_default
            || self.previous.ipv6_default != current.ipv6_default;
        self.previous = current;
        Ok(if default_route_changed {
            MacosTunTopologyChange::DefaultRouteChanged
        } else {
            MacosTunTopologyChange::Stable
        })
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn ensure_macos_tun_network_available(tun_ipv4: Ipv4Addr, tun_prefix: u8) -> Result<()> {
    let topology = inspect_macos_topology(u32::MAX)?;
    if let Some(conflict) = find_tun_network_conflict(tun_ipv4, tun_prefix, &topology) {
        return Err(AgentError::Connection(conflict_message(
            tun_ipv4, tun_prefix, &conflict,
        )));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn inspect_macos_topology(tun_if_index: u32) -> Result<MacosNetworkTopology> {
    let mut manager = RouteManager::new()
        .map_err(|error| AgentError::Connection(format!("RouteManager 初始化失败：{error}")))?;
    let routes = manager
        .list()
        .map_err(|error| AgentError::Connection(format!("读取系统路由表失败：{error}")))?;
    let interfaces = if_addrs::get_if_addrs()
        .map_err(|error| AgentError::Connection(format!("读取系统网络接口失败：{error}")))?;
    Ok(MacosNetworkTopology {
        ipv4_default: default_route_signature(&routes, false),
        ipv6_default: default_route_signature(&routes, true),
        local_ipv4_networks: interfaces
            .into_iter()
            .filter(|interface| interface.index != Some(tun_if_index))
            .filter(|interface| !interface.is_loopback())
            .filter_map(|interface| match interface.addr {
                IfAddr::V4(address) => Some(LocalIpv4Network {
                    interface_name: interface.name,
                    address: address.ip,
                    prefix: address.prefixlen,
                }),
                IfAddr::V6(_) => None,
            })
            .collect(),
    })
}

#[cfg(target_os = "macos")]
fn default_route_signature(routes: &[route_manager::Route], want_v6: bool) -> Option<DefaultRoute> {
    let (gateway, if_index) = find_default_route(routes, want_v6);
    (gateway.is_some() || if_index.is_some()).then_some(DefaultRoute { gateway, if_index })
}

#[cfg(target_os = "macos")]
fn find_tun_network_conflict(
    tun_ipv4: Ipv4Addr,
    tun_prefix: u8,
    topology: &MacosNetworkTopology,
) -> Option<LocalIpv4Network> {
    topology
        .local_ipv4_networks
        .iter()
        .find(|network| {
            ipv4_networks_overlap(tun_ipv4, tun_prefix, network.address, network.prefix)
        })
        .cloned()
}

#[cfg(target_os = "macos")]
fn conflict_message(tun_ipv4: Ipv4Addr, tun_prefix: u8, conflict: &LocalIpv4Network) -> String {
    format!(
        "TUN 网段 {tun_ipv4}/{tun_prefix} 与接口 {} 的本地网段 {}/{} 重叠；\
         请修改 [tun].ipv4 后重试（推荐 198.18.0.1/15），以避免 VMware/vmnet 破坏宿主机 TUN 路由",
        conflict.interface_name, conflict.address, conflict.prefix
    )
}
