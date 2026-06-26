mod bridge;
mod direct_domain_cache;
mod dns_proxy;
mod network;
mod supervisor;
mod tcp;
mod udp;
mod udp_relay;

use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::config::AndroidAgentConfig;
use crate::direct_access::DirectAccessChecker;
use crate::error::Result;
use crate::fd_device::{AndroidTunDevice, RawFd};
use crate::yamux_session::AndroidYamuxSessionManager;

use direct_domain_cache::DirectDomainCache;
use network::{TunNetworks, parse_cidr_v4, parse_cidr_v6};
use supervisor::spawn_netstack_supervisor;

#[derive(Clone)]
struct ForwardContext {
    tcp_sessions: Arc<AndroidYamuxSessionManager>,
    udp_sessions: Arc<AndroidYamuxSessionManager>,
    direct_checker: Arc<DirectAccessChecker>,
    direct_domain_cache: Arc<DirectDomainCache>,
    tun_networks: TunNetworks,
    proxy_dns: bool,
}

pub async fn run_android_agent(
    raw_fd: RawFd,
    config: AndroidAgentConfig,
    shutdown: CancellationToken,
) -> Result<()> {
    config.validate()?;

    let (ipv4, ipv4_prefix) = parse_cidr_v4(&config.tun.ipv4)?;
    let ipv6 = config
        .tun
        .ipv6
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(parse_cidr_v6)
        .transpose()?;
    let tun_networks = TunNetworks::new(ipv4, ipv4_prefix, ipv6);
    let mtu = config.tun.mtu as usize;
    let proxy_dns = config.tun.proxy_dns;
    let quic_policy = config.tun.effective_quic_policy();

    info!(
        "starting Android TUN agent: ipv4={}, ipv6={:?}, mtu={}, proxy_dns={}, quic_policy={:?}, tcp=direct-framed, udp_yamux_sessions={}",
        config.tun.ipv4,
        config.tun.ipv6,
        mtu,
        proxy_dns,
        quic_policy,
        config.yamux.udp_session_count()
    );
    info!(
        "Android TUN UDP/443 QUIC policy: {}",
        quic_policy.description_zh()
    );

    let device = Arc::new(AndroidTunDevice::from_raw_fd(raw_fd)?);
    let config = Arc::new(config);
    let direct_checker = Arc::new(DirectAccessChecker::new(&config.direct_access));
    let tcp_sessions = AndroidYamuxSessionManager::new_tcp_direct(config.clone(), shutdown.clone());
    let udp_sessions = AndroidYamuxSessionManager::new_udp(config.clone(), shutdown.clone());
    let context = ForwardContext {
        tcp_sessions,
        udp_sessions,
        direct_checker,
        direct_domain_cache: Arc::new(DirectDomainCache::new(Duration::from_secs(300))),
        tun_networks,
        proxy_dns,
    };
    let netstack_task =
        spawn_netstack_supervisor(device, mtu, context, quic_policy, shutdown.clone())?;

    shutdown.cancelled().await;
    info!("Android TUN agent shutdown requested");
    let _ = netstack_task.await;
    info!("Android TUN agent stopped");
    Ok(())
}
