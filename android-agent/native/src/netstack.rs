mod bridge;
mod direct_domain_cache;
mod dns_proxy;
mod domain_sniff;
mod network;
mod supervisor;
mod tcp;
mod udp;
mod udp_relay;

use std::sync::Arc;
use std::time::Duration;

use common::spawn_guarded;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::config::AndroidAgentConfig;
use crate::connection_pool::AndroidConnectionPool;
use crate::direct_access::DirectAccessChecker;
use crate::error::Result;
use crate::fd_device::{AndroidTunDevice, RawFd};

use direct_domain_cache::DirectDomainCache;
use network::{TunNetworks, parse_cidr_v4, parse_cidr_v6};
use supervisor::spawn_netstack_supervisor;

#[derive(Clone)]
struct ForwardContext {
    tcp_pool: Arc<AndroidConnectionPool>,
    udp_pool: Arc<AndroidConnectionPool>,
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
    let block_quic = config.tun.block_quic;

    info!(
        "starting Android TUN agent: ipv4={}, ipv6={:?}, mtu={}, proxy_dns={}, block_quic={}, tcp_pool_size={}, udp_pool_size={}",
        config.tun.ipv4,
        config.tun.ipv6,
        mtu,
        proxy_dns,
        block_quic,
        config.tcp_pool_size,
        config.udp_pool_size
    );

    let device = Arc::new(AndroidTunDevice::from_raw_fd(raw_fd)?);
    let config = Arc::new(config);
    let direct_checker = Arc::new(DirectAccessChecker::new(&config.direct_access));
    let tcp_pool = AndroidConnectionPool::new(
        config.clone(),
        shutdown.clone(),
        config.tcp_pool_size,
        "tcp_pool",
    );
    let udp_pool = AndroidConnectionPool::new(
        config.clone(),
        shutdown.clone(),
        config.udp_pool_size,
        "udp_pool",
    );
    let tcp_pool_for_prewarm = tcp_pool.clone();
    spawn_guarded("android tcp pool prewarm", async move {
        tcp_pool_for_prewarm.prewarm().await;
    });
    let udp_pool_for_prewarm = udp_pool.clone();
    spawn_guarded("android udp pool prewarm", async move {
        udp_pool_for_prewarm.prewarm().await;
    });
    let context = ForwardContext {
        tcp_pool,
        udp_pool,
        direct_checker,
        direct_domain_cache: Arc::new(DirectDomainCache::new(Duration::from_secs(300))),
        tun_networks,
        proxy_dns,
    };
    let netstack_task =
        spawn_netstack_supervisor(device, mtu, context, block_quic, shutdown.clone())?;

    shutdown.cancelled().await;
    info!("Android TUN agent shutdown requested");
    let _ = netstack_task.await;
    info!("Android TUN agent stopped");
    Ok(())
}
