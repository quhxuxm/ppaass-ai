use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use common::{QuicPolicy, QuicUdpStats, spawn_guarded};
use futures::{SinkExt, StreamExt};
use protocol::{Address, TransportProtocol};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace};

use super::ForwardContext;
use super::direct_domain_cache::DirectDomainCache;
use super::dns_proxy::DnsProxy;
use super::network::{
    TunNetworks, address_for_tun_target, is_tun_local_udp_target, reject_tun_target,
};
use super::udp_relay::UdpRelay;
use crate::android_log;
use crate::connection_pool::AndroidConnectionPool;
use crate::direct_access::{DirectAccessChecker, address_to_string};
use crate::error::Result;

pub(super) type UdpWriter = Arc<tokio::sync::Mutex<netstack_smoltcp::udp::WriteHalf>>;

type UdpSessionKey = (SocketAddr, SocketAddr);
type UdpSessionTx = tokio::sync::mpsc::Sender<Vec<u8>>;
type UdpSessions = Arc<dashmap::DashMap<UdpSessionKey, UdpSessionTx>>;

const UDP_SESSION_IDLE: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub(super) struct UdpSessionContext {
    pub(super) tun_networks: TunNetworks,
    pub(super) proxy_dns: bool,
    pub(super) quic_policy: QuicPolicy,
    pub(super) netstack_tx: UdpWriter,
    pub(super) udp_pool: Arc<AndroidConnectionPool>,
    pub(super) direct_checker: Arc<DirectAccessChecker>,
    pub(super) direct_domain_cache: Arc<DirectDomainCache>,
    pub(super) shutdown: CancellationToken,
}

pub(super) fn spawn_udp_sessions(
    udp_socket: netstack_smoltcp::UdpSocket,
    context: ForwardContext,
    quic_policy: QuicPolicy,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    spawn_guarded("android udp sessions", async move {
        let (mut udp_rx, udp_tx) = udp_socket.split();
        let udp_tx = Arc::new(tokio::sync::Mutex::new(udp_tx));
        let sessions: UdpSessions = Arc::new(dashmap::DashMap::new());
        let dns_proxy = context
            .proxy_dns
            .then(|| DnsProxy::spawn(context.clone(), udp_tx.clone(), shutdown.clone()));
        let udp_relay = UdpRelay::spawn(context.clone(), udp_tx.clone(), shutdown.clone());
        let quic_stats = Arc::new(QuicUdpStats::default());
        spawn_quic_udp_stats_logger(quic_stats.clone(), shutdown.clone());

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                message = udp_rx.next() => {
                    let Some((data, source, target)) = message else { break };
                    if context.proxy_dns && target.port() == 53 {
                        if let Some(dns_proxy) = &dns_proxy {
                            dns_proxy.send(source, target, data);
                        }
                        continue;
                    }

                    let (address, _) = address_for_tun_target(target, context.proxy_dns);
                    if context.tun_networks.is_ipv4_broadcast(target.ip()) {
                        debug!("Android TUN UDP broadcast dropped -> {}", target);
                        continue;
                    }
                    if is_tun_local_udp_target(source, target, context.tun_networks) {
                        debug!("Android TUN UDP local network noise dropped: {} -> {}", source, target);
                        continue;
                    }
                    if let Err(e) = reject_tun_target("UDP", source, target, context.tun_networks)
                    {
                        debug!("Android TUN UDP target rejected: {e}");
                        continue;
                    }

                    let key = (source, target);
                    if let Some(tx) = sessions.get(&key).map(|tx| tx.clone()) {
                        if target.port() == 443 {
                            quic_stats.record_direct();
                        }
                        if tx.try_send(data).is_err() {
                            debug!("Android TUN UDP direct session queue is full; dropping packet -> {}", target);
                        }
                        continue;
                    }

                    let mut direct_match = context.direct_checker.is_direct(&address);
                    let mut proxy_address = address.clone();
                    if !direct_match {
                        if context
                            .direct_domain_cache
                            .matching_domain_for_ip(target.ip(), |domain| {
                                context.direct_checker.is_direct_domain(domain)
                            })
                            .is_some()
                        {
                            direct_match = true;
                        } else if let Some(domain) = context
                            .direct_domain_cache
                            .matching_domain_for_ip(target.ip(), |_| true)
                        {
                            proxy_address = domain_address(&domain, target.port());
                        }
                    }

                    if target.port() == 443 && quic_policy.should_block_udp443(direct_match) {
                        quic_stats.record_blocked();
                        debug!(
                            "Android TUN UDP/443 QUIC dropped by policy {:?} -> {}",
                            quic_policy,
                            target
                        );
                        continue;
                    }

                    if !direct_match {
                        if target.port() == 443 {
                            quic_stats.record_proxied();
                        }
                        udp_relay.send(source, target, proxy_address, data);
                        continue;
                    }

                    if target.port() == 443 {
                        quic_stats.record_direct();
                    }
                    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
                    sessions.insert(key, tx.clone());
                    let _ = tx.try_send(data);

                    let sessions_c = sessions.clone();
                    let session_context = UdpSessionContext {
                        tun_networks: context.tun_networks,
                        proxy_dns: context.proxy_dns,
                        quic_policy,
                        netstack_tx: udp_tx.clone(),
                        udp_pool: context.udp_pool.clone(),
                        direct_checker: context.direct_checker.clone(),
                        direct_domain_cache: context.direct_domain_cache.clone(),
                        shutdown: shutdown.clone(),
                    };
                    spawn_guarded("android tun udp direct flow", async move {
                        if let Err(e) = handle_tun_udp(source, target, rx, session_context).await {
                            debug!("Android TUN UDP direct session ended: {e}");
                        }
                        sessions_c.remove(&key);
                    });
                }
            }
        }
        debug!("android UDP session task exited");
    })
}

fn spawn_quic_udp_stats_logger(stats: Arc<QuicUdpStats>, shutdown: CancellationToken) {
    spawn_guarded("android quic udp stats", async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = interval.tick() => {
                    let snapshot = stats.snapshot_and_reset();
                    if snapshot.observed > 0 {
                        debug!(
                            "Android TUN UDP/443 QUIC stats: observed={} direct={} proxied={} blocked={}",
                            snapshot.observed,
                            snapshot.direct,
                            snapshot.proxied,
                            snapshot.blocked
                        );
                    }
                }
            }
        }
    });
}

pub(super) async fn handle_tun_udp(
    client: SocketAddr,
    target: SocketAddr,
    mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    context: UdpSessionContext,
) -> Result<()> {
    let UdpSessionContext {
        tun_networks,
        proxy_dns,
        quic_policy,
        netstack_tx,
        udp_pool,
        direct_checker,
        direct_domain_cache,
        shutdown,
    } = context;

    let (address, proxy_dns_request) = address_for_tun_target(target, proxy_dns);
    if !proxy_dns_request {
        if tun_networks.is_ipv4_broadcast(target.ip()) {
            debug!("Android TUN UDP broadcast dropped -> {}", target);
            drain_dropped_udp(rx, shutdown).await;
            return Ok(());
        }
        if is_tun_local_udp_target(client, target, tun_networks) {
            debug!(
                "Android TUN UDP local network noise dropped: {} -> {}",
                client, target
            );
            drain_dropped_udp(rx, shutdown).await;
            return Ok(());
        }
        reject_tun_target("UDP", client, target, tun_networks)?;
    }
    let target_label = if proxy_dns_request {
        format!("{target} -> proxy DNS")
    } else {
        target.to_string()
    };

    let mut direct_target = None;
    let mut direct_label = target_label.clone();
    let mut proxy_address = address.clone();
    let mut proxy_reason = None;
    if !proxy_dns_request {
        if direct_checker.is_direct(&address) {
            direct_target = Some(target);
        } else if let Some(domain) = direct_domain_cache
            .matching_domain_for_ip(target.ip(), |domain| {
                direct_checker.is_direct_domain(domain)
            })
        {
            debug!(
                "Android TUN UDP cached direct domain matched: {} ({})",
                target, domain
            );
            direct_label = format!("{} ({})", target_label, domain);
            direct_target = Some(target);
        }
    }

    if direct_target.is_none()
        && !proxy_dns_request
        && let Some(domain) = direct_domain_cache.matching_domain_for_ip(target.ip(), |_| true)
    {
        debug!(
            "Android TUN UDP cached proxy domain matched: {} ({})",
            target, domain
        );
        proxy_address = domain_address(&domain, target.port());
        proxy_reason = Some(format!("cached domain {domain}"));
    }

    if !proxy_dns_request
        && target.port() == 443
        && quic_policy.should_block_udp443(direct_target.is_some())
    {
        debug!(
            "Android TUN UDP/443 QUIC dropped by policy {:?} -> {}",
            quic_policy, target_label
        );
        drain_dropped_udp(rx, shutdown).await;
        return Ok(());
    }

    if let Some(connect_target) = direct_target {
        let target_str = address_to_string(&address);
        debug!("Android TUN UDP direct -> {}", target_str);
        android_log::info(format!(
            "Android TUN UDP DIRECT {target_str} -> {connect_target}"
        ));
        relay_direct_udp(
            client,
            target,
            connect_target,
            direct_label,
            rx,
            netstack_tx,
            shutdown,
        )
        .await?;
        return Ok(());
    }

    let proxy_label = proxy_target_label(&target_label, proxy_reason.as_deref());
    if proxy_dns_request {
        debug!("Android TUN UDP DNS -> proxy -> {}", target_label);
    } else {
        debug!("Android TUN UDP fallback proxy -> {}", proxy_label);
        android_log::info(format!("Android TUN UDP PROXY {proxy_label}"));
    }
    let proxy_io = match udp_pool
        .get_connected_stream(proxy_address, TransportProtocol::Udp)
        .await
    {
        Ok(proxy_io) => proxy_io,
        Err(e) => {
            android_log::error(format!(
                "Android TUN UDP PROXY connect failed {proxy_label}: {e}"
            ));
            return Err(e);
        }
    };
    let (mut reader, mut writer) = tokio::io::split(proxy_io);
    let idle_sleep = tokio::time::sleep(UDP_SESSION_IDLE);
    tokio::pin!(idle_sleep);
    let mut response_buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = &mut idle_sleep => {
                debug!("Android UDP proxy session idle; closing -> {}", target_label);
                break;
            }
            maybe_data = rx.recv() => {
                let Some(data) = maybe_data else {
                    break;
                };
                trace!(
                    "Android UDP proxy write -> {} bytes={}",
                    target_label,
                    data.len()
                );
                if let Err(e) = writer.write_all(&data).await {
                    debug!("Android UDP proxy write failed: {e}");
                    break;
                }
                if let Err(e) = writer.flush().await {
                    debug!("Android UDP proxy flush failed: {e}");
                    break;
                }
                idle_sleep.as_mut().reset(tokio::time::Instant::now() + UDP_SESSION_IDLE);
            }
            read = reader.read(&mut response_buf) => {
                match read {
                    Ok(0) => break,
                    Ok(n) => {
                        trace!(
                            "Android UDP proxy read <- {} bytes={} writeback {} -> {}",
                            target_label, n, target, client
                        );
                        let pkt = response_buf[..n].to_vec();
                        let mut tx = netstack_tx.lock().await;
                        if let Err(e) = tx.send((pkt, target, client)).await {
                            debug!("Android UDP proxy response writeback failed: {e}");
                            break;
                        }
                        idle_sleep.as_mut().reset(tokio::time::Instant::now() + UDP_SESSION_IDLE);
                    }
                    Err(e) => {
                        debug!("Android UDP proxy read failed: {e}");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

async fn relay_direct_udp(
    client: SocketAddr,
    original_target: SocketAddr,
    connect_target: SocketAddr,
    target_label: String,
    mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    netstack_tx: UdpWriter,
    shutdown: CancellationToken,
) -> Result<()> {
    let socket = bind_direct_udp(connect_target)?;
    socket.connect(connect_target).await?;
    let idle_sleep = tokio::time::sleep(UDP_SESSION_IDLE);
    tokio::pin!(idle_sleep);
    let mut response_buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = &mut idle_sleep => {
                debug!("Android UDP direct session idle; closing -> {}", target_label);
                break;
            }
            maybe_data = rx.recv() => {
                let Some(data) = maybe_data else {
                    break;
                };
                if let Err(e) = socket.send(&data).await {
                    debug!("Android UDP direct send failed: {e}");
                    break;
                }
                idle_sleep.as_mut().reset(tokio::time::Instant::now() + UDP_SESSION_IDLE);
            }
            received = socket.recv(&mut response_buf) => {
                match received {
                    Ok(n) => {
                        let pkt = response_buf[..n].to_vec();
                        let mut tx = netstack_tx.lock().await;
                        if let Err(e) = tx.send((pkt, original_target, client)).await {
                            debug!("Android UDP direct response writeback failed: {e}");
                            break;
                        }
                        idle_sleep.as_mut().reset(tokio::time::Instant::now() + UDP_SESSION_IDLE);
                    }
                    Err(e) => {
                        debug!("Android UDP direct receive failed: {e}");
                        break;
                    }
                }
            }
        }
    }
    debug!("Android TUN UDP direct relay ended -> {}", target_label);
    Ok(())
}

fn bind_direct_udp(target: SocketAddr) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(
        Domain::for_address(target),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    protect_direct_socket(&socket)?;
    tune_direct_udp_socket(&socket, target);

    let bind_addr = if target.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    socket.bind(&SockAddr::from(bind_addr))?;
    socket.set_nonblocking(true)?;

    UdpSocket::from_std(socket.into())
}

fn tune_direct_udp_socket(socket: &Socket, target: SocketAddr) {
    if let Err(err) = socket.set_recv_buffer_size(crate::config::ANDROID_SOCKET_BUFFER_SIZE) {
        debug!("Android TUN UDP direct recv buffer setup failed target={target}: {err}");
    }
    if let Err(err) = socket.set_send_buffer_size(crate::config::ANDROID_SOCKET_BUFFER_SIZE) {
        debug!("Android TUN UDP direct send buffer setup failed target={target}: {err}");
    }
}

fn protect_direct_socket(socket: &Socket) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;

        crate::socket_protector::protect_fd(socket.as_raw_fd())
    }

    #[cfg(not(unix))]
    {
        let _ = socket;
        Ok(())
    }
}

async fn drain_dropped_udp(
    mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            received = timeout(Duration::from_secs(10), rx.recv()) => {
                if !matches!(received, Ok(Some(_))) {
                    break;
                }
            }
        }
    }
}

fn domain_address(domain: &str, port: u16) -> Address {
    Address::Domain {
        host: domain.to_string(),
        port,
    }
}

fn proxy_target_label(target_label: &str, reason: Option<&str>) -> String {
    match reason {
        Some(reason) => format!("{reason}, original {target_label}"),
        None => target_label.to_string(),
    }
}
