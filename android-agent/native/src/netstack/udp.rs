use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use common::spawn_guarded;
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

#[derive(Clone)]
pub(super) struct UdpSessionContext {
    pub(super) tun_networks: TunNetworks,
    pub(super) proxy_dns: bool,
    pub(super) block_quic: bool,
    pub(super) netstack_tx: UdpWriter,
    pub(super) udp_pool: Arc<AndroidConnectionPool>,
    pub(super) direct_checker: Arc<DirectAccessChecker>,
    pub(super) direct_domain_cache: Arc<DirectDomainCache>,
}

pub(super) fn spawn_udp_sessions(
    udp_socket: netstack_smoltcp::UdpSocket,
    context: ForwardContext,
    block_quic: bool,
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

                    if block_quic && target.port() == 443 && !direct_match {
                        debug!("Android TUN UDP/443 QUIC dropped -> {}", target);
                        continue;
                    }

                    if !direct_match {
                        udp_relay.send(source, target, proxy_address, data);
                        continue;
                    }

                    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
                    sessions.insert(key, tx.clone());
                    let _ = tx.try_send(data);

                    let sessions_c = sessions.clone();
                    let session_context = UdpSessionContext {
                        tun_networks: context.tun_networks,
                        proxy_dns: context.proxy_dns,
                        block_quic,
                        netstack_tx: udp_tx.clone(),
                        udp_pool: context.udp_pool.clone(),
                        direct_checker: context.direct_checker.clone(),
                        direct_domain_cache: context.direct_domain_cache.clone(),
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

pub(super) async fn handle_tun_udp(
    client: SocketAddr,
    target: SocketAddr,
    mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    context: UdpSessionContext,
) -> Result<()> {
    let UdpSessionContext {
        tun_networks,
        proxy_dns,
        block_quic,
        netstack_tx,
        udp_pool,
        direct_checker,
        direct_domain_cache,
    } = context;

    let (address, proxy_dns_request) = address_for_tun_target(target, proxy_dns);
    if !proxy_dns_request {
        if tun_networks.is_ipv4_broadcast(target.ip()) {
            debug!("Android TUN UDP broadcast dropped -> {}", target);
            drain_dropped_udp(rx).await;
            return Ok(());
        }
        if is_tun_local_udp_target(client, target, tun_networks) {
            debug!(
                "Android TUN UDP local network noise dropped: {} -> {}",
                client, target
            );
            drain_dropped_udp(rx).await;
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

    if block_quic && !proxy_dns_request && target.port() == 443 && direct_target.is_none() {
        debug!("Android TUN UDP/443 QUIC dropped -> {}", target_label);
        drain_dropped_udp(rx).await;
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

    let write_target = target_label.clone();
    let write = async move {
        while let Some(data) = rx.recv().await {
            trace!(
                "Android UDP proxy write -> {} bytes={}",
                write_target,
                data.len()
            );
            if let Err(e) = writer.write_all(&data).await {
                debug!("Android UDP proxy write failed: {e}");
                break;
            }
            let _ = writer.flush().await;
        }
    };

    let netstack_tx_r = netstack_tx.clone();
    let read_target = target_label.clone();
    let read = async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    trace!(
                        "Android UDP proxy read <- {} bytes={} writeback {} -> {}",
                        read_target, n, target, client
                    );
                    let pkt = buf[..n].to_vec();
                    let mut tx = netstack_tx_r.lock().await;
                    if let Err(e) = tx.send((pkt, target, client)).await {
                        debug!("Android UDP proxy response writeback failed: {e}");
                        break;
                    }
                }
                Err(e) => {
                    debug!("Android UDP proxy read failed: {e}");
                    break;
                }
            }
        }
    };

    tokio::select! {
        _ = write => {}
        _ = read => {}
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
) -> Result<()> {
    let socket = bind_direct_udp(connect_target)?;
    socket.connect(connect_target).await?;
    let socket = Arc::new(socket);

    let socket_w = socket.clone();
    let write = async move {
        while let Some(data) = rx.recv().await {
            if let Err(e) = socket_w.send(&data).await {
                debug!("Android UDP direct send failed: {e}");
                break;
            }
        }
    };

    let netstack_tx_r = netstack_tx.clone();
    let read = async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match socket.recv(&mut buf).await {
                Ok(n) => {
                    let pkt = buf[..n].to_vec();
                    let mut tx = netstack_tx_r.lock().await;
                    if let Err(e) = tx.send((pkt, original_target, client)).await {
                        debug!("Android UDP direct response writeback failed: {e}");
                        break;
                    }
                }
                Err(e) => {
                    debug!("Android UDP direct receive failed: {e}");
                    break;
                }
            }
        }
    };

    tokio::select! {
        _ = write => {}
        _ = read => {}
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

    let bind_addr = if target.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    socket.bind(&SockAddr::from(bind_addr))?;
    socket.set_nonblocking(true)?;

    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket)
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

async fn drain_dropped_udp(mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>) {
    while let Ok(Some(_)) = timeout(Duration::from_secs(10), rx.recv()).await {}
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
