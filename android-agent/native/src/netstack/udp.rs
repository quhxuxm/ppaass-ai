use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use common::{QuicPolicy, QuicUdpStats, dns::is_dns_query_packet, spawn_guarded};
use futures::StreamExt;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::HashMap;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};
use tokio_util::sync::CancellationToken;
use tracing::debug;

use super::ForwardContext;
use super::direct_domain_cache::DirectDomainCache;
use super::dns_proxy::DnsProxy;
use super::dns_proxy::parse_dns_query;
use super::network::{
    TunNetworks, address_for_tun_target, is_tun_local_udp_target, reject_tun_target,
};
use super::udp_relay::UdpRelay;
use super::udp_writer::UdpWriter;
use crate::direct_access::DirectAccessChecker;
use crate::error::{AndroidAgentError, Result};
use crate::yamux_session::AndroidYamuxSessionManager;

type UdpSessionKey = (SocketAddr, SocketAddr);
type UdpSessionTx = tokio::sync::mpsc::Sender<Vec<u8>>;
type UdpSessions = HashMap<UdpSessionKey, UdpSessionTx>;

const UDP_SESSION_IDLE: Duration = Duration::from_secs(60);
const DIRECT_UDP_SESSION_CHANNEL_SIZE: usize = 256;

mod proxy;
use proxy::{ProxyUdpRelayContext, relay_proxy_udp};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpRoute {
    Direct,
    Proxy,
    Block,
}

#[derive(Clone)]
pub(super) struct UdpSessionContext {
    pub(super) tun_networks: TunNetworks,
    pub(super) proxy_dns: bool,
    pub(super) force_direct: bool,
    pub(super) close_after_response: bool,
    pub(super) quic_policy: QuicPolicy,
    pub(super) netstack_tx: UdpWriter,
    pub(super) udp_sessions: Arc<AndroidYamuxSessionManager>,
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
        let udp_tx = UdpWriter::spawn(udp_tx, shutdown.clone());
        // The dispatcher owns the map; flow tasks send completion notices.
        // This removes a DashMap shard lock from every proxied UDP packet.
        let mut sessions = UdpSessions::new();
        let (session_closed_tx, mut session_closed_rx) = tokio::sync::mpsc::unbounded_channel();
        let dns_proxy = context
            .proxy_dns
            .then(|| DnsProxy::spawn(context.clone(), udp_tx.clone(), shutdown.clone()));
        let udp_relay = UdpRelay::spawn(context.clone(), udp_tx.clone(), shutdown.clone());
        let quic_stats = Arc::new(QuicUdpStats::default());
        spawn_quic_udp_stats_logger(quic_stats.clone(), shutdown.clone());

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                closed = session_closed_rx.recv() => {
                    if let Some(key) = closed {
                        sessions.remove(&key);
                    }
                }
                message = udp_rx.next() => {
                    let Some((data, source, target)) = message else { break };
                    // 只有端口 53 且 payload 能解析成标准 DNS 查询时才进入 DnsProxy。
                    // 非 DNS 的 UDP/53 必须继续按普通 UDP 转发，避免被 DNS ID 改写和缓存逻辑误处理。
                    let is_dns_query = target.port() == 53 && is_dns_query_packet(&data);
                    let is_dns_proxy_query = context.proxy_dns && is_dns_query;
                    let mut force_dns_direct = false;
                    if is_dns_proxy_query {
                        let direct_domain = parse_dns_query(&data)
                            .is_some_and(|(domain, _)| context.direct_checker.is_direct_domain(&domain));
                        if direct_domain {
                            force_dns_direct = true;
                        } else {
                            if let Some(dns_proxy) = &dns_proxy {
                                dns_proxy.send(source, target, data);
                            }
                            continue;
                        }
                    }
                    if !force_dns_direct && !context.proxy_dns
                        && target.port() == 53 && is_dns_query_packet(&data)
                    {
                        force_dns_direct = true;
                    }

                    // 上面已经消化了真实 DNS 查询；没有通过 DNS 校验的 UDP/53
                    // 不能再启用 proxy_dns 虚拟地址映射。
                    let (address, _) = address_for_tun_target(target, false);
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
                    if let Some(tx) = sessions.get(&key).cloned() {
                        if target.port() == 443 {
                            quic_stats.record_direct();
                        }
                        if tx.try_send(data).is_err() {
                            debug!("Android TUN UDP direct session queue is full; dropping packet -> {}", target);
                        }
                        continue;
                    }

                    let mut direct_match =
                        force_dns_direct || context.direct_checker.is_direct(&address);
                    let proxy_address = address.clone();
                    if !direct_match {
                        // UDP/QUIC 代理目标保持原始 IP；只有域名规则可能改判直连时，
                        // 才需要查 DNS cache。这样可以避免 proxy 端重新 DNS 到不同
                        // CDN 边缘节点，减少 HTTP/3 视频播放抖动。
                        if context.direct_checker.has_domain_direct_rules()
                            && context
                                .direct_domain_cache
                                .matching_domain_for_ip(target.ip(), |domain| {
                                context.direct_checker.is_direct_domain(domain)
                            })
                            .is_some()
                        {
                            direct_match = true;
                        }
                    }

                    match classify_udp_route(
                        target.port(),
                        quic_policy,
                        direct_match,
                    ) {
                        UdpRoute::Block => {
                            quic_stats.record_blocked();
                            debug!(
                                "Android TUN UDP/443 QUIC blocked by explicit policy {:?} -> {}; waiting for TCP/TLS fallback",
                                quic_policy,
                                target
                            );
                            continue;
                        }
                        UdpRoute::Proxy => {
                            if target.port() == 443 {
                                quic_stats.record_proxied();
                            }
                            udp_relay.send(source, target, proxy_address, data);
                            continue;
                        }
                        UdpRoute::Direct => {
                            if target.port() == 443 {
                                quic_stats.record_direct();
                            }
                        }
                    }
                    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(
                        DIRECT_UDP_SESSION_CHANNEL_SIZE,
                    );
                    sessions.insert(key, tx.clone());
                    let _ = tx.try_send(data);

                    let session_closed_tx = session_closed_tx.clone();
                    let session_context = UdpSessionContext {
                        tun_networks: context.tun_networks,
                        // 普通 UDP 会话内部不再处理 proxy_dns，防止二次映射到 Address::ProxyDns。
                        proxy_dns: false,
                        // This task exists only after the ingress classifier selected Direct.
                        force_direct: true,
                        // DNS uses a fresh client source port frequently. Close these
                        // one-shot sockets promptly and cap them in the relay.
                        close_after_response: is_dns_query,
                        quic_policy,
                        netstack_tx: udp_tx.clone(),
                        udp_sessions: context.udp_sessions.clone(),
                        direct_checker: context.direct_checker.clone(),
                        direct_domain_cache: context.direct_domain_cache.clone(),
                        shutdown: shutdown.clone(),
                    };
                    spawn_guarded("android tun udp direct flow", async move {
                        if let Err(e) = handle_tun_udp(source, target, rx, session_context).await {
                            debug!("Android TUN UDP direct session ended: {e}");
                        }
                        let _ = session_closed_tx.send(key);
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
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    context: UdpSessionContext,
) -> Result<()> {
    let UdpSessionContext {
        tun_networks,
        proxy_dns,
        force_direct,
        close_after_response,
        quic_policy,
        netstack_tx,
        udp_sessions,
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

    let mut direct_target = (!proxy_dns_request && force_direct).then_some(target);
    let mut direct_label = target_label.clone();
    let proxy_address = address.clone();
    let mut proxy_reason = None;
    if direct_target.is_none() && !proxy_dns_request {
        if direct_checker.is_direct(&address) {
            direct_target = Some(target);
        } else if direct_checker.has_domain_direct_rules()
            && let Some(domain_match) = direct_domain_cache
                .matching_domain_for_ip(target.ip(), |domain| {
                    direct_checker.is_direct_domain(domain)
                })
        {
            debug!(
                "Android TUN UDP cached direct domain matched: {} ({}){}",
                target,
                domain_match.domain(),
                if domain_match.is_stale() {
                    " [stale]"
                } else {
                    ""
                }
            );
            direct_label = format!("{} ({})", target_label, domain_match.domain());
            direct_target = Some(target);
        }
    }

    if direct_target.is_none()
        && !proxy_dns_request
        && let Some(domain_match) =
            direct_domain_cache.matching_domain_for_ip(target.ip(), |_| true)
    {
        let domain = domain_match.into_domain();
        debug!(
            "Android TUN UDP cached proxy domain matched for label only: {} ({})，proxy target keeps original IP",
            target, domain
        );
        proxy_reason = Some(format!("cached domain {domain}"));
    }

    let route = classify_udp_route(target.port(), quic_policy, direct_target.is_some());
    if route == UdpRoute::Block {
        debug!(
            "Android TUN UDP/443 QUIC blocked by explicit policy {:?} -> {}; waiting for TCP/TLS fallback",
            quic_policy, target_label
        );
        drain_dropped_udp(rx, shutdown).await;
        return Ok(());
    }

    if route == UdpRoute::Direct
        && let Some(connect_target) = direct_target
    {
        debug!("Android TUN UDP direct -> {}", target_label);
        relay_direct_udp(
            client,
            target,
            connect_target,
            direct_label,
            rx,
            netstack_tx,
            close_after_response,
            shutdown,
        )
        .await?;
        return Ok(());
    }

    let proxy_label = proxy_target_label(&target_label, proxy_reason.as_deref());
    relay_proxy_udp(ProxyUdpRelayContext {
        client,
        target,
        target_label,
        proxy_label,
        proxy_dns_request,
        proxy_address,
        rx,
        netstack_tx,
        udp_sessions,
        shutdown,
    })
    .await
}

mod routing;
pub use routing::classify_udp_route;
pub(super) use routing::tune_direct_udp_socket;
use routing::{drain_dropped_udp, proxy_target_label, relay_direct_udp};
