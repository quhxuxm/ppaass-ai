//! TUN netstack 的任务分发。
//!
//! 这里把原始 TUN 包桥接到用户态协议栈，并把协议栈产出的 TCP/UDP 流分发到
//! `handle_tun_tcp`、`handle_tun_udp`、DNS proxy 或共享 UDP relay。

use super::TunForwardContext;

mod packet_bridge;

use super::dns_proxy::DnsProxy;
use super::dns_proxy::parse_dns_query;
use super::network::{address_for_tun_target, is_tun_local_udp_target, reject_tun_target};
use super::tcp::handle_tun_tcp;
use super::udp::UdpSessionContext;
use super::udp::handle_tun_udp;
use super::udp_relay::UdpRelay;
use super::udp_writer::UdpWriter;
use common::{QuicPolicy, QuicUdpStats, dns::is_dns_query_packet, spawn_guarded};
use futures::StreamExt;
pub(super) use packet_bridge::spawn_packet_bridge;
pub use packet_bridge::tun_packet_is_safe_for_netstack;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

type UdpSessionKey = (SocketAddr, SocketAddr);
type UdpSessionTx = tokio::sync::mpsc::Sender<Vec<u8>>;
type UdpSessions = HashMap<UdpSessionKey, UdpSessionTx>;
const DIRECT_UDP_SESSION_CHANNEL_SIZE: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpRoute {
    Direct,
    Proxy,
    Block,
}

pub(super) fn spawn_tcp_listener(
    mut tcp_listener: netstack_smoltcp::TcpListener,
    context: TunForwardContext,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    spawn_guarded("desktop tcp listener", async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                accepted = tcp_listener.next() => {
                    // 每条 TUN TCP 流独立转发，避免慢连接阻塞后续 accept。
                    let Some((stream, source_addr, target_addr)) = accepted else { break };
                    debug!("TUN TCP {} -> {}", source_addr, target_addr);
                    let context = context.clone();
                    spawn_guarded("desktop tun tcp flow", async move {
                        if let Err(e) =
                            handle_tun_tcp(
                                stream,
                                source_addr,
                                target_addr,
                                context,
                            ).await
                        {
                            debug!("TUN TCP 流结束：{e}");
                        }
                    });
                }
            }
        }
        debug!("tcp_task 退出");
    })
}

pub(super) fn spawn_udp_sessions(
    udp_socket: netstack_smoltcp::UdpSocket,
    context: TunForwardContext,
    quic_policy: QuicPolicy,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    spawn_guarded("desktop udp sessions", async move {
        // UDP 以五元组近似会话化，同一 source/target 复用一个处理任务。
        let (mut udp_rx, udp_tx) = udp_socket.split();
        let udp_tx = UdpWriter::spawn(udp_tx, shutdown.clone());
        // Only this dispatcher mutates the map. Flow tasks report completion
        // through a channel, avoiding a DashMap shard lock on every UDP packet.
        let mut sessions = UdpSessions::new();
        let (session_closed_tx, mut session_closed_rx) = tokio::sync::mpsc::unbounded_channel();
        // DNS 请求单独走 DnsProxy：它会维护 DNS ID 映射并记录域名解析缓存。
        let dns_proxy = context.proxy_dns.then(|| {
            DnsProxy::spawn(
                context.udp_sessions.clone(),
                udp_tx.clone(),
                context.direct_domain_cache.clone(),
                shutdown.clone(),
            )
        });
        // proxy_udp 只控制普通 UDP。quic_policy=allow 时，即使普通 UDP
        // 被配置为直连，仍需要 relay 承载未命中 direct_access 的 UDP/443。
        let udp_relay = should_start_udp_relay(context.proxy_udp, quic_policy).then(|| {
            UdpRelay::spawn(
                context.udp_sessions.clone(),
                udp_tx.clone(),
                shutdown.clone(),
            )
        });
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
                msg = udp_rx.next() => {
                    let Some((data, source_addr, target_addr)) = msg else { break };
                    // 只有端口和 DNS 协议结构都匹配时才进入 DnsProxy。
                    // 部分应用会把非 DNS UDP 流量发到 53 端口，单靠端口判断会误把它们
                    // 送进 DNS ID 改写/缓存逻辑，最终表现为 UDP 会话无响应或被错误关闭。
                    let is_dns_proxy_query =
                        context.proxy_dns && target_addr.port() == 53 && is_dns_query_packet(&data);
                    let mut force_dns_direct = false;
                    if is_dns_proxy_query {
                        let direct_domain = parse_dns_query(&data)
                            .is_some_and(|(domain, _)| context.direct_checker.is_direct_domain(&domain));
                        if direct_domain {
                            force_dns_direct = true;
                        } else {
                            if let Some(dns_proxy) = &dns_proxy {
                                dns_proxy.send(source_addr, target_addr, data);
                            }
                            continue;
                        }
                    }
                    if !force_dns_direct && !context.proxy_dns
                        && target_addr.port() == 53 && is_dns_query_packet(&data)
                    {
                        force_dns_direct = true;
                    }

                    // 未通过 DNS 解析校验的 UDP/53 继续按普通 UDP 处理，不能再启用
                    // proxy_dns 虚拟地址映射，否则 address_for_tun_target 会再次把它
                    // 转成 Address::ProxyDns。
                    let (address, _) = address_for_tun_target(target_addr, false);
                    if context.tun_networks.is_ipv4_broadcast(target_addr.ip()) {
                        debug!("TUN UDP 广播已丢弃 -> {}", target_addr);
                        continue;
                    }
                    if is_tun_local_udp_target(source_addr, target_addr, context.tun_networks) {
                        debug!(
                            "TUN UDP 本地网段流量已丢弃：{} -> {}",
                            source_addr, target_addr
                        );
                        continue;
                    }
                    if let Err(e) = reject_tun_target(
                        "UDP",
                        source_addr,
                        target_addr,
                        context.tun_networks,
                    ) {
                        debug!("TUN UDP 目标已拒绝：{e}");
                        continue;
                    }

                    let key = (source_addr, target_addr);
                    // 已存在的 direct 会话优先复用，避免域名缓存过期后把同一 UDP 流切到 proxy。
                    if let Some(tx) = sessions.get(&key).cloned() {
                        if target_addr.port() == 443 {
                            quic_stats.record_direct();
                        }
                        if tx.try_send(data).is_err() {
                            debug!("TUN UDP 会话队列已满，丢弃一个 UDP 包 -> {}", target_addr);
                        }
                        continue;
                    }

                    // 先独立计算 direct_access 结论。proxy_udp=false 只强制普通 UDP
                    // 直连，不能把本应经 proxy 的浏览器 QUIC 一并改成直连。
                    let mut direct_access_match =
                        force_dns_direct || context.direct_checker.is_direct(&address);
                    let proxy_address = address.clone();
                    if !direct_access_match
                        && should_consult_udp_domain_cache(context.proxy_udp, target_addr.port())
                    {
                        // 会参与 proxy/direct 分流的 UDP 才查询 DNS 记录的域名缓存。
                        // 非直连代理目标始终保留原始 IP，避免 proxy 端重新 DNS 到
                        // 不同 CDN 边缘节点后出现播放抖动。
                        if context.direct_checker.has_domain_direct_rules()
                            && context
                                .direct_domain_cache
                                .matching_domain_for_ip(target_addr.ip(), |domain| {
                                context.direct_checker.is_direct_domain(domain)
                            })
                            .is_some()
                        {
                            direct_access_match = true;
                        }
                    }

                    match classify_udp_route(
                        target_addr.port(),
                        quic_policy,
                        context.proxy_udp,
                        direct_access_match,
                    ) {
                        UdpRoute::Block => {
                            quic_stats.record_blocked();
                            debug!(
                                "TUN UDP/443 QUIC 已按显式策略 {:?} 阻断 -> {}",
                                quic_policy,
                                target_addr
                            );
                            continue;
                        }
                        UdpRoute::Proxy => {
                            if target_addr.port() == 443 {
                                quic_stats.record_proxied();
                            }
                            if let Some(udp_relay) = &udp_relay {
                                udp_relay.send(source_addr, target_addr, proxy_address, data);
                            } else {
                                warn!(
                                    "TUN UDP proxy relay 未启动，丢弃一个 UDP 包 -> {}",
                                    target_addr
                                );
                            }
                            continue;
                        }
                        UdpRoute::Direct => {}
                    }

                    if target_addr.port() == 443 {
                        quic_stats.record_direct();
                    }
                    // 新会话先入表，再发送首包，避免首包在任务启动前丢失。
                    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(
                        DIRECT_UDP_SESSION_CHANNEL_SIZE,
                    );
                    sessions.insert(key, tx.clone());
                    let _ = tx.try_send(data);

                    let session_closed_tx = session_closed_tx.clone();
                    let context = UdpSessionContext {
                        tun_networks: context.tun_networks,
                        // DNS 查询已经在上面的分流点单独处理；普通 UDP 会话必须关闭
                        // proxy_dns 标记，避免会话内部二次映射到 Address::ProxyDns。
                        proxy_dns: false,
                        // This task is created only after classify_udp_route returned Direct.
                        // Preserve that decision instead of repeating rule/cache lookups.
                        force_direct: true,
                        quic_policy,
                        netstack_tx: udp_tx.clone(),
                        tcp_sessions: context.tcp_sessions.clone(),
                        udp_sessions: context.udp_sessions.clone(),
                        direct_checker: context.direct_checker.clone(),
                        direct_domain_cache: context.direct_domain_cache.clone(),
                        direct_egress: context.direct_egress.clone(),
                        shutdown: shutdown.clone(),
                    };
                    spawn_guarded("desktop tun udp flow", async move {
                        // 会话任务结束后清理 map，下一包会重新建立会话。
                        if let Err(e) =
                            handle_tun_udp(
                                source_addr,
                                target_addr,
                                rx,
                                context,
                            ).await
                        {
                            debug!("TUN UDP 会话结束：{e}");
                        }
                        let _ = session_closed_tx.send(key);
                    });
                }
            }
        }
        debug!("udp_task 退出");
    })
}

pub fn classify_udp_route(
    target_port: u16,
    quic_policy: QuicPolicy,
    proxy_udp: bool,
    direct_access_match: bool,
) -> UdpRoute {
    if target_port == 443 {
        if quic_policy.should_block_udp443() {
            UdpRoute::Block
        } else if direct_access_match {
            UdpRoute::Direct
        } else {
            UdpRoute::Proxy
        }
    } else if !proxy_udp || direct_access_match {
        UdpRoute::Direct
    } else {
        UdpRoute::Proxy
    }
}

pub fn should_start_udp_relay(proxy_udp: bool, quic_policy: QuicPolicy) -> bool {
    proxy_udp || !quic_policy.should_block_udp443()
}

pub fn should_consult_udp_domain_cache(proxy_udp: bool, target_port: u16) -> bool {
    proxy_udp || target_port == 443
}

fn spawn_quic_udp_stats_logger(stats: Arc<QuicUdpStats>, shutdown: CancellationToken) {
    spawn_guarded("desktop quic udp stats", async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = interval.tick() => {
                    let snapshot = stats.snapshot_and_reset();
                    if snapshot.observed > 0 {
                        debug!(
                            "TUN UDP/443 QUIC 观测：observed={} direct={} proxied={} blocked={}",
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
