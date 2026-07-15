//! TUN netstack 的任务分发。
//!
//! 这里把原始 TUN 包桥接到用户态协议栈，并把协议栈产出的 TCP/UDP 流分发到
//! `handle_tun_tcp`、`handle_tun_udp`、DNS proxy 或共享 UDP relay。

use super::TunForwardContext;
use super::dns_proxy::DnsProxy;
use super::network::{address_for_tun_target, is_tun_local_udp_target, reject_tun_target};
use super::tcp::handle_tun_tcp;
use super::udp::handle_tun_udp;
use super::udp_relay::UdpRelay;
use common::{QuicPolicy, QuicUdpStats, dns::is_dns_query_packet, spawn_guarded};
use futures::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};

use super::udp::UdpSessionContext;

type UdpSessionKey = (SocketAddr, SocketAddr);
type UdpSessionTx = tokio::sync::mpsc::Sender<Vec<u8>>;
type UdpSessions = Arc<dashmap::DashMap<UdpSessionKey, UdpSessionTx>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpRoute {
    Direct,
    Proxy,
    Block,
}

pub(super) fn spawn_packet_bridge(
    device: Arc<tun_rs::AsyncDevice>,
    stack: netstack_smoltcp::Stack,
    mtu: usize,
    shutdown: CancellationToken,
) -> (JoinHandle<()>, JoinHandle<()>) {
    // stack.split() 得到 TUN 包进入协议栈和协议栈包写回 TUN 的两个方向。
    let (mut stack_sink, mut stack_stream) = stack.split();

    let device_in = device.clone();
    let shutdown_in = shutdown.clone();
    let tun_to_stack = spawn_guarded("desktop tun_to_stack", async move {
        // TUN -> netstack：读取系统注入的 IP 包并交给用户态协议栈处理。
        let mut buf = vec![0u8; mtu.max(1500) + 64];
        loop {
            tokio::select! {
                _ = shutdown_in.cancelled() => break,
                read = device_in.recv(&mut buf) => {
                    match read {
                        Ok(n) if n > 0 => {
                            let pkt = buf[..n].to_vec();
                            if let Err(e) = stack_sink.send(pkt).await {
                                warn!("向 netstack 推送数据包失败：{e}");
                                break;
                            }
                        }
                        Ok(_) => continue,
                        Err(e) => {
                            error!("TUN 读取错误：{e}");
                            break;
                        }
                    }
                }
            }
        }
        debug!("tun_to_stack 任务退出");
    });

    let device_out = device;
    let shutdown_out = shutdown;
    let stack_to_tun = spawn_guarded("desktop stack_to_tun", async move {
        // netstack -> TUN：协议栈生成的响应包写回虚拟网卡。
        loop {
            tokio::select! {
                _ = shutdown_out.cancelled() => break,
                pkt = stack_stream.next() => {
                    match pkt {
                        Some(Ok(pkt)) => {
                            if let Err(e) = device_out.send(&pkt).await {
                                warn!("向 TUN 设备写入数据包失败：{e}");
                                break;
                            }
                        }
                        Some(Err(e)) => {
                            warn!("netstack 流错误：{e}");
                        }
                        None => break,
                    }
                }
            }
        }
        debug!("stack_to_tun 任务退出");
    });

    (tun_to_stack, stack_to_tun)
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
        let udp_tx = Arc::new(tokio::sync::Mutex::new(udp_tx));
        let sessions: UdpSessions = Arc::new(dashmap::DashMap::new());
        // DNS 请求单独走 DnsProxy：它会维护 DNS ID 映射并记录域名解析缓存。
        let dns_proxy = context.proxy_dns.then(|| {
            DnsProxy::spawn(
                context.udp_sessions.clone(),
                udp_tx.clone(),
                context.direct_domain_cache.clone(),
                shutdown.clone(),
            )
        });
        // proxy_udp 只控制普通 UDP。外层是 QUIC 时，不再为代理 UDP/443 单独启动
        // 可靠 stream relay，避免 QUIC-over-QUIC 队头阻塞。
        let udp_relay =
            should_start_udp_relay(context.proxy_udp, quic_policy, context.outer_transport_quic)
                .then(|| {
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
                msg = udp_rx.next() => {
                    let Some((data, source_addr, target_addr)) = msg else { break };
                    // 只有端口和 DNS 协议结构都匹配时才进入 DnsProxy。
                    // 部分应用会把非 DNS UDP 流量发到 53 端口，单靠端口判断会误把它们
                    // 送进 DNS ID 改写/缓存逻辑，最终表现为 UDP 会话无响应或被错误关闭。
                    let is_dns_proxy_query =
                        context.proxy_dns && target_addr.port() == 53 && is_dns_query_packet(&data);
                    if is_dns_proxy_query {
                        if let Some(dns_proxy) = &dns_proxy {
                            dns_proxy.send(source_addr, target_addr, data);
                        }
                        continue;
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
                    if let Some(tx) = sessions.get(&key).map(|t| t.clone()) {
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
                    let mut direct_access_match = context.direct_checker.is_direct(&address);
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
                        context.outer_transport_quic,
                    ) {
                        UdpRoute::Block => {
                            quic_stats.record_blocked();
                            debug!(
                                "TUN UDP/443 QUIC 已阻断（策略={:?} outer_quic={}）-> {}，等待应用回退 TCP/TLS",
                                quic_policy,
                                context.outer_transport_quic,
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
                    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
                    sessions.insert(key, tx.clone());
                    let _ = tx.try_send(data);

                    let sessions_c = sessions.clone();
                    let context = UdpSessionContext {
                        tun_networks: context.tun_networks,
                        // DNS 查询已经在上面的分流点单独处理；普通 UDP 会话必须关闭
                        // proxy_dns 标记，避免会话内部二次映射到 Address::ProxyDns。
                        proxy_dns: false,
                        force_direct: !context.proxy_udp,
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
                        sessions_c.remove(&key);
                    });
                }
            }
        }
        debug!("udp_task 退出");
    })
}

fn classify_udp_route(
    target_port: u16,
    quic_policy: QuicPolicy,
    proxy_udp: bool,
    direct_access_match: bool,
    outer_transport_quic: bool,
) -> UdpRoute {
    if target_port == 443 {
        if quic_policy.should_block_udp443() {
            UdpRoute::Block
        } else if direct_access_match {
            UdpRoute::Direct
        } else if outer_transport_quic {
            // 代理 UDP 当前承载在可靠有序的目标 stream 上。内层 HTTP/3/QUIC
            // 套在外层 QUIC stream 上会产生跨层重传和队头阻塞；丢弃首包后，
            // 浏览器会按 Happy Eyeballs/Alt-Svc 逻辑回退到 TCP/TLS。
            UdpRoute::Block
        } else {
            UdpRoute::Proxy
        }
    } else if !proxy_udp || direct_access_match {
        UdpRoute::Direct
    } else {
        UdpRoute::Proxy
    }
}

fn should_start_udp_relay(
    proxy_udp: bool,
    quic_policy: QuicPolicy,
    outer_transport_quic: bool,
) -> bool {
    proxy_udp || (!quic_policy.should_block_udp443() && !outer_transport_quic)
}

fn should_consult_udp_domain_cache(proxy_udp: bool, target_port: u16) -> bool {
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

#[cfg(test)]
mod tests {
    use super::{
        UdpRoute, classify_udp_route, should_consult_udp_domain_cache, should_start_udp_relay,
    };
    use common::QuicPolicy;

    #[test]
    fn ordinary_udp_proxy_switch_preserves_old_routing_or_forces_direct() {
        assert_eq!(
            classify_udp_route(3478, QuicPolicy::Allow, true, false, true),
            UdpRoute::Proxy
        );
        assert_eq!(
            classify_udp_route(3478, QuicPolicy::Allow, true, true, true),
            UdpRoute::Direct
        );
        assert_eq!(
            classify_udp_route(3478, QuicPolicy::Allow, false, false, true),
            UdpRoute::Direct
        );
        assert_eq!(
            classify_udp_route(3478, QuicPolicy::Block, false, true, true),
            UdpRoute::Direct
        );
    }

    #[test]
    fn quic_allow_uses_proxy_only_when_outer_transport_is_tcp() {
        assert_eq!(
            classify_udp_route(443, QuicPolicy::Allow, false, false, false),
            UdpRoute::Proxy
        );
        assert_eq!(
            classify_udp_route(443, QuicPolicy::Allow, false, true, true),
            UdpRoute::Direct
        );
        assert_eq!(
            classify_udp_route(443, QuicPolicy::Allow, true, false, true),
            UdpRoute::Block
        );
    }

    #[test]
    fn explicit_quic_block_overrides_udp_and_direct_access_routing() {
        for proxy_udp in [false, true] {
            for direct_access_match in [false, true] {
                assert_eq!(
                    classify_udp_route(
                        443,
                        QuicPolicy::Block,
                        proxy_udp,
                        direct_access_match,
                        false,
                    ),
                    UdpRoute::Block
                );
            }
        }
    }

    #[test]
    fn relay_and_domain_cache_stay_available_for_quic() {
        assert!(should_start_udp_relay(false, QuicPolicy::Allow, false));
        assert!(!should_start_udp_relay(false, QuicPolicy::Allow, true));
        assert!(!should_start_udp_relay(false, QuicPolicy::Block, false));
        assert!(should_start_udp_relay(true, QuicPolicy::Block, true));

        assert!(should_consult_udp_domain_cache(false, 443));
        assert!(!should_consult_udp_domain_cache(false, 3478));
        assert!(should_consult_udp_domain_cache(true, 3478));
    }
}
