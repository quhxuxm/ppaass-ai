use super::TunForwardContext;
use super::dns_proxy::DnsProxy;
use super::network::{address_for_tun_target, is_tun_local_udp_target, reject_tun_target};
use super::tcp::handle_tun_tcp;
use super::udp::handle_tun_udp;
use super::udp_relay::UdpRelay;
use common::spawn_guarded;
use futures::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};

use super::udp::UdpSessionContext;

type UdpSessionKey = (SocketAddr, SocketAddr);
type UdpSessionTx = tokio::sync::mpsc::Sender<Vec<u8>>;
type UdpSessions = Arc<dashmap::DashMap<UdpSessionKey, UdpSessionTx>>;

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
    block_quic: bool,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    spawn_guarded("desktop udp sessions", async move {
        // UDP 以五元组近似会话化，同一 source/target 复用一个处理任务。
        let (mut udp_rx, udp_tx) = udp_socket.split();
        let udp_tx = Arc::new(tokio::sync::Mutex::new(udp_tx));
        let sessions: UdpSessions = Arc::new(dashmap::DashMap::new());
        let dns_proxy = context
            .proxy_dns
            .then(|| {
                DnsProxy::spawn(
                    context.udp_pool.clone(),
                    udp_tx.clone(),
                    context.direct_domain_cache.clone(),
                    shutdown.clone(),
                )
            });
        let udp_relay = UdpRelay::spawn(context.udp_pool.clone(), udp_tx.clone(), shutdown.clone());

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                msg = udp_rx.next() => {
                    let Some((data, source_addr, target_addr)) = msg else { break };
                    if context.proxy_dns && target_addr.port() == 53 {
                        if let Some(dns_proxy) = &dns_proxy {
                            dns_proxy.send(source_addr, target_addr, data);
                        }
                        continue;
                    }

                    let (address, _) = address_for_tun_target(target_addr, context.proxy_dns);
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
                    if block_quic && target_addr.port() == 443 {
                        debug!("TUN UDP/443 QUIC 已阻断 -> {}", target_addr);
                        continue;
                    }

                    let mut direct_match = context.direct_checker.is_direct(&address);
                    if !direct_match
                        && let Some(domain) =
                            context.direct_domain_cache.domain_for_ip(target_addr.ip())
                    {
                        direct_match = context.direct_checker.is_direct_domain(&domain);
                    }

                    if !direct_match {
                        udp_relay.send(source_addr, target_addr, data);
                        continue;
                    }

                    let key = (source_addr, target_addr);
                    // 已存在会话时只把新 payload 投递给该会话任务。
                    if let Some(tx) = sessions.get(&key).map(|t| t.clone()) {
                        if tx.try_send(data).is_err() {
                            debug!("TUN UDP 会话队列已满，丢弃一个 UDP 包 -> {}", target_addr);
                        }
                        continue;
                    }

                    // 新会话先入表，再发送首包，避免首包在任务启动前丢失。
                    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
                    sessions.insert(key, tx.clone());
                    let _ = tx.try_send(data);

                    let sessions_c = sessions.clone();
                    let context = UdpSessionContext {
                        tun_networks: context.tun_networks,
                        proxy_dns: context.proxy_dns,
                        block_quic,
                        netstack_tx: udp_tx.clone(),
                        udp_pool: context.udp_pool.clone(),
                        direct_checker: context.direct_checker.clone(),
                        direct_domain_cache: context.direct_domain_cache.clone(),
                        direct_bind_interface: context.direct_bind_interface.clone(),
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
