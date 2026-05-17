use super::network::TunNetworks;
use super::tcp::handle_tun_tcp;
use super::udp::handle_tun_udp;
use crate::connection_pool::ConnectionPool;
use crate::direct_access::DirectAccessChecker;
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
    let (mut stack_sink, mut stack_stream) = stack.split();

    let device_in = device.clone();
    let shutdown_in = shutdown.clone();
    let tun_to_stack = tokio::spawn(async move {
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
    let stack_to_tun = tokio::spawn(async move {
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
    pool: Arc<ConnectionPool>,
    direct_checker: Arc<DirectAccessChecker>,
    tun_networks: TunNetworks,
    proxy_dns: bool,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                accepted = tcp_listener.next() => {
                    let Some((stream, source_addr, target_addr)) = accepted else { break };
                    debug!("TUN TCP {} -> {}", source_addr, target_addr);
                    let pool = pool.clone();
                    let checker = direct_checker.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_tun_tcp(
                                stream,
                                source_addr,
                                target_addr,
                                tun_networks,
                                proxy_dns,
                                pool,
                                checker,
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
    pool: Arc<ConnectionPool>,
    direct_checker: Arc<DirectAccessChecker>,
    tun_networks: TunNetworks,
    proxy_dns: bool,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let (mut udp_rx, udp_tx) = udp_socket.split();
        let udp_tx = Arc::new(tokio::sync::Mutex::new(udp_tx));
        let sessions: UdpSessions = Arc::new(dashmap::DashMap::new());

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                msg = udp_rx.next() => {
                    let Some((data, source_addr, target_addr)) = msg else { break };
                    let key = (source_addr, target_addr);
                    if let Some(tx) = sessions.get(&key).map(|t| t.clone()) {
                        let _ = tx.send(data).await;
                        continue;
                    }

                    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
                    sessions.insert(key, tx.clone());
                    let _ = tx.send(data).await;

                    let pool = pool.clone();
                    let checker = direct_checker.clone();
                    let sessions_c = sessions.clone();
                    let context = UdpSessionContext {
                        tun_networks,
                        proxy_dns,
                        netstack_tx: udp_tx.clone(),
                        pool,
                        direct_checker: checker,
                    };
                    tokio::spawn(async move {
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
