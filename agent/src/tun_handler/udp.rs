use super::network::{TunNetworks, address_for_tun_target, reject_tun_target};
use crate::connection_pool::ConnectionPool;
use crate::direct_access::{DirectAccessChecker, address_to_string};
use crate::error::Result;
use crate::telemetry;
use common::{BindInterface, bind_socket_to_interface};
use futures::SinkExt;
use protocol::TransportProtocol;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::{Duration, timeout};
use tracing::{debug, trace};

pub(super) type UdpWriter = Arc<tokio::sync::Mutex<netstack_smoltcp::udp::WriteHalf>>;

#[derive(Clone)]
pub(super) struct UdpSessionContext {
    pub(super) tun_networks: TunNetworks,
    pub(super) proxy_dns: bool,
    pub(super) block_quic: bool,
    pub(super) netstack_tx: UdpWriter,
    pub(super) pool: Arc<ConnectionPool>,
    pub(super) direct_checker: Arc<DirectAccessChecker>,
    pub(super) direct_bind_interface: Option<BindInterface>,
}

pub(super) async fn handle_tun_udp(
    client: SocketAddr,
    target: SocketAddr,
    mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    context: UdpSessionContext,
) -> Result<()> {
    // 将会话上下文拆出，后续分支可分别移动到读写任务里。
    let UdpSessionContext {
        tun_networks,
        proxy_dns,
        block_quic,
        netstack_tx,
        pool,
        direct_checker,
        direct_bind_interface,
    } = context;

    // UDP 目标同样先处理 proxy DNS 虚拟地址。
    let (address, proxy_dns_request) = address_for_tun_target(target, proxy_dns);
    if !proxy_dns_request {
        if tun_networks.is_ipv4_broadcast(target.ip()) {
            debug!("TUN UDP 广播已丢弃 -> {}", target);
            drain_dropped_udp(rx).await;
            return Ok(());
        }
        // 普通 UDP 目标不能指向 TUN 自身网段。
        reject_tun_target("UDP", client, target, tun_networks)?;
    }
    let target_label = if proxy_dns_request {
        format!("{target} -> proxy默认DNS")
    } else {
        target.to_string()
    };

    if block_quic && !proxy_dns_request && target.port() == 443 {
        debug!(
            "TUN UDP/443 QUIC 已阻断 -> {}，等待应用回退 TCP",
            target_label
        );
        drain_dropped_udp(rx).await;
        return Ok(());
    }

    if !proxy_dns_request && direct_checker.is_direct(&address) {
        // 直连 UDP 使用本地 UDP socket 与目标通信，回复写回 netstack。
        let target_str = address_to_string(&address);
        debug!("TUN UDP 直连 -> {}", target_str);
        relay_direct_udp(
            client,
            target,
            target_label,
            rx,
            netstack_tx,
            direct_bind_interface,
        )
        .await?;
        return Ok(());
    }

    // 代理 UDP 路径通过连接池建立一个 UDP 语义的 proxy stream。
    if proxy_dns_request {
        debug!("TUN UDP DNS -> 代理 -> {}", target_label);
    } else {
        debug!("TUN UDP -> 代理 -> {}", target_label);
    }
    let connected = pool
        .as_ref()
        .get_connected_stream(address, TransportProtocol::Udp)
        .await?;
    let proxy_io = connected.into_async_io();
    let (mut reader, mut writer) = tokio::io::split(proxy_io);

    // 写方向：同一 UDP 会话的 payload 从 channel 进入 proxy stream。
    let write_target = target_label.clone();
    let write = async move {
        while let Some(data) = rx.recv().await {
            trace!(
                "UDP 代理写入 payload -> {} bytes={}",
                write_target,
                data.len()
            );
            if let Err(e) = writer.write_all(&data).await {
                debug!("UDP 代理写入错误：{e}");
                break;
            }
            let _ = writer.flush().await;
        }
    };
    let netstack_tx_r = netstack_tx.clone();
    let read_target = target_label.clone();
    // 读方向：proxy 返回的 payload 重新写回 netstack 的 UDP 发送半边。
    let read = async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    trace!(
                        "UDP 代理读取回复 <- {} bytes={} 写回 {} -> {}",
                        read_target, n, target, client
                    );
                    let pkt = buf[..n].to_vec();
                    let mut s = netstack_tx_r.lock().await;
                    if let Err(e) = s.send((pkt, target, client)).await {
                        debug!("UDP 代理回复错误：{e}");
                        break;
                    }
                }
                Err(e) => {
                    debug!("UDP 代理读取错误：{e}");
                    break;
                }
            }
        }
    };
    // 任一方向结束即结束本会话，下一包会重新创建会话。
    tokio::select! {
        _ = write => {}
        _ = read => {}
    }

    telemetry::emit_traffic("TUN UDP", target_label, 0, 0);
    Ok(())
}

async fn relay_direct_udp(
    client: SocketAddr,
    target: SocketAddr,
    target_label: String,
    mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    netstack_tx: UdpWriter,
    direct_bind_interface: Option<BindInterface>,
) -> Result<()> {
    // 直连 UDP 绑定临时本地端口并 connect 到目标，便于 recv 只接收该目标回复。
    let socket = bind_direct_udp(target, direct_bind_interface.as_ref())?;
    socket.connect(target).await?;
    let socket = Arc::new(socket);

    let socket_w = socket.clone();
    // 写方向：TUN 会话 payload 发往真实目标。
    let write = async move {
        while let Some(data) = rx.recv().await {
            if let Err(e) = socket_w.send(&data).await {
                debug!("UDP 直连发送错误：{e}");
                break;
            }
        }
    };
    let netstack_tx_r = netstack_tx.clone();
    // 读方向：真实目标回复写回 netstack，并保持原 source/target 方向。
    let read = async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match socket.recv(&mut buf).await {
                Ok(n) => {
                    let pkt = buf[..n].to_vec();
                    let mut s = netstack_tx_r.lock().await;
                    if let Err(e) = s.send((pkt, target, client)).await {
                        debug!("UDP 直连回复错误：{e}");
                        break;
                    }
                }
                Err(e) => {
                    debug!("UDP 直连接收错误：{e}");
                    break;
                }
            }
        }
    };
    // 直连会话和代理会话一样，任一方向结束就释放会话。
    tokio::select! {
        _ = write => {}
        _ = read => {}
    }
    telemetry::emit_traffic("TUN UDP (直连)", target_label, 0, 0);
    Ok(())
}

fn bind_direct_udp(
    target: SocketAddr,
    bind_interface: Option<&BindInterface>,
) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(
        Domain::for_address(target),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    bind_socket_to_interface(&socket, bind_interface, target)?;

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

async fn drain_dropped_udp(mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>) {
    while let Ok(Some(_)) = timeout(Duration::from_secs(10), rx.recv()).await {
        // Keep the session alive briefly so repeated dropped UDP retries do not spin up tasks.
    }
}
