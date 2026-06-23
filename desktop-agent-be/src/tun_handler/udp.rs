//! TUN UDP 会话处理。
//!
//! UDP 在 netstack 层没有连接生命周期，所以外层会按 source/target 近似会话化。
//! 本模块负责单个会话的直连或代理中继；未命中直连规则的高并发普通 UDP
//! 通常会被 `udp_relay.rs` 的共享 relay 接走。

use super::network::{
    TunNetworks, address_for_tun_target, is_tun_local_udp_target, reject_tun_target,
};
use crate::connection_pool::ConnectionPool;
use crate::direct_access::{DirectAccessChecker, address_to_string};
use crate::error::{AgentError, Result};
use crate::telemetry;
use common::{BindInterface, QuicPolicy, bind_socket_to_interface};
use futures::SinkExt;
use protocol::{Address, TransportProtocol};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::{Duration, timeout};
use tracing::{debug, trace};

use super::direct_domain_cache::DirectDomainCache;

pub(super) type UdpWriter = Arc<tokio::sync::Mutex<netstack_smoltcp::udp::WriteHalf>>;

#[derive(Clone)]
pub(super) struct UdpSessionContext {
    pub(super) tun_networks: TunNetworks,
    pub(super) proxy_dns: bool,
    pub(super) quic_policy: QuicPolicy,
    pub(super) netstack_tx: UdpWriter,
    pub(super) tcp_pool: Arc<ConnectionPool>,
    pub(super) udp_pool: Arc<ConnectionPool>,
    pub(super) direct_checker: Arc<DirectAccessChecker>,
    pub(super) direct_domain_cache: Arc<DirectDomainCache>,
    pub(super) direct_egress: Arc<super::TunDirectEgress>,
}

struct DirectUdpRelayContext {
    client: SocketAddr,
    original_target: SocketAddr,
    connect_target: SocketAddr,
    target_label: String,
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    netstack_tx: UdpWriter,
    direct_egress: Arc<super::TunDirectEgress>,
    tcp_pool: Arc<ConnectionPool>,
    udp_pool: Arc<ConnectionPool>,
    tun_networks: TunNetworks,
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
        quic_policy,
        netstack_tx,
        tcp_pool,
        udp_pool,
        direct_checker,
        direct_domain_cache,
        direct_egress,
    } = context;

    // UDP 目标同样先处理 proxy DNS 虚拟地址。
    let (address, proxy_dns_request) = address_for_tun_target(target, proxy_dns);
    if !proxy_dns_request {
        if tun_networks.is_ipv4_broadcast(target.ip()) {
            debug!("TUN UDP 广播已丢弃 -> {}", target);
            drain_dropped_udp(rx).await;
            return Ok(());
        }
        if is_tun_local_udp_target(client, target, tun_networks) {
            debug!("TUN UDP 本地网段流量已丢弃：{} -> {}", client, target);
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

    let mut direct_target = None;
    let mut direct_label = target_label.clone();
    let mut proxy_address = address.clone();
    let mut proxy_reason = None;
    if !proxy_dns_request {
        // UDP 没有 TCP 的 SNI 嗅探机会，主要依赖 IP/CIDR 和 DNS proxy 记录的域名缓存。
        if direct_checker.is_direct(&address) {
            direct_target = Some(target);
        } else if let Some(domain) = direct_domain_cache
            .matching_domain_for_ip(target.ip(), |domain| {
                direct_checker.is_direct_domain(domain)
            })
        {
            debug!(
                "TUN UDP 缓存域名规则命中：{} ({})，先使用原始 IP 直连",
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
        debug!("TUN UDP 缓存域名用于代理目标：{} ({})", target, domain);
        proxy_address = domain_address(&domain, target.port());
        proxy_reason = Some(format!("缓存域名 {domain}"));
    }

    if !proxy_dns_request
        && target.port() == 443
        && quic_policy.should_block_udp443(direct_target.is_some())
    {
        debug!(
            "TUN UDP/443 QUIC 已按策略 {:?} 阻断 -> {}，等待应用回退 TCP",
            quic_policy, target_label
        );
        drain_dropped_udp(rx).await;
        return Ok(());
    }

    if let Some(connect_target) = direct_target {
        // 直连 UDP 使用本地 UDP socket 与目标通信，回复写回 netstack。
        let target_str = address_to_string(&address);
        debug!("TUN UDP 直连 -> {}", target_str);
        relay_direct_udp(DirectUdpRelayContext {
            client,
            original_target: target,
            connect_target,
            target_label: direct_label,
            rx,
            netstack_tx,
            direct_egress,
            tcp_pool,
            udp_pool,
            tun_networks,
        })
        .await?;
        return Ok(());
    }

    // 代理 UDP 路径通过连接池建立一个 UDP 语义的 proxy stream。
    let proxy_label = proxy_target_label(&target_label, proxy_reason.as_deref());
    if proxy_dns_request {
        debug!("TUN UDP DNS -> 代理 -> {}", target_label);
    } else {
        debug!("TUN UDP -> 代理 -> {}", proxy_label);
    }
    let connected = udp_pool
        .as_ref()
        .get_connected_stream(proxy_address, TransportProtocol::Udp)
        .await?;
    let proxy_io = connected.into_async_io();
    let (mut reader, mut writer) = tokio::io::split(proxy_io);
    let outbound_bytes = Arc::new(AtomicU64::new(0));
    let inbound_bytes = Arc::new(AtomicU64::new(0));

    // 写方向：同一 UDP 会话的 payload 从 channel 进入 proxy stream。
    let write_target = target_label.clone();
    let outbound_bytes_w = outbound_bytes.clone();
    let write = async move {
        while let Some(data) = rx.recv().await {
            let data_len = data.len();
            trace!(
                "UDP 代理写入 payload -> {} bytes={}",
                write_target, data_len
            );
            if let Err(e) = writer.write_all(&data).await {
                debug!("UDP 代理写入错误：{e}");
                break;
            }
            outbound_bytes_w.fetch_add(data_len as u64, Ordering::Relaxed);
            let _ = writer.flush().await;
        }
    };
    let netstack_tx_r = netstack_tx.clone();
    let read_target = target_label.clone();
    let inbound_bytes_r = inbound_bytes.clone();
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
                    inbound_bytes_r.fetch_add(n as u64, Ordering::Relaxed);
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

    telemetry::emit_traffic(
        "TUN UDP",
        target_label,
        outbound_bytes.load(Ordering::Relaxed),
        inbound_bytes.load(Ordering::Relaxed),
    );
    Ok(())
}

async fn relay_direct_udp(context: DirectUdpRelayContext) -> Result<()> {
    let DirectUdpRelayContext {
        client,
        original_target,
        connect_target,
        target_label,
        mut rx,
        netstack_tx,
        direct_egress,
        tcp_pool,
        udp_pool,
        tun_networks,
    } = context;

    // 直连 UDP 绑定临时本地端口并 connect 到目标，便于 recv 只接收该目标回复。
    let socket = connect_direct_udp_with_refresh(
        connect_target,
        &target_label,
        direct_egress.as_ref(),
        tcp_pool.as_ref(),
        udp_pool.as_ref(),
        tun_networks,
    )
    .await?;
    let socket = Arc::new(socket);
    let outbound_bytes = Arc::new(AtomicU64::new(0));
    let inbound_bytes = Arc::new(AtomicU64::new(0));

    let socket_w = socket.clone();
    let outbound_bytes_w = outbound_bytes.clone();
    // 写方向：TUN 会话 payload 发往真实目标。
    let write = async move {
        while let Some(data) = rx.recv().await {
            let data_len = data.len();
            if let Err(e) = socket_w.send(&data).await {
                debug!("UDP 直连发送错误：{e}");
                break;
            }
            outbound_bytes_w.fetch_add(data_len as u64, Ordering::Relaxed);
        }
    };
    let netstack_tx_r = netstack_tx.clone();
    let inbound_bytes_r = inbound_bytes.clone();
    // 读方向：真实目标回复写回 netstack，并保持原 source/target 方向。
    let read = async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match socket.recv(&mut buf).await {
                Ok(n) => {
                    let pkt = buf[..n].to_vec();
                    let mut s = netstack_tx_r.lock().await;
                    if let Err(e) = s.send((pkt, original_target, client)).await {
                        debug!("UDP 直连回复错误：{e}");
                        break;
                    }
                    inbound_bytes_r.fetch_add(n as u64, Ordering::Relaxed);
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
    telemetry::emit_traffic(
        "TUN UDP (直连)",
        target_label,
        outbound_bytes.load(Ordering::Relaxed),
        inbound_bytes.load(Ordering::Relaxed),
    );
    Ok(())
}

async fn connect_direct_udp_with_refresh(
    target: SocketAddr,
    target_label: &str,
    direct_egress: &super::TunDirectEgress,
    tcp_pool: &ConnectionPool,
    udp_pool: &ConnectionPool,
    tun_networks: TunNetworks,
) -> Result<UdpSocket> {
    let initial_bind_interface = direct_egress.bind_interface();
    match connect_direct_udp(target, initial_bind_interface.as_ref()).await {
        Ok(socket) => Ok(socket),
        Err(first_err) => {
            debug!(
                "TUN UDP 直连首次失败，刷新物理出口后重试：target={} bind_interface={:?} error={}",
                target_label, initial_bind_interface, first_err
            );
            let refreshed_bind_interface = direct_egress
                .refresh_after_direct_failure(target.ip(), tcp_pool, udp_pool, tun_networks)
                .await;
            connect_direct_udp(target, refreshed_bind_interface.as_ref())
                .await
                .map_err(|retry_err| {
                    AgentError::Connection(format!(
                        "UDP 直连 {target_label} 失败：首次错误={first_err}；刷新物理出口后重试错误={retry_err}"
                    ))
                })
        }
    }
}

async fn connect_direct_udp(
    target: SocketAddr,
    bind_interface: Option<&BindInterface>,
) -> std::io::Result<UdpSocket> {
    let socket = bind_direct_udp(target, bind_interface)?;
    socket.connect(target).await?;
    Ok(socket)
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

    UdpSocket::from_std(socket.into())
}

async fn drain_dropped_udp(mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>) {
    while let Ok(Some(_)) = timeout(Duration::from_secs(10), rx.recv()).await {
        // 保持会话短暂存活，避免应用持续重试被丢弃 UDP 时频繁创建/销毁任务。
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
        Some(reason) => format!("{reason}，原始目标 {target_label}"),
        None => target_label.to_string(),
    }
}
