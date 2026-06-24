//! TUN TCP 流处理。
//!
//! netstack 把系统 IP 包还原成 `TcpStream` 后进入这里。处理顺序是：
//! 1. 过滤 TUN 自身网段和 proxy DNS 特例；
//! 2. 用 IP/CIDR 和 DNS proxy 缓存判断是否直连；
//! 3. 命中直连则连真实目标，否则从 TCP 连接池拿 proxy stream 双向中继。

use super::TunForwardContext;
use super::network::{address_for_tun_target, reject_tun_target};
use crate::connection_pool::ConnectionPool;
use crate::error::{AgentError, Result};
use crate::tcp_relay::{TcpRelayOptions, relay_tcp_bidirectional};
use crate::telemetry;
use common::{BindInterface, bind_socket_to_interface};
use protocol::TransportProtocol;
use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::timeout;
use tracing::debug;

/// macOS 待机恢复后 scoped route 可能短暂失效，避免直连卡到系统 TCP 超时。
const DIRECT_TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

pub(super) async fn handle_tun_tcp(
    mut client: netstack_smoltcp::TcpStream,
    source: SocketAddr,
    target: SocketAddr,
    context: TunForwardContext,
) -> Result<()> {
    let TunForwardContext {
        tcp_pool,
        udp_pool,
        direct_checker,
        direct_domain_cache,
        tun_networks,
        proxy_dns,
        direct_egress,
    } = context;

    // 先把 TUN 目标地址转成代理协议地址，并处理 proxy DNS 特例。
    let (address, proxy_dns_request) = address_for_tun_target(target, proxy_dns);
    if !proxy_dns_request {
        // 普通目标不能落入 TUN 自身网段，避免流量在本机回环。
        reject_tun_target("TCP", source, target, tun_networks)?;
    }
    let target_label = if proxy_dns_request {
        format!("{target} -> proxy默认DNS")
    } else {
        target.to_string()
    };
    // 1. IP/CIDR 命中：完全不需要嗅探，直接连原始目标。
    let mut direct_target = None;
    let proxy_address = address.clone();
    let mut proxy_reason = None;
    if !proxy_dns_request && direct_checker.is_direct(&address) {
        direct_target = Some(target);
    }

    // 2. 缓存中已知 IP -> 域名映射且命中域名规则：仍然使用原始 IP 直连。
    //    这里的域名只来自 proxy DNS 缓存，不触发 agent 本机 DNS 解析，也不再
    //    从 TCP payload 读取 TLS SNI/HTTP Host。这样 TUN 数据面不会因为首包
    //    嗅探和补发逻辑影响视频分片下载。
    if direct_target.is_none()
        && !proxy_dns_request
        && direct_checker.has_domain_direct_rules()
        && let Some(domain) = direct_domain_cache.matching_domain_for_ip(target.ip(), |domain| {
            direct_checker.is_direct_domain(domain)
        })
    {
        debug!(
            "TUN TCP 缓存域名规则命中：{} ({})，先使用原始 IP 直连",
            target, domain
        );
        direct_target = Some(target);
    }

    if direct_target.is_none()
        && !proxy_dns_request
        && let Some(domain) = direct_domain_cache.matching_domain_for_ip(target.ip(), |_| true)
    {
        debug!(
            "TUN TCP 缓存域名用于代理标签：{} ({})，代理目标保留原始 IP",
            target, domain
        );
        proxy_reason = Some(format!("缓存域名 {domain}"));
    }

    if let Some(connect_target) = direct_target {
        // 直连规则命中时绕过 proxy，直接连接真实目标。
        let target_str = format!("{} (原始目标 {})", connect_target, target);
        let mut target_stream = connect_direct_tcp_with_refresh(DirectTcpRefreshContext {
            target: connect_target,
            target_str: &target_str,
            direct_egress: direct_egress.as_ref(),
            tcp_pool: tcp_pool.as_ref(),
            udp_pool: udp_pool.as_ref(),
            tun_networks,
        })
        .await?;
        match relay_tcp_bidirectional(
            &mut client,
            &mut target_stream,
            TcpRelayOptions::standard(&target_str),
        )
        .await
        {
            Ok(stats) => {
                telemetry::emit_traffic(
                    "TUN TCP (直连)",
                    target_label,
                    stats.client_to_remote,
                    stats.remote_to_client,
                );
            }
            Err(e) => debug!("TUN TCP 直连中继结束：{e}"),
        }
        let _ = client.shutdown().await;
        return Ok(());
    }

    // 默认路径通过连接池获取已认证 proxy 流，再做双向拷贝。
    if proxy_dns_request {
        debug!("TUN TCP DNS -> 代理 -> {}", target_label);
    } else {
        debug!("TUN TCP -> 代理 -> {}", target_label);
    }
    let proxy_label = proxy_target_label(&target_label, proxy_reason.as_deref());
    if !proxy_dns_request {
        debug!("TUN TCP 代理目标：{}", proxy_label);
    }
    // TUN TCP 不再抢读首包做 SNI/Host 嗅探。proxy 路径直接把原始字节流交给
    // copy_bidirectional，中间没有“已读首段再补发”的状态，减少短连接分片卡顿点。
    let connected = tcp_pool
        .as_ref()
        .get_connected_stream(proxy_address, TransportProtocol::Tcp)
        .await?;
    let mut proxy_io = connected.into_async_io();
    match relay_tcp_bidirectional(
        &mut client,
        &mut proxy_io,
        TcpRelayOptions::tun(&proxy_label),
    )
    .await
    {
        Ok(stats) => {
            telemetry::emit_traffic(
                "TUN TCP",
                target_label,
                stats.client_to_remote,
                stats.remote_to_client,
            );
        }
        Err(e) => debug!("TUN TCP 中继结束：{e}"),
    }
    let _ = client.shutdown().await;
    Ok(())
}

fn proxy_target_label(target_label: &str, reason: Option<&str>) -> String {
    match reason {
        Some(reason) => format!("{reason}，原始目标 {target_label}"),
        None => target_label.to_string(),
    }
}

async fn connect_direct_tcp(
    target: SocketAddr,
    bind_interface: Option<&BindInterface>,
) -> std::io::Result<TcpStream> {
    // TUN 直连也要绑定物理接口，否则系统默认路由已指向 TUN 时会出现自回环。
    let socket = Socket::new(
        Domain::for_address(target),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    bind_socket_to_interface(&socket, bind_interface, target)?;
    enable_direct_tcp_keepalive(&socket, target);
    socket.set_nonblocking(true)?;

    let socket = TcpSocket::from_std_stream(socket.into());
    timeout(DIRECT_TCP_CONNECT_TIMEOUT, socket.connect(target))
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("TUN TCP 直连 {target} 超时"),
            )
        })?
}

struct DirectTcpRefreshContext<'a> {
    target: SocketAddr,
    target_str: &'a str,
    direct_egress: &'a super::TunDirectEgress,
    tcp_pool: &'a ConnectionPool,
    udp_pool: &'a crate::connection_pool::ConnectionPool,
    tun_networks: super::network::TunNetworks,
}

async fn connect_direct_tcp_with_refresh(
    context: DirectTcpRefreshContext<'_>,
) -> Result<TcpStream> {
    let DirectTcpRefreshContext {
        target,
        target_str,
        direct_egress,
        tcp_pool,
        udp_pool,
        tun_networks,
    } = context;
    let initial_bind_interface = direct_egress.bind_interface();
    match connect_direct_tcp(target, initial_bind_interface.as_ref()).await {
        Ok(stream) => Ok(stream),
        Err(first_err) => {
            debug!(
                "TUN TCP 直连首次失败，刷新物理出口后重试：target={} bind_interface={:?} error={}",
                target_str, initial_bind_interface, first_err
            );
            let refreshed_bind_interface = direct_egress
                .refresh_after_direct_failure(target.ip(), tcp_pool, udp_pool, tun_networks)
                .await;
            match connect_direct_tcp(target, refreshed_bind_interface.as_ref()).await {
                Ok(stream) => Ok(stream),
                Err(retry_err) => {
                    // 这里刻意不做 agent 侧域名解析兜底。
                    // TUN 流量进来时系统/应用已经完成了解析，agent 看到的是原始目标 IP；
                    // 如果直连失败后再用 agent 本机 DNS 重新解析域名，会改变客户端实际
                    // 选择的 CDN/出口语义，也会和“域名由 proxy 端解析”的安全要求冲突。
                    // 因此直连失败只刷新物理出口重试同一个 IP，不把域名解析拉回 agent。
                    Err(AgentError::Connection(format!(
                        "直连 {target_str} 失败：首次错误={first_err}；刷新物理出口后重试错误={retry_err}"
                    )))
                }
            }
        }
    }
}

fn enable_direct_tcp_keepalive(socket: &Socket, target: SocketAddr) {
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(30))
        .with_retries(4);

    if let Err(err) = socket.set_tcp_keepalive(&keepalive) {
        debug!("TUN TCP 直连 keepalive 设置失败 target={target}: {err}");
    }
    if let Err(err) = socket.set_tcp_nodelay(true) {
        debug!("TUN TCP 直连 TCP_NODELAY 设置失败 target={target}: {err}");
    }
}
