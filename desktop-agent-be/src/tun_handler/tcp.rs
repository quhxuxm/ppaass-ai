use super::TunForwardContext;
use super::network::{address_for_tun_target, reject_tun_target};
use crate::error::{AgentError, Result};
use crate::telemetry;
use common::{BindInterface, DEFAULT_STREAM_RELAY_BUFFER_SIZE, bind_socket_to_interface};
use protocol::TransportProtocol;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::IpAddr;
use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpSocket, TcpStream};
use tracing::debug;

pub(super) async fn handle_tun_tcp(
    mut client: netstack_smoltcp::TcpStream,
    source: SocketAddr,
    target: SocketAddr,
    context: TunForwardContext,
) -> Result<()> {
    let TunForwardContext {
        tcp_pool,
        udp_pool: _,
        direct_checker,
        direct_domain_cache,
        tun_networks,
        proxy_dns,
        direct_bind_interface,
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

    let mut direct_target = None;
    if !proxy_dns_request {
        if direct_checker.is_direct(&address) {
            direct_target = Some(target);
        } else if let Some(domain) = direct_domain_cache.domain_for_ip(target.ip())
            && direct_checker.is_direct_domain(&domain)
        {
            match resolve_direct_domain_target(&domain, target.port(), target.ip()).await {
                Ok(resolved) => {
                    debug!(
                        "TUN TCP 域名规则命中：{} -> 使用 Agent DNS 解析 {} -> {}",
                        target,
                        domain,
                        resolved
                    );
                    direct_target = Some(resolved);
                }
                Err(e) => {
                    debug!(
                        "TUN TCP 域名规则命中但 Agent DNS 解析失败，回退代理：{} -> {}，错误：{}",
                        target,
                        domain,
                        e
                    );
                }
            }
        }
    }

    if let Some(connect_target) = direct_target {
        // 直连规则命中时绕过 proxy，直接连接真实目标。
        let target_str = format!("{} (原始目标 {})", connect_target, target);
        let mut target = connect_direct_tcp(connect_target, direct_bind_interface.as_ref())
            .await
            .map_err(|e| AgentError::Connection(format!("直连 {target_str} 失败：{e}")))?;
        match tokio::io::copy_bidirectional_with_sizes(
            &mut client,
            &mut target,
            DEFAULT_STREAM_RELAY_BUFFER_SIZE,
            DEFAULT_STREAM_RELAY_BUFFER_SIZE,
        )
        .await
        {
            Ok((c2t, t2c)) => {
                telemetry::emit_traffic("TUN TCP (直连)", target_label, c2t, t2c);
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
    let connected = tcp_pool
        .as_ref()
        .get_connected_stream(address, TransportProtocol::Tcp)
        .await?;
    let mut proxy_io = connected.into_async_io();
    // TUN TCP 流和 proxy stream 都实现 AsyncRead/AsyncWrite，可直接双向中继。
    match tokio::io::copy_bidirectional_with_sizes(
        &mut client,
        &mut proxy_io,
        DEFAULT_STREAM_RELAY_BUFFER_SIZE,
        DEFAULT_STREAM_RELAY_BUFFER_SIZE,
    )
    .await
    {
        Ok((c2p, p2c)) => {
            telemetry::emit_traffic("TUN TCP", target_label, c2p, p2c);
        }
        Err(e) => debug!("TUN TCP 中继结束：{e}"),
    }
    let _ = client.shutdown().await;
    Ok(())
}

async fn connect_direct_tcp(
    target: SocketAddr,
    bind_interface: Option<&BindInterface>,
) -> std::io::Result<TcpStream> {
    let socket = Socket::new(
        Domain::for_address(target),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    bind_socket_to_interface(&socket, bind_interface, target)?;
    socket.set_nonblocking(true)?;

    let socket = TcpSocket::from_std_stream(socket.into());
    socket.connect(target).await
}

async fn resolve_direct_domain_target(
    domain: &str,
    port: u16,
    prefer_ip_family: IpAddr,
) -> io::Result<SocketAddr> {
    let mut first = None;
    let prefer_v4 = prefer_ip_family.is_ipv4();
    for addr in tokio::net::lookup_host((domain, port)).await? {
        if first.is_none() {
            first = Some(addr);
        }
        if addr.is_ipv4() == prefer_v4 {
            return Ok(addr);
        }
    }

    first.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("域名 {domain} 无可用解析结果"),
        )
    })
}
