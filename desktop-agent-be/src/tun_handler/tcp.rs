use super::TunForwardContext;
use super::domain_sniff::{extract_http_host, extract_tls_sni};
use super::network::{address_for_tun_target, reject_tun_target};
use super::system_dns::resolve_via_system;
use crate::error::{AgentError, Result};
use crate::telemetry;
use common::{BindInterface, DEFAULT_STREAM_RELAY_BUFFER_SIZE, bind_socket_to_interface};
use protocol::TransportProtocol;
use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::timeout;
use tracing::debug;

/// 嗅探首段字节的最大长度。TLS ClientHello 最大约 16KB，但常见的 SNI/Host
/// 通常在前 1-2KB 即出现；选择 4KB 兼顾覆盖率与首字节延迟。
const SNIFF_MAX_BYTES: usize = 4096;
/// 等待客户端首段字节的最长时间。某些应用握手前会短暂沉默，
/// 但超过 300ms 仍未发数据多半是 server-first 协议，直接放弃嗅探走原路径。
const SNIFF_TIMEOUT: Duration = Duration::from_millis(300);

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
    if !proxy_dns_request && direct_checker.is_direct(&address) {
        direct_target = Some(target);
    }

    // 2. 缓存中已知 IP -> 域名映射且命中域名规则：保持现有行为，
    //    通过 Agent 本机 DNS 重新解析以获得 agent 侧的 CDN IP。
    if direct_target.is_none()
        && !proxy_dns_request
        && let Some(domain) = direct_domain_cache.matching_domain_for_ip(target.ip(), |domain| {
            direct_checker.is_direct_domain(domain)
        })
    {
        direct_target = resolve_direct_target_via_system("TCP", source, target, &domain).await;
        if direct_target.is_none() {
            debug!(
                "TUN TCP 缓存域名命中但 Agent DNS 解析失败，回退用原始 IP 直连：{} ({})",
                target, domain
            );
            direct_target = Some(target);
        }
    }

    // 3. DNS 路径无法命中（例如浏览器使用 DoH 或操作系统 DNS 缓存）时，
    //    从首段字节中嗅探 SNI / HTTP Host，作为域名规则的兜底来源。
    let mut sniffed: Vec<u8> = Vec::new();
    if direct_target.is_none() && !proxy_dns_request {
        sniffed = sniff_first_bytes(&mut client).await;
        if !sniffed.is_empty()
            && let Some(domain) = sniff_domain(target.port(), &sniffed)
        {
            debug!("TUN TCP 嗅探域名 {} <- {}", domain, target);
            // 嗅探到的 IP -> 域名映射写回缓存，下一次同 IP 的连接可以走快路径。
            direct_domain_cache.record_resolution(&domain, &[target.ip().to_string()]);
            if direct_checker.is_direct_domain(&domain) {
                direct_target =
                    resolve_direct_target_via_system("TCP", source, target, &domain).await;
                if direct_target.is_none() {
                    debug!(
                        "TUN TCP 嗅探域名命中但 Agent DNS 解析失败，回退用原始 IP 直连：{} ({})",
                        target, domain
                    );
                    direct_target = Some(target);
                }
            }
        }
    }

    if let Some(connect_target) = direct_target {
        // 直连规则命中时绕过 proxy，直接连接真实目标。
        let target_str = format!("{} (原始目标 {})", connect_target, target);
        let mut target_stream = connect_direct_tcp_with_refresh(
            connect_target,
            &target_str,
            direct_egress.as_ref(),
            tcp_pool.as_ref(),
            udp_pool.as_ref(),
            tun_networks,
        )
        .await?;
        // 把嗅探时已经读出的字节先补发给目标，否则握手会丢首段。
        if !sniffed.is_empty()
            && let Err(e) = target_stream.write_all(&sniffed).await
        {
            debug!("TUN TCP 直连补发首段字节失败：{e}");
        }
        match tokio::io::copy_bidirectional_with_sizes(
            &mut client,
            &mut target_stream,
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
    // 嗅探阶段消耗的字节同样需要补发给 proxy，否则 proxy 端收到的报文头会被截断。
    if !sniffed.is_empty()
        && let Err(e) = proxy_io.write_all(&sniffed).await
    {
        debug!("TUN TCP 代理补发首段字节失败：{e}");
    }
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

/// 在不超过 `SNIFF_TIMEOUT` 的前提下，尝试从客户端读取最多 `SNIFF_MAX_BYTES`
/// 个字节用于域名嗅探。读取到的数据在后续转发时会被原样补发。
async fn sniff_first_bytes(client: &mut netstack_smoltcp::TcpStream) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(SNIFF_MAX_BYTES);
    let deadline = tokio::time::Instant::now() + SNIFF_TIMEOUT;
    let mut chunk = [0u8; 1024];

    loop {
        if buffer.len() >= SNIFF_MAX_BYTES {
            break;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, client.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => buffer.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => {
                debug!("TUN TCP 嗅探读取出错：{e}");
                break;
            }
            // 超时后停止嗅探，已经读到的字节仍会被补发，避免阻塞 server-first 协议。
            Err(_) => break,
        }
    }

    buffer
}

fn sniff_domain(port: u16, buf: &[u8]) -> Option<String> {
    match port {
        // HTTP 端口优先匹配明文 Host 头，TLS 反代场景再退到 SNI。
        80 | 8080 | 8000 => extract_http_host(buf).or_else(|| extract_tls_sni(buf)),
        // 其他端口默认按 TLS（含 443/8443/853 等）解析，失败再尝试 HTTP。
        _ => extract_tls_sni(buf).or_else(|| extract_http_host(buf)),
    }
}

async fn resolve_direct_target_via_system(
    transport: &'static str,
    source: SocketAddr,
    target: SocketAddr,
    domain: &str,
) -> Option<SocketAddr> {
    match resolve_via_system(transport, source, domain, target.port(), target.ip()).await {
        Ok(resolved) => {
            debug!(
                "TUN {} 域名规则命中：{} -> 使用 Agent DNS 解析 {} -> {}",
                transport, target, domain, resolved
            );
            Some(resolved)
        }
        Err(e) => {
            debug!(
                "TUN {} 域名规则命中但 Agent DNS 解析失败：{} -> {}，错误：{}",
                transport, target, domain, e
            );
            None
        }
    }
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
    enable_direct_tcp_keepalive(&socket, target);
    socket.set_nonblocking(true)?;

    let socket = TcpSocket::from_std_stream(socket.into());
    socket.connect(target).await
}

async fn connect_direct_tcp_with_refresh(
    target: SocketAddr,
    target_str: &str,
    direct_egress: &super::TunDirectEgress,
    tcp_pool: &crate::connection_pool::ConnectionPool,
    udp_pool: &crate::connection_pool::ConnectionPool,
    tun_networks: super::network::TunNetworks,
) -> Result<TcpStream> {
    let initial_bind_interface = direct_egress.bind_interface();
    match connect_direct_tcp(target, initial_bind_interface.as_ref()).await {
        Ok(stream) => Ok(stream),
        Err(first_err) => {
            debug!(
                "TUN TCP 直连首次失败，刷新物理出口后重试：target={} bind_interface={:?} error={}",
                target_str, initial_bind_interface, first_err
            );
            let refreshed_bind_interface = direct_egress.refresh_after_direct_failure(
                target.ip(),
                tcp_pool,
                udp_pool,
                tun_networks,
            );
            connect_direct_tcp(target, refreshed_bind_interface.as_ref())
                .await
                .map_err(|retry_err| {
                    AgentError::Connection(format!(
                        "直连 {target_str} 失败：首次错误={first_err}；刷新物理出口后重试错误={retry_err}"
                    ))
                })
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
}
