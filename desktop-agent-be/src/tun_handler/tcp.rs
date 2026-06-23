//! TUN TCP 流处理。
//!
//! netstack 把系统 IP 包还原成 `TcpStream` 后进入这里。处理顺序是：
//! 1. 过滤 TUN 自身网段和 proxy DNS 特例；
//! 2. 用 IP/CIDR、DNS 缓存、SNI/Host 嗅探判断是否直连；
//! 3. 命中直连则连真实目标，否则从 TCP 连接池拿 proxy stream 双向中继。

use super::TunForwardContext;
use super::domain_sniff::{extract_http_host, extract_tls_sni};
use super::network::{address_for_tun_target, reject_tun_target};
use super::system_dns::resolve_via_system;
use crate::connection_pool::{ConnectedStream, ConnectionPool};
use crate::error::{AgentError, Result};
use crate::telemetry;
use common::{BindInterface, bind_socket_to_interface};
use protocol::{Address, TransportProtocol};
use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::debug;

/// 嗅探首段字节的最大长度。TLS ClientHello 最大约 16KB，但常见的 SNI/Host
/// 通常在前 1-2KB 即出现；选择 4KB 兼顾覆盖率与首字节延迟。
const SNIFF_MAX_BYTES: usize = 4096;
/// 等待客户端首段字节的最长时间。某些应用握手前会短暂沉默，
/// 但超过 300ms 仍未发数据多半是 server-first 协议，直接放弃嗅探走原路径。
const SNIFF_TIMEOUT: Duration = Duration::from_millis(300);
/// macOS 待机恢复后 scoped route 可能短暂失效，避免直连卡到系统 TCP 超时。
const DIRECT_TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// 常规通道如果中途无进展，低频输出累计字节，帮助定位卡在上行还是下行。
const TCP_RELAY_PROGRESS_LOG_INTERVAL: Duration = Duration::from_secs(5);

type ProxyPreconnect = (Address, JoinHandle<Result<ConnectedStream>>);

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
    let relay_buffer_size = tcp_pool.tcp_relay_buffer_size();

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
    let mut direct_domain = None;
    let mut proxy_address = address.clone();
    let mut proxy_reason = None;
    if !proxy_dns_request && direct_checker.is_direct(&address) {
        direct_target = Some(target);
    }

    // 2. 缓存中已知 IP -> 域名映射且命中域名规则：先使用原始 IP 直连，
    //    避免 macOS 待机恢复后系统 DNS 慢解析阻塞直连路径。
    if direct_target.is_none()
        && !proxy_dns_request
        && let Some(domain) = direct_domain_cache.matching_domain_for_ip(target.ip(), |domain| {
            direct_checker.is_direct_domain(domain)
        })
    {
        debug!(
            "TUN TCP 缓存域名规则命中：{} ({})，先使用原始 IP 直连",
            target, domain
        );
        direct_domain = Some(domain);
        direct_target = Some(target);
    }

    if direct_target.is_none()
        && !proxy_dns_request
        && let Some(domain) = direct_domain_cache.matching_domain_for_ip(target.ip(), |_| true)
    {
        debug!("TUN TCP 缓存域名用于代理目标：{} ({})", target, domain);
        proxy_address = domain_address(&domain, target.port());
        proxy_reason = Some(format!("缓存域名 {domain}"));
    }

    let mut proxy_preconnect = if direct_target.is_none() {
        // TUN TCP 嗅探和 proxy stream 获取原本是串行的：先等首包/解析域名，再从
        // 连接池拿 proxy 流。视频分片会频繁建短 TCP 连接，这两个等待叠加时容易
        // 形成可见卡顿。这里先按当前已知目标预连接；如果后续 sniff 命中直连或
        // 改写了 proxy 域名，会取消这个任务，保持路由语义不变。
        Some(spawn_proxy_preconnect(
            tcp_pool.clone(),
            proxy_address.clone(),
        ))
    } else {
        None
    };

    // 3. DNS 路径无法命中（例如浏览器使用 DoH 或操作系统 DNS 缓存）时，
    //    从首段字节中嗅探 SNI / HTTP Host，作为域名规则的兜底来源。
    let mut sniffed: Vec<u8> = Vec::new();
    if direct_target.is_none() && !proxy_dns_request {
        sniffed = sniff_first_bytes(&mut client, target.port()).await;
        if !sniffed.is_empty()
            && let Some(domain) = sniff_domain(target.port(), &sniffed)
        {
            debug!("TUN TCP 嗅探域名 {} <- {}", domain, target);
            // 嗅探到的 IP -> 域名映射写回缓存，下一次同 IP 的连接可以走快路径。
            direct_domain_cache.record_resolution(&domain, &[target.ip().to_string()]);
            if direct_checker.is_direct_domain(&domain) {
                debug!(
                    "TUN TCP 嗅探域名规则命中：{} ({})，先使用原始 IP 直连",
                    target, domain
                );
                direct_domain = Some(domain);
                direct_target = Some(target);
            } else {
                debug!("TUN TCP 嗅探域名用于代理目标：{} ({})", target, domain);
                proxy_address = domain_address(&domain, target.port());
                proxy_reason = Some(format!("嗅探域名 {domain}"));
            }
        }
    }

    if let Some(connect_target) = direct_target {
        abort_proxy_preconnect(proxy_preconnect.take());
        // 直连规则命中时绕过 proxy，直接连接真实目标。
        let target_str = format!("{} (原始目标 {})", connect_target, target);
        let mut target_stream = connect_direct_tcp_with_refresh(DirectTcpRefreshContext {
            target: connect_target,
            target_str: &target_str,
            direct_domain: direct_domain.as_deref(),
            source,
            direct_egress: direct_egress.as_ref(),
            tcp_pool: tcp_pool.as_ref(),
            udp_pool: udp_pool.as_ref(),
            tun_networks,
        })
        .await?;
        // 把嗅探时已经读出的字节先补发给目标，否则握手会丢首段。
        if !sniffed.is_empty() {
            if let Err(e) = target_stream.write_all(&sniffed).await {
                debug!("TUN TCP 直连补发首段字节失败：{e}");
            } else if let Err(e) = target_stream.flush().await {
                debug!("TUN TCP 直连刷新首段字节失败：{e}");
            }
        }
        match tokio::io::copy_bidirectional_with_sizes(
            &mut client,
            &mut target_stream,
            relay_buffer_size,
            relay_buffer_size,
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
    let proxy_label = proxy_target_label(&target_label, proxy_reason.as_deref());
    if !proxy_dns_request {
        debug!("TUN TCP 代理目标：{}", proxy_label);
    }
    let connected =
        get_proxy_stream(tcp_pool.clone(), proxy_address, proxy_preconnect.take()).await?;
    let mut proxy_io = connected.into_async_io();
    // 嗅探阶段消耗的字节同样需要补发给 proxy，否则 proxy 端收到的报文头会被截断。
    if !sniffed.is_empty() {
        if let Err(e) = proxy_io.write_all(&sniffed).await {
            debug!("TUN TCP 代理补发首段字节失败：{e}");
        } else if let Err(e) = proxy_io.flush().await {
            debug!("TUN TCP 代理刷新首段字节失败：{e}");
        }
    }
    match relay_tun_tcp_proxy_with_flush(
        &mut client,
        &mut proxy_io,
        relay_buffer_size,
        &proxy_label,
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

async fn relay_tun_tcp_proxy_with_flush<C, P>(
    client: &mut C,
    proxy_io: &mut P,
    relay_buffer_size: usize,
    label: &str,
) -> std::io::Result<(u64, u64)>
where
    C: AsyncRead + AsyncWrite + Unpin,
    P: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_reader, mut client_writer) = tokio::io::split(client);
    let (mut proxy_reader, mut proxy_writer) = tokio::io::split(proxy_io);
    let mut client_buf = vec![0u8; relay_buffer_size];
    let mut proxy_buf = vec![0u8; relay_buffer_size];
    let mut client_done = false;
    let mut proxy_done = false;
    let mut client_to_proxy = 0u64;
    let mut proxy_to_client = 0u64;
    let mut last_client_to_proxy = 0u64;
    let mut last_proxy_to_client = 0u64;
    let mut progress_log = tokio::time::interval(TCP_RELAY_PROGRESS_LOG_INTERVAL);
    progress_log.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        if client_done && proxy_done {
            break;
        }

        tokio::select! {
            read = client_reader.read(&mut client_buf), if !client_done => {
                match read {
                    Ok(0) => {
                        client_done = true;
                        proxy_writer.shutdown().await?;
                    }
                    Ok(n) => {
                        // 常规通道的 proxy 写端是 SinkWriter<DataPacketSink>。只 poll_write
                        // 不一定立刻把 framed 数据推到底层 socket；HLS/HTTP2 中后续
                        // WINDOW_UPDATE 或请求体如果滞留，服务端会发一部分后停住。
                        // 因此 TUN TCP 代理路径每次写入后显式 flush。
                        proxy_writer.write_all(&client_buf[..n]).await?;
                        proxy_writer.flush().await?;
                        client_to_proxy += n as u64;
                    }
                    Err(e) => return Err(e),
                }
            }
            read = proxy_reader.read(&mut proxy_buf), if !proxy_done => {
                match read {
                    Ok(0) => {
                        proxy_done = true;
                        client_writer.shutdown().await?;
                    }
                    Ok(n) => {
                        client_writer.write_all(&proxy_buf[..n]).await?;
                        client_writer.flush().await?;
                        proxy_to_client += n as u64;
                    }
                    Err(e) => return Err(e),
                }
            }
            _ = progress_log.tick() => {
                if client_to_proxy == last_client_to_proxy && proxy_to_client == last_proxy_to_client {
                    if client_to_proxy > 0 || proxy_to_client > 0 {
                        debug!(
                            "TUN TCP relay 暂无进展：target={} client_to_proxy={} proxy_to_client={}",
                            label,
                            client_to_proxy,
                            proxy_to_client
                        );
                    }
                } else {
                    last_client_to_proxy = client_to_proxy;
                    last_proxy_to_client = proxy_to_client;
                }
            }
        }
    }

    Ok((client_to_proxy, proxy_to_client))
}

/// 在不超过 `SNIFF_TIMEOUT` 的前提下，尝试从客户端读取最多 `SNIFF_MAX_BYTES`
/// 个字节用于域名嗅探。读取到的数据在后续转发时会被原样补发。
async fn sniff_first_bytes(client: &mut netstack_smoltcp::TcpStream, port: u16) -> Vec<u8> {
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
            Ok(Ok(n)) => {
                buffer.extend_from_slice(&chunk[..n]);
                if sniff_buffer_ready(port, &buffer) {
                    break;
                }
            }
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

fn sniff_buffer_ready(port: u16, buf: &[u8]) -> bool {
    if sniff_domain(port, buf).is_some() {
        return true;
    }

    // 如果已经拿到完整的 TLS record 或 HTTP 头，即使没有解析出域名也不要继续等
    // `SNIFF_TIMEOUT`。Cloudflare/ECH 或无 Host 的连接在 TUN 下否则会给每条新 TCP
    // 连接额外叠加一次首包等待，对 HLS `.ts` 分片这类高频短连接尤其明显。
    has_complete_tls_record(buf) || has_complete_http_headers(buf)
}

fn has_complete_tls_record(buf: &[u8]) -> bool {
    if buf.len() < 5 || buf[0] != 0x16 {
        return false;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    buf.len() >= 5usize.saturating_add(record_len)
}

fn has_complete_http_headers(buf: &[u8]) -> bool {
    std::str::from_utf8(buf)
        .map(|text| text.contains("\r\n\r\n"))
        .unwrap_or(false)
}

fn sniff_domain(port: u16, buf: &[u8]) -> Option<String> {
    match port {
        // HTTP 端口优先匹配明文 Host 头，TLS 反代场景再退到 SNI。
        80 | 8080 | 8000 => extract_http_host(buf).or_else(|| extract_tls_sni(buf)),
        // 其他端口默认按 TLS（含 443/8443/853 等）解析，失败再尝试 HTTP。
        _ => extract_tls_sni(buf).or_else(|| extract_http_host(buf)),
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

fn spawn_proxy_preconnect(
    tcp_pool: Arc<ConnectionPool>,
    proxy_address: Address,
) -> ProxyPreconnect {
    let address_for_task = proxy_address.clone();
    let task = tokio::spawn(async move {
        tcp_pool
            .as_ref()
            .get_connected_stream(address_for_task, TransportProtocol::Tcp)
            .await
    });
    (proxy_address, task)
}

fn abort_proxy_preconnect(preconnect: Option<ProxyPreconnect>) {
    if let Some((_, task)) = preconnect {
        task.abort();
    }
}

async fn get_proxy_stream(
    tcp_pool: Arc<ConnectionPool>,
    proxy_address: Address,
    preconnect: Option<ProxyPreconnect>,
) -> Result<ConnectedStream> {
    if let Some((preconnect_address, task)) = preconnect {
        if same_proxy_address(&preconnect_address, &proxy_address) {
            debug!("TUN TCP 复用 sniff 期间建立的 proxy stream");
            return task.await.map_err(|e| {
                AgentError::Connection(format!("TUN TCP proxy 预连接任务失败：{e}"))
            })?;
        }

        // sniff 后如果目标从 IP 改为域名，或者命中其他目标，必须丢弃预连接，
        // 按最终 proxy_address 重新连接，避免优化改变路由选择。
        task.abort();
    }

    tcp_pool
        .as_ref()
        .get_connected_stream(proxy_address, TransportProtocol::Tcp)
        .await
}

fn same_proxy_address(left: &Address, right: &Address) -> bool {
    match (left, right) {
        (
            Address::Domain {
                host: left_host,
                port: left_port,
            },
            Address::Domain {
                host: right_host,
                port: right_port,
            },
        ) => left_port == right_port && left_host.eq_ignore_ascii_case(right_host),
        (
            Address::Ipv4 {
                addr: left_addr,
                port: left_port,
            },
            Address::Ipv4 {
                addr: right_addr,
                port: right_port,
            },
        ) => left_addr == right_addr && left_port == right_port,
        (
            Address::Ipv6 {
                addr: left_addr,
                port: left_port,
            },
            Address::Ipv6 {
                addr: right_addr,
                port: right_port,
            },
        ) => left_addr == right_addr && left_port == right_port,
        (Address::ProxyDns { port: left_port }, Address::ProxyDns { port: right_port }) => {
            left_port == right_port
        }
        (Address::UdpRelay, Address::UdpRelay)
        | (Address::TcpYamux, Address::TcpYamux)
        | (Address::UdpYamux, Address::UdpYamux) => true,
        _ => false,
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
    direct_domain: Option<&'a str>,
    source: SocketAddr,
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
        direct_domain,
        source,
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
                    if let Some(domain) = direct_domain
                        && let Some(resolved) =
                            resolve_direct_target_via_system("TCP", source, target, domain).await
                    {
                        if resolved != target {
                            debug!(
                                "TUN TCP 原始 IP 直连失败，尝试系统 DNS 兜底：{} -> {}",
                                domain, resolved
                            );
                            return connect_direct_tcp(resolved, refreshed_bind_interface.as_ref())
                                .await
                                .map_err(|resolved_err| {
                                    AgentError::Connection(format!(
                                        "直连 {target_str} 失败：首次错误={first_err}；刷新物理出口后重试错误={retry_err}；系统 DNS 解析 {domain} -> {resolved} 后仍失败={resolved_err}"
                                    ))
                                });
                        }
                        debug!(
                            "TUN TCP 系统 DNS 兜底仍指向原始目标：{} -> {}",
                            domain, resolved
                        );
                    }

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniff_buffer_waits_for_complete_tls_record() {
        let partial = [0x16, 0x03, 0x01, 0x00, 0x03, 0x01];
        let complete = [0x16, 0x03, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03];

        assert!(!has_complete_tls_record(&partial));
        assert!(has_complete_tls_record(&complete));
        assert!(sniff_buffer_ready(443, &complete));
    }

    #[test]
    fn sniff_buffer_stops_on_complete_http_headers() {
        let partial = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        let complete = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

        assert!(!has_complete_http_headers(partial));
        assert!(has_complete_http_headers(complete));
        assert!(sniff_buffer_ready(80, complete));
    }
}
