//! TUN TCP 流处理。
//!
//! netstack 把系统 IP 包还原成 `TcpStream` 后进入这里。处理顺序是：
//! 1. 过滤 TUN 自身网段和 proxy DNS 特例；
//! 2. 用 IP/CIDR 和 DNS proxy 缓存判断是否直连；
//! 3. 命中直连则连真实目标，否则从 proxy session manager 打开目标流并双向中继。

use super::TunForwardContext;
use super::network::{address_for_tun_target, reject_tun_target};
use crate::error::{AgentError, Result};
use crate::tcp_relay::{TcpRelayOptions, relay_tcp_bidirectional};
use crate::telemetry;
use std::future::Future;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

const TUN_TCP_PREFETCH_LIMIT: usize = 64 * 1024;
const TUN_TCP_PREFETCH_CHUNK: usize = 16 * 1024;

mod direct;
mod proxy_connect;

use direct::{DirectTcpRefreshContext, connect_direct_tcp_with_refresh};
use proxy_connect::{connect_proxy_stream_with_tun_prefetch, prefetch_tls_sni_for_ip};
pub use proxy_connect::{
    direct_rule_tls_server_name, proxy_target_address, tls_client_hello_server_name,
};

pub(super) async fn handle_tun_tcp(
    mut client: netstack_smoltcp::TcpStream,
    source: SocketAddr,
    target: SocketAddr,
    context: TunForwardContext,
) -> Result<()> {
    let TunForwardContext {
        tcp_sessions,
        udp_sessions,
        direct_checker,
        direct_domain_cache,
        tun_networks,
        proxy_dns,
        proxy_udp: _,
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
    //    proxy_dns=false 时 DNS 查询由 agent 直连上游 DNS 服务器。
    let mut direct_target = None;
    let mut proxy_address = address.clone();
    let mut proxy_reason = None;
    if !proxy_dns_request
        && (direct_checker.is_direct(&address) || (!proxy_dns && target.port() == 53))
    {
        direct_target = Some(target);
    }

    if direct_target.is_none()
        && !proxy_dns_request
        && direct_checker.has_domain_direct_rules()
        && let Some(domain_match) = direct_domain_cache
            .matching_domain_for_ip(target.ip(), |domain| {
                direct_checker.is_direct_domain(domain)
            })
    {
        debug!(
            "TUN TCP 缓存域名规则命中：{} ({}){}，先使用原始 IP 直连",
            target,
            domain_match.domain(),
            if domain_match.is_stale() {
                " [stale]"
            } else {
                ""
            }
        );
        direct_target = Some(target);
    }

    if direct_target.is_none()
        && !proxy_dns_request
        && let Some(domain_match) =
            direct_domain_cache.matching_domain_for_ip(target.ip(), |_| true)
    {
        let domain = domain_match.into_domain();
        debug!("TUN TCP 使用缓存域名作为代理目标：{} ({})", target, domain);
        proxy_address = proxy_target_address(proxy_address, Some(&domain));
        proxy_reason = Some(format!("缓存域名 {domain}"));
    }

    // Windows Teams/WebView2 可用 DoH，DNS 映射缺失时按 TLS SNI 判定直连。
    let mut sni_prefetched = Vec::new();
    if direct_target.is_none()
        && !proxy_dns_request
        && direct_checker.has_domain_direct_rules()
        && address.port() == 443
        && matches!(
            address,
            protocol::Address::Ipv4 { .. } | protocol::Address::Ipv6 { .. }
        )
    {
        sni_prefetched = prefetch_tls_sni_for_ip(&mut client, &address).await?;
        if let Some(host) = direct_rule_tls_server_name(&sni_prefetched, &direct_checker) {
            debug!(
                "TUN TCP TLS SNI 域名规则命中：{} ({host})，改为直连",
                target
            );
            direct_target = Some(target);
        }
    }

    if let Some(connect_target) =
        direct_target.filter(|target| direct_egress.can_direct(target.ip()))
    {
        // 直连规则命中时绕过 proxy，直接连接真实目标。
        let target_str = target_label.as_str();
        let direct_connect = connect_direct_tcp_with_refresh(DirectTcpRefreshContext {
            target: connect_target,
            target_str,
            direct_egress: direct_egress.as_ref(),
            tcp_sessions: tcp_sessions.as_ref(),
            udp_sessions: udp_sessions.as_ref(),
            tun_networks,
        });
        let (mut target_stream, mut prefetched) =
            connect_with_tun_prefetch(&mut client, direct_connect, target_str).await?;
        if !sni_prefetched.is_empty() {
            sni_prefetched.append(&mut prefetched);
            prefetched = sni_prefetched;
        }
        write_prefetched(&mut target_stream, &prefetched).await?;
        match relay_tcp_bidirectional(
            &mut client,
            &mut target_stream,
            TcpRelayOptions::standard(target_str),
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

    if direct_target.is_some() {
        debug!(
            "TUN TCP 直连缺少同地址族物理源地址，回退 proxy：{}",
            target_label
        );
    }

    // 默认路径通过 proxy session manager 获取已认证 proxy 流，再做双向拷贝。
    if proxy_dns_request {
        debug!("TUN TCP DNS -> 代理 -> {}", target_label);
    } else {
        debug!("TUN TCP -> 代理 -> {}", target_label);
    }
    let proxy_label = proxy_target_label(&target_label, proxy_reason.as_deref());
    if !proxy_dns_request {
        debug!("TUN TCP 代理目标：{}", proxy_label);
    }
    let (connected, prefetched) = connect_proxy_stream_with_tun_prefetch(
        &mut client,
        tcp_sessions.as_ref(),
        proxy_address,
        &proxy_label,
        sni_prefetched,
    )
    .await?;
    let mut proxy_io = connected.into_async_io();
    if !prefetched.is_empty() {
        // 这里只做“预读后原样补写”，不解析、不嗅探、不参与直连规则。
        // TUN TCP 三次握手已经由 netstack 接住；如果等待 proxy 建连期间完全不读本地流，
        // 浏览器的 TLS/HTTP2 首包会卡在接收窗口里。先缓存少量首包，远端通道建立后
        // 立即写出，可以降低视频分片连接在建连阶段的抖动。
        write_prefetched(&mut proxy_io, &prefetched).await?;
    }
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

async fn connect_with_tun_prefetch<T, F>(
    client: &mut netstack_smoltcp::TcpStream,
    connect: F,
    label: &str,
) -> Result<(T, Vec<u8>)>
where
    F: Future<Output = Result<T>>,
{
    let mut connect = Box::pin(connect);
    let mut prefetched = Vec::with_capacity(TUN_TCP_PREFETCH_CHUNK);
    let mut chunk = vec![0u8; TUN_TCP_PREFETCH_CHUNK];

    loop {
        if prefetched.len() >= TUN_TCP_PREFETCH_LIMIT {
            debug!(
                "TUN TCP 预读达到 {} 字节上限，暂停读取等待远端建连：{}",
                TUN_TCP_PREFETCH_LIMIT, label
            );
            let connected = connect.await?;
            return Ok((connected, prefetched));
        }

        let read_limit = (TUN_TCP_PREFETCH_LIMIT - prefetched.len()).min(chunk.len());
        tokio::select! {
            connected = &mut connect => {
                return Ok((connected?, prefetched));
            }
            read = client.read(&mut chunk[..read_limit]) => {
                let read = read?;
                if read == 0 {
                    // 客户端在远端通道建好前已经关闭；没有必要继续建立连接。
                    // 如果已经预读到数据，则仍等待 proxy 连接并把这些数据补写出去，
                    // 后续 copy_bidirectional 会自然观察到客户端 EOF 并传播半关闭。
                    if prefetched.is_empty() {
                        return Err(AgentError::Connection(format!(
                            "TUN TCP 客户端在远端建连前关闭：{label}"
                        )));
                    }
                    let connected = connect.await?;
                    return Ok((connected, prefetched));
                }
                prefetched.extend_from_slice(&chunk[..read]);
            }
        }
    }
}

async fn write_prefetched<W>(remote: &mut W, prefetched: &[u8]) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    if prefetched.is_empty() {
        return Ok(());
    }
    remote.write_all(prefetched).await?;
    remote.flush().await?;
    Ok(())
}
