//! TUN DNS 代理。
//!
//! 当 TUN 捕获到 UDP/53 且启用 proxy_dns 时，DNS 请求会走这里：
//! agent 通过 UDP Yamux session manager 连接 proxy 的 `Address::ProxyDns` 虚拟目标，让 proxy 端使用
//! 它所在网络的 DNS 上游解析。同时本模块记录响应中的域名/IP 映射，供 direct_access
//! 在后续 TCP/UDP IP 连接上还原域名规则。

use super::direct_domain_cache::DirectDomainCache;
use super::udp::UdpWriter;
use crate::telemetry::{self, DnsResolutionRecord};
use crate::yamux_session::YamuxSessionManager;
use common::spawn_guarded;
use futures::SinkExt;
use protocol::{Address, TransportProtocol};
use std::collections::HashMap;
use std::convert::TryInto;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

mod cache;
mod parser;
mod response;
#[cfg(test)]
mod tests;

use cache::{DnsResponseCache, DnsResponseSummary};
use parser::{parse_dns_query, parse_dns_response};
#[cfg(test)]
use response::{allocate_dns_id, dns_id};
use response::{
    cleanup_pending_dns, handle_dns_response, send_dns_request, try_send_cached_dns_response,
    write_dns_id,
};

const DNS_PENDING_TTL: Duration = Duration::from_secs(10);
const DNS_REQUEST_CHANNEL_SIZE: usize = 1024;
const DNS_PROXY_CONNECTION_IDLE: Duration = Duration::from_secs(15);
const DNS_RESPONSE_CACHE_MAX_ENTRIES: usize = 4096;
const DNS_RESPONSE_CACHE_MAX_TTL: Duration = Duration::from_secs(300);

pub(super) struct DnsProxy {
    tx: mpsc::Sender<DnsProxyRequest>,
}

#[derive(Clone)]
struct DnsProxyRequest {
    client: SocketAddr,
    target: SocketAddr,
    packet: Vec<u8>,
}

struct PendingDnsRequest {
    // DNS ID 会被改写成 upstream_id；收到响应后再恢复 original_id 给客户端。
    client: SocketAddr,
    target: SocketAddr,
    original_id: u16,
    query: String,
    record_type: String,
    started_at: Instant,
    expires_at: Instant,
}

impl DnsProxy {
    pub(super) fn spawn(
        sessions: Arc<YamuxSessionManager>,
        netstack_tx: UdpWriter,
        direct_domain_cache: Arc<DirectDomainCache>,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(DNS_REQUEST_CHANNEL_SIZE);
        spawn_guarded(
            "desktop tun dns proxy",
            run_dns_proxy(sessions, netstack_tx, direct_domain_cache, rx, shutdown),
        );
        Arc::new(Self { tx })
    }

    pub(super) fn send(&self, client: SocketAddr, target: SocketAddr, packet: Vec<u8>) {
        match self.tx.try_send(DnsProxyRequest {
            client,
            target,
            packet,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => debug!("TUN UDP DNS 队列已满，丢弃请求"),
            Err(TrySendError::Closed(_)) => debug!("TUN UDP DNS 共享转发器已关闭，丢弃请求"),
        }
    }
}

async fn run_dns_proxy(
    sessions: Arc<YamuxSessionManager>,
    netstack_tx: UdpWriter,
    direct_domain_cache: Arc<DirectDomainCache>,
    mut rx: mpsc::Receiver<DnsProxyRequest>,
    shutdown: CancellationToken,
) {
    let mut pending = HashMap::new();
    let mut response_cache = DnsResponseCache::default();
    let mut next_id = 0u16;
    // 共享 DNS proxy 连接断开时，保留当前请求并在重连后优先重发。
    let mut retry_request = None;
    let mut reconnect_delay = Duration::from_millis(200);

    loop {
        let first_request = match retry_request.take() {
            Some(request) => request,
            None => {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    maybe_request = rx.recv() => {
                        let Some(request) = maybe_request else { break };
                        request
                    }
                }
            }
        };

        if try_send_cached_dns_response(
            &netstack_tx,
            direct_domain_cache.as_ref(),
            &mut response_cache,
            &first_request,
        )
        .await
        {
            continue;
        }

        let connected = connect_dns_stream(&sessions).await;
        let proxy_io = match connected {
            Ok(proxy_io) => {
                reconnect_delay = Duration::from_millis(200);
                proxy_io
            }
            Err(e) => {
                warn!("TUN UDP DNS 共享连接创建失败：{e}");
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(reconnect_delay) => {}
                }
                reconnect_delay = (reconnect_delay * 2).min(Duration::from_secs(5));
                retry_request = Some(first_request);
                continue;
            }
        };

        debug!("TUN UDP DNS 已建立共享 proxy 连接");
        let (mut reader, mut writer) = tokio::io::split(proxy_io);
        let mut cleanup = tokio::time::interval(Duration::from_secs(5));
        cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let idle = tokio::time::sleep(DNS_PROXY_CONNECTION_IDLE);
        tokio::pin!(idle);
        pending.clear();
        retry_request = Some(first_request);
        let mut response_buf = vec![0u8; 65535];

        loop {
            if let Some(request) = retry_request.take() {
                if try_send_cached_dns_response(
                    &netstack_tx,
                    direct_domain_cache.as_ref(),
                    &mut response_cache,
                    &request,
                )
                .await
                {
                    continue;
                }
                if let Err(e) =
                    send_dns_request(&mut writer, &mut pending, &mut next_id, &request).await
                {
                    debug!("TUN UDP DNS 共享连接写入失败：{e}");
                    retry_request = Some(request);
                    break;
                }
                idle.as_mut()
                    .reset(tokio::time::Instant::now() + DNS_PROXY_CONNECTION_IDLE);
                continue;
            }

            tokio::select! {
                _ = shutdown.cancelled() => {
                    let _ = writer.shutdown().await;
                    return;
                }
                _ = &mut idle => {
                    debug!(
                        "TUN UDP DNS 共享连接空闲超过 {} 秒，主动关闭 proxy 连接",
                        DNS_PROXY_CONNECTION_IDLE.as_secs()
                    );
                    let _ = writer.shutdown().await;
                    break;
                }
                _ = cleanup.tick() => cleanup_pending_dns(&mut pending),
                maybe_request = rx.recv() => {
                    let Some(request) = maybe_request else {
                        let _ = writer.shutdown().await;
                        return;
                    };
                    if try_send_cached_dns_response(
                        &netstack_tx,
                        direct_domain_cache.as_ref(),
                        &mut response_cache,
                        &request,
                    ).await {
                        continue;
                    }
                    if let Err(e) = send_dns_request(
                        &mut writer,
                        &mut pending,
                        &mut next_id,
                        &request,
                    ).await {
                        debug!("TUN UDP DNS 共享连接写入失败：{e}");
                        retry_request = Some(request);
                        break;
                    }
                    idle.as_mut().reset(tokio::time::Instant::now() + DNS_PROXY_CONNECTION_IDLE);
                }
                read = reader.read(&mut response_buf) => {
                    match read {
                        Ok(0) => {
                            debug!("TUN UDP DNS 共享连接已关闭");
                            break;
                        }
                        Ok(n) => {
                            let mut response = response_buf[..n].to_vec();
                            if let Err(e) = handle_dns_response(
                                &netstack_tx,
                                direct_domain_cache.as_ref(),
                                &mut response_cache,
                                &mut pending,
                                &mut response,
                            ).await {
                                debug!("TUN UDP DNS 回复写回失败：{e}");
                            }
                            idle.as_mut().reset(tokio::time::Instant::now() + DNS_PROXY_CONNECTION_IDLE);
                        }
                        Err(e) => {
                            debug!("TUN UDP DNS 共享连接读取失败：{e}");
                            break;
                        }
                    }
                }
            }
        }
    }

    debug!("TUN UDP DNS 共享转发器退出");
}

async fn connect_dns_stream(
    sessions: &YamuxSessionManager,
) -> crate::error::Result<impl AsyncRead + AsyncWrite + Unpin + Send + 'static> {
    let connected = sessions
        .connect_to_target(Address::ProxyDns { port: 53 }, TransportProtocol::Udp)
        .await?;
    Ok(connected.into_async_io())
}
