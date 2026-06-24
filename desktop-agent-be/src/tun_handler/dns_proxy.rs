//! TUN DNS 代理。
//!
//! 当 TUN 捕获到 UDP/53 且启用 proxy_dns 时，DNS 请求会走这里：
//! agent 通过 UDP 连接池连接 proxy 的 `Address::ProxyDns` 虚拟目标，让 proxy 端使用
//! 它所在网络的 DNS 上游解析。同时本模块记录响应中的域名/IP 映射，供 direct_access
//! 在后续 TCP/UDP IP 连接上还原域名规则。

use super::direct_domain_cache::DirectDomainCache;
use super::udp::UdpWriter;
use crate::connection_pool::ConnectionPool;
use crate::telemetry::{self, DnsResolutionRecord};
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

mod parser;
#[cfg(test)]
mod tests;

use parser::{parse_dns_query, parse_dns_response};

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

struct DnsResponseSummary {
    status: String,
    answers: Vec<String>,
    min_ttl: Option<u32>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct DnsCacheKey {
    query: String,
    record_type: String,
}

struct CachedDnsResponse {
    packet: Vec<u8>,
    expires_at: Instant,
}

#[derive(Default)]
struct DnsResponseCache {
    entries: HashMap<DnsCacheKey, CachedDnsResponse>,
}

impl DnsResponseCache {
    fn get(&mut self, query: &str, record_type: &str, request_id: u16) -> Option<Vec<u8>> {
        self.cleanup_expired();
        let key = dns_cache_key(query, record_type);
        let entry = self.entries.get(&key)?;
        if entry.expires_at <= Instant::now() {
            self.entries.remove(&key);
            return None;
        }

        let mut packet = entry.packet.clone();
        write_dns_id(&mut packet, request_id);
        Some(packet)
    }

    fn insert(
        &mut self,
        query: &str,
        record_type: &str,
        summary: &DnsResponseSummary,
        response: &[u8],
    ) {
        if summary.status != "NOERROR" || summary.answers.is_empty() {
            return;
        }
        let Some(ttl_secs) = summary.min_ttl else {
            return;
        };
        if ttl_secs == 0 {
            return;
        }

        self.cleanup_expired();
        if self.entries.len() >= DNS_RESPONSE_CACHE_MAX_ENTRIES {
            self.evict_one();
        }

        let mut packet = response.to_vec();
        // 缓存完整 DNS 响应；命中时再替换成当前请求的 transaction id。
        write_dns_id(&mut packet, 0);
        self.entries.insert(
            dns_cache_key(query, record_type),
            CachedDnsResponse {
                packet,
                expires_at: Instant::now()
                    + Duration::from_secs(u64::from(ttl_secs)).min(DNS_RESPONSE_CACHE_MAX_TTL),
            },
        );
    }

    fn cleanup_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| entry.expires_at > now);
    }

    fn evict_one(&mut self) {
        if let Some(key) = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.expires_at)
            .map(|(key, _)| key.clone())
        {
            self.entries.remove(&key);
        }
    }
}

fn dns_cache_key(query: &str, record_type: &str) -> DnsCacheKey {
    DnsCacheKey {
        query: query.trim().trim_end_matches('.').to_ascii_lowercase(),
        record_type: record_type.to_ascii_uppercase(),
    }
}

impl DnsProxy {
    pub(super) fn spawn(
        pool: Arc<ConnectionPool>,
        netstack_tx: UdpWriter,
        direct_domain_cache: Arc<DirectDomainCache>,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(DNS_REQUEST_CHANNEL_SIZE);
        spawn_guarded(
            "desktop tun dns proxy",
            run_dns_proxy(pool, netstack_tx, direct_domain_cache, rx, shutdown),
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
    pool: Arc<ConnectionPool>,
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

        let connected = connect_dns_stream(&pool).await;
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
    pool: &ConnectionPool,
) -> crate::error::Result<impl AsyncRead + AsyncWrite + Unpin + Send + 'static> {
    let connected = pool
        .get_connected_stream(Address::ProxyDns { port: 53 }, TransportProtocol::Udp)
        .await?;
    Ok(connected.into_async_io())
}

async fn try_send_cached_dns_response(
    netstack_tx: &UdpWriter,
    direct_domain_cache: &DirectDomainCache,
    response_cache: &mut DnsResponseCache,
    request: &DnsProxyRequest,
) -> bool {
    let Some(original_id) = dns_id(&request.packet) else {
        debug!("TUN UDP DNS 请求过短，跳过缓存查询");
        return false;
    };
    let Some((query, record_type)) = parse_dns_query(&request.packet) else {
        debug!("TUN UDP DNS 请求解析失败，跳过缓存查询");
        return false;
    };
    let Some(response) = response_cache.get(&query, &record_type, original_id) else {
        return false;
    };

    let response_summary = parse_dns_response(&response).unwrap_or_else(|| DnsResponseSummary {
        status: "INVALID".to_string(),
        answers: Vec::new(),
        min_ttl: None,
    });
    direct_domain_cache.record_resolution(&query, &response_summary.answers);
    telemetry::emit_dns_resolution(DnsResolutionRecord {
        timestamp_ms: telemetry::current_time_millis(),
        resolver: "agent-cache".to_string(),
        client: request.client.to_string(),
        upstream: request.target.to_string(),
        query,
        record_type,
        status: response_summary.status,
        answers: response_summary.answers,
        duration_ms: 0,
    });

    let mut writer = netstack_tx.lock().await;
    if let Err(e) = writer
        .send((response, request.target, request.client))
        .await
    {
        debug!("TUN UDP DNS 缓存回复写回失败：{e}");
    }
    true
}

async fn send_dns_request<W>(
    writer: &mut W,
    pending: &mut HashMap<u16, PendingDnsRequest>,
    next_id: &mut u16,
    request: &DnsProxyRequest,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let Some(original_id) = dns_id(&request.packet) else {
        debug!("TUN UDP DNS 请求过短，已丢弃");
        return Ok(());
    };
    let (query, record_type) = parse_dns_query(&request.packet)
        .unwrap_or_else(|| ("<unknown>".to_string(), "UNKNOWN".to_string()));

    cleanup_pending_dns(pending);
    // 同一条共享连接上可能有多个并发 DNS 请求；改写 ID 用于区分响应归属。
    let Some(upstream_id) = allocate_dns_id(pending, next_id) else {
        warn!("TUN UDP DNS 待处理请求过多，已丢弃一个请求");
        return Ok(());
    };

    let started_at = Instant::now();
    let mut packet = request.packet.clone();
    write_dns_id(&mut packet, upstream_id);
    pending.insert(
        upstream_id,
        PendingDnsRequest {
            client: request.client,
            target: request.target,
            original_id,
            query,
            record_type,
            started_at,
            expires_at: Instant::now() + DNS_PENDING_TTL,
        },
    );

    let write_result = async {
        writer.write_all(&packet).await?;
        writer.flush().await
    }
    .await;

    if write_result.is_err() {
        pending.remove(&upstream_id);
    }

    write_result
}

async fn handle_dns_response(
    netstack_tx: &UdpWriter,
    direct_domain_cache: &DirectDomainCache,
    response_cache: &mut DnsResponseCache,
    pending: &mut HashMap<u16, PendingDnsRequest>,
    response: &mut [u8],
) -> io::Result<()> {
    // 根据改写后的 upstream_id 找回原请求，恢复原始 DNS ID 后写回 netstack。
    let Some(upstream_id) = dns_id(response) else {
        debug!("TUN UDP DNS 回复过短，已丢弃");
        return Ok(());
    };

    let Some(request) = pending.remove(&upstream_id) else {
        debug!("TUN UDP DNS 收到无匹配请求的回复 id={upstream_id}");
        return Ok(());
    };

    let response_summary = parse_dns_response(response).unwrap_or_else(|| DnsResponseSummary {
        status: "INVALID".to_string(),
        answers: Vec::new(),
        min_ttl: None,
    });
    response_cache.insert(
        &request.query,
        &request.record_type,
        &response_summary,
        response,
    );
    direct_domain_cache.record_resolution(&request.query, &response_summary.answers);
    telemetry::emit_dns_resolution(DnsResolutionRecord {
        timestamp_ms: telemetry::current_time_millis(),
        resolver: "agent".to_string(),
        client: request.client.to_string(),
        upstream: request.target.to_string(),
        query: request.query,
        record_type: request.record_type,
        status: response_summary.status,
        answers: response_summary.answers,
        duration_ms: request.started_at.elapsed().as_millis(),
    });

    write_dns_id(response, request.original_id);
    let mut s = netstack_tx.lock().await;
    s.send((response.to_vec(), request.target, request.client))
        .await
}

fn cleanup_pending_dns(pending: &mut HashMap<u16, PendingDnsRequest>) {
    let now = Instant::now();
    let expired_ids: Vec<u16> = pending
        .iter()
        .filter_map(|(id, request)| (request.expires_at <= now).then_some(*id))
        .collect();

    for id in expired_ids {
        if let Some(request) = pending.remove(&id) {
            telemetry::emit_dns_resolution(DnsResolutionRecord {
                timestamp_ms: telemetry::current_time_millis(),
                resolver: "agent".to_string(),
                client: request.client.to_string(),
                upstream: request.target.to_string(),
                query: request.query,
                record_type: request.record_type,
                status: "TIMEOUT".to_string(),
                answers: Vec::new(),
                duration_ms: request.started_at.elapsed().as_millis(),
            });
        }
    }
}

fn allocate_dns_id(pending: &HashMap<u16, PendingDnsRequest>, next_id: &mut u16) -> Option<u16> {
    for _ in 0..=u16::MAX {
        let id = *next_id;
        *next_id = next_id.wrapping_add(1);
        if !pending.contains_key(&id) {
            return Some(id);
        }
    }
    None
}

fn dns_id(packet: &[u8]) -> Option<u16> {
    let bytes = packet.get(..2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn write_dns_id(packet: &mut [u8], id: u16) {
    let bytes = id.to_be_bytes();
    packet[0] = bytes[0];
    packet[1] = bytes[1];
}
