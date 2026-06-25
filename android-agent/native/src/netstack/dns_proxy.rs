use std::collections::HashMap;
use std::convert::TryInto;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{dns::parse_dns_query_packet, spawn_guarded};
use futures::SinkExt;
use protocol::{Address, TransportProtocol};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use super::ForwardContext;
use super::direct_domain_cache::DirectDomainCache;
use super::udp::UdpWriter;
use crate::android_log;
use crate::error::Result;
use crate::traffic_stats::{self, DnsResolutionRecord};

const DNS_PENDING_TTL: Duration = Duration::from_secs(10);
const DNS_PROXY_CONNECTION_IDLE: Duration = Duration::from_secs(15);
const DNS_REQUEST_CHANNEL_SIZE: usize = 1024;
const DIRECT_DNS_TIMEOUT: Duration = Duration::from_secs(5);
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
        context: ForwardContext,
        netstack_tx: UdpWriter,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(DNS_REQUEST_CHANNEL_SIZE);
        spawn_guarded(
            "android tun dns proxy",
            run_dns_proxy(context, netstack_tx, rx, shutdown),
        );
        Arc::new(Self { tx })
    }

    pub(super) fn send(&self, client: SocketAddr, target: SocketAddr, packet: Vec<u8>) {
        debug!(
            "Android TUN DNS request queued: {} -> {} bytes={}",
            client,
            target,
            packet.len()
        );
        match self.tx.try_send(DnsProxyRequest {
            client,
            target,
            packet,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => debug!("Android TUN DNS queue is full; dropping packet"),
            Err(TrySendError::Closed(_)) => {
                debug!("Android TUN DNS proxy is closed; dropping packet");
            }
        }
    }
}

async fn run_dns_proxy(
    context: ForwardContext,
    netstack_tx: UdpWriter,
    mut rx: mpsc::Receiver<DnsProxyRequest>,
    shutdown: CancellationToken,
) {
    let mut pending = HashMap::new();
    let mut response_cache = DnsResponseCache::default();
    let mut next_id = 0u16;
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

        if try_send_cached_dns_response(&context, &netstack_tx, &mut response_cache, &first_request)
            .await
        {
            continue;
        }
        if try_send_direct_dns_response(&context, &netstack_tx, &mut response_cache, &first_request)
            .await
        {
            continue;
        }

        let connected = connect_dns_stream(&context).await;
        let proxy_io = match connected {
            Ok(proxy_io) => {
                reconnect_delay = Duration::from_millis(200);
                proxy_io
            }
            Err(e) => {
                warn!("Android TUN DNS proxy connection failed: {e}");
                android_log::error(format!("Android TUN DNS proxy connection failed: {e}"));
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(reconnect_delay) => {}
                }
                reconnect_delay = (reconnect_delay * 2).min(Duration::from_secs(5));
                retry_request = Some(first_request);
                continue;
            }
        };

        debug!("Android TUN DNS proxy connected");
        let (mut reader, mut writer) = tokio::io::split(proxy_io);
        let mut cleanup = tokio::time::interval(Duration::from_secs(5));
        cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let idle_sleep = tokio::time::sleep(DNS_PROXY_CONNECTION_IDLE);
        tokio::pin!(idle_sleep);
        pending.clear();
        retry_request = Some(first_request);
        let mut response_buf = vec![0u8; 65535];

        loop {
            if let Some(request) = retry_request.take() {
                if try_send_cached_dns_response(
                    &context,
                    &netstack_tx,
                    &mut response_cache,
                    &request,
                )
                .await
                {
                    continue;
                }
                if try_send_direct_dns_response(
                    &context,
                    &netstack_tx,
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
                    debug!("Android TUN DNS proxy write failed: {e}");
                    retry_request = Some(request);
                    break;
                }
                idle_sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + DNS_PROXY_CONNECTION_IDLE);
                continue;
            }

            tokio::select! {
                _ = shutdown.cancelled() => {
                    let _ = writer.shutdown().await;
                    return;
                }
                _ = &mut idle_sleep => {
                    debug!("Android TUN DNS proxy idle; closing connection");
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
                        &context,
                        &netstack_tx,
                        &mut response_cache,
                        &request,
                    ).await {
                        continue;
                    }
                    if try_send_direct_dns_response(
                        &context,
                        &netstack_tx,
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
                        debug!("Android TUN DNS proxy write failed: {e}");
                        retry_request = Some(request);
                        break;
                    }
                    idle_sleep.as_mut().reset(
                        tokio::time::Instant::now() + DNS_PROXY_CONNECTION_IDLE,
                    );
                }
                read = reader.read(&mut response_buf) => {
                    match read {
                        Ok(0) => {
                            debug!("Android TUN DNS proxy closed");
                            break;
                        }
                        Ok(n) => {
                            let mut response = response_buf[..n].to_vec();
                            if let Err(e) = handle_dns_response(
                                &netstack_tx,
                                context.direct_domain_cache.as_ref(),
                                &mut response_cache,
                                &mut pending,
                                &mut response,
                            ).await {
                                debug!("Android TUN DNS proxy response failed: {e}");
                            }
                            idle_sleep.as_mut().reset(
                                tokio::time::Instant::now() + DNS_PROXY_CONNECTION_IDLE,
                            );
                        }
                        Err(e) => {
                            debug!("Android TUN DNS proxy read failed: {e}");
                            break;
                        }
                    }
                }
            }
        }
    }

    debug!("Android TUN DNS proxy exited");
}

async fn connect_dns_stream(
    context: &ForwardContext,
) -> Result<impl AsyncRead + AsyncWrite + Unpin + Send + 'static> {
    context
        .udp_sessions
        .connect_to_target(Address::ProxyDns { port: 53 }, TransportProtocol::Udp)
        .await
}

async fn try_send_cached_dns_response(
    context: &ForwardContext,
    netstack_tx: &UdpWriter,
    response_cache: &mut DnsResponseCache,
    request: &DnsProxyRequest,
) -> bool {
    let Some(original_id) = dns_id(&request.packet) else {
        debug!("Android TUN DNS request too short; skipping cache lookup");
        return false;
    };
    let Some(question) = parse_dns_question(&request.packet) else {
        debug!("Android TUN DNS request parse failed; skipping cache lookup");
        return false;
    };
    let Some(response) = response_cache.get(&question.query, &question.record_type, original_id)
    else {
        return false;
    };

    let summary = parse_dns_response(&response).unwrap_or_else(|| DnsResponseSummary {
        status: "INVALID".to_string(),
        answers: Vec::new(),
        min_ttl: None,
    });
    context
        .direct_domain_cache
        .record_resolution(&question.query, &summary.answers);
    traffic_stats::record_dns_resolution(DnsResolutionRecord {
        timestamp_ms: traffic_stats::current_time_millis(),
        resolver: "agent-cache".to_string(),
        client: request.client.to_string(),
        upstream: request.target.to_string(),
        query: question.query,
        record_type: question.record_type,
        status: summary.status,
        answers: summary.answers,
        duration_ms: 0,
    });

    let mut tx = netstack_tx.lock().await;
    if let Err(e) = tx.send((response, request.target, request.client)).await {
        debug!("Android TUN DNS cached response writeback failed: {e}");
    }
    true
}

async fn try_send_direct_dns_response(
    context: &ForwardContext,
    netstack_tx: &UdpWriter,
    response_cache: &mut DnsResponseCache,
    request: &DnsProxyRequest,
) -> bool {
    let Some(question) = parse_dns_question(&request.packet) else {
        android_log::warn(format!(
            "Android TUN DNS request parse failed bytes={}",
            request.packet.len()
        ));
        return false;
    };
    if !context.direct_checker.is_direct_domain(&question.query) {
        android_log::info(format!(
            "Android TUN DNS PROXY_CANDIDATE {} {}",
            question.query, question.record_type
        ));
        return false;
    }

    let started_at = Instant::now();
    debug!(
        "Android TUN DNS direct -> {} {} via {}",
        question.query, question.record_type, request.target
    );
    android_log::info(format!(
        "Android TUN DNS DIRECT {} {} via {}",
        question.query, question.record_type, request.target
    ));

    let direct_result = timeout(
        DIRECT_DNS_TIMEOUT,
        query_direct_dns(request.target, &request.packet),
    )
    .await;

    let mut response = match direct_result {
        Ok(Ok(response)) => response,
        Ok(Err(e)) => {
            warn!(
                "Android TUN DNS direct query failed: {} {} via {}, error: {}",
                question.query, question.record_type, request.target, e
            );
            android_log::warn(format!(
                "Android TUN DNS DIRECT failed {} {} via {}: {}",
                question.query, question.record_type, request.target, e
            ));
            build_dns_error_response(&request.packet, 2).unwrap_or_default()
        }
        Err(_) => {
            warn!(
                "Android TUN DNS direct query timed out: {} {} via {}",
                question.query, question.record_type, request.target
            );
            android_log::warn(format!(
                "Android TUN DNS DIRECT timeout {} {} via {}",
                question.query, question.record_type, request.target
            ));
            build_dns_error_response(&request.packet, 2).unwrap_or_default()
        }
    };

    if response.is_empty() {
        return true;
    }

    let summary = parse_dns_response(&response).unwrap_or_else(|| DnsResponseSummary {
        status: "INVALID".to_string(),
        answers: Vec::new(),
        min_ttl: None,
    });
    response_cache.insert(&question.query, &question.record_type, &summary, &response);
    context
        .direct_domain_cache
        .record_resolution(&question.query, &summary.answers);
    record_direct_dns_result(
        request,
        &question,
        &summary.status,
        summary.answers,
        started_at,
    );

    let mut tx = netstack_tx.lock().await;
    if let Err(e) = tx
        .send((response.split_off(0), request.target, request.client))
        .await
    {
        debug!("Android TUN DNS direct response writeback failed: {e}");
    }
    true
}

async fn query_direct_dns(upstream: SocketAddr, packet: &[u8]) -> io::Result<Vec<u8>> {
    let socket = bind_direct_dns_socket(upstream)?;
    socket.send_to(packet, upstream).await?;
    let mut response = vec![0u8; 65535];
    let (n, _) = socket.recv_from(&mut response).await?;
    response.truncate(n);
    Ok(response)
}

fn bind_direct_dns_socket(upstream: SocketAddr) -> io::Result<UdpSocket> {
    let socket = Socket::new(
        Domain::for_address(upstream),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    protect_direct_socket(&socket)?;
    let bind_addr: SocketAddr = if upstream.is_ipv4() {
        "0.0.0.0:0".parse().expect("valid IPv4 bind address")
    } else {
        "[::]:0".parse().expect("valid IPv6 bind address")
    };
    socket.bind(&SockAddr::from(bind_addr))?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

fn protect_direct_socket(socket: &Socket) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;

        crate::socket_protector::protect_fd(socket.as_raw_fd())
    }

    #[cfg(not(unix))]
    {
        let _ = socket;
        Ok(())
    }
}

fn record_direct_dns_result(
    request: &DnsProxyRequest,
    question: &DnsQuestion,
    status: &str,
    answers: Vec<String>,
    started_at: Instant,
) {
    traffic_stats::record_dns_resolution(DnsResolutionRecord {
        timestamp_ms: traffic_stats::current_time_millis(),
        resolver: "agent-direct".to_string(),
        client: request.client.to_string(),
        upstream: request.target.to_string(),
        query: question.query.clone(),
        record_type: question.record_type.clone(),
        status: status.to_string(),
        answers,
        duration_ms: started_at.elapsed().as_millis(),
    });
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
        debug!("Android TUN DNS request is too short; dropping");
        return Ok(());
    };
    let (query, record_type) = parse_dns_query(&request.packet)
        .unwrap_or_else(|| ("<unknown>".to_string(), "UNKNOWN".to_string()));
    android_log::info(format!("Android TUN DNS PROXY {query} {record_type}"));

    cleanup_pending_dns(pending);
    let Some(upstream_id) = allocate_dns_id(pending, next_id) else {
        warn!("Android TUN DNS pending table is full; dropping request");
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
    let Some(upstream_id) = dns_id(response) else {
        debug!("Android TUN DNS response is too short; dropping");
        return Ok(());
    };

    let Some(request) = pending.remove(&upstream_id) else {
        debug!("Android TUN DNS response had no matching id={upstream_id}");
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
    traffic_stats::record_dns_resolution(DnsResolutionRecord {
        timestamp_ms: traffic_stats::current_time_millis(),
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
    let mut tx = netstack_tx.lock().await;
    debug!(
        "Android TUN DNS response writeback: {} -> {} bytes={}",
        request.target,
        request.client,
        response.len()
    );
    tx.send((response.to_vec(), request.target, request.client))
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
            traffic_stats::record_dns_resolution(DnsResolutionRecord {
                timestamp_ms: traffic_stats::current_time_millis(),
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

fn build_dns_error_response(request: &[u8], rcode: u16) -> Option<Vec<u8>> {
    let question = parse_dns_question(request)?;
    let request_flags = read_u16(request, 2).unwrap_or(0);
    let flags = 0x8000 | (request_flags & 0x0100) | 0x0080 | (rcode & 0x000f);

    let mut response = Vec::with_capacity(question.question_end);
    response.extend_from_slice(request.get(..2)?);
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(request.get(12..question.question_end)?);
    Some(response)
}

struct DnsQuestion {
    query: String,
    record_type: String,
    question_end: usize,
}

fn parse_dns_query(packet: &[u8]) -> Option<(String, String)> {
    let question = parse_dns_question(packet)?;
    Some((question.query, question.record_type))
}

fn parse_dns_question(packet: &[u8]) -> Option<DnsQuestion> {
    // DNS 查询本身交给 hickory-proto 校验；这里仅补充计算 question 结束位置，
    // 便于构造错误响应时原样带回客户端问题段。
    let parsed = parse_dns_query_packet(packet)?;

    let mut offset = 12;
    parse_dns_name(packet, &mut offset)?;
    offset = offset.checked_add(2)?;
    let _class = read_u16(packet, offset)?;
    offset = offset.checked_add(2)?;
    if offset > packet.len() {
        return None;
    }
    Some(DnsQuestion {
        query: parsed.query,
        record_type: parsed.record_type,
        question_end: offset,
    })
}

fn parse_dns_response(packet: &[u8]) -> Option<DnsResponseSummary> {
    if packet.len() < 12 {
        return None;
    }

    let flags = read_u16(packet, 2)?;
    let qdcount = read_u16(packet, 4)?;
    let ancount = read_u16(packet, 6)?;
    let mut offset = 12;

    for _ in 0..qdcount {
        parse_dns_name(packet, &mut offset)?;
        offset = offset.checked_add(4)?;
        if offset > packet.len() {
            return None;
        }
    }

    let mut answers = Vec::new();
    let mut min_ttl = None;
    for _ in 0..ancount {
        parse_dns_name(packet, &mut offset)?;
        let record_type = read_u16(packet, offset)?;
        offset = offset.checked_add(2)?;
        let _class = read_u16(packet, offset)?;
        offset = offset.checked_add(2)?;
        let ttl = read_u32(packet, offset)?;
        offset = offset.checked_add(4)?;
        let rdlength = read_u16(packet, offset)? as usize;
        offset = offset.checked_add(2)?;
        let rdata_offset = offset;
        let rdata_end = offset.checked_add(rdlength)?;
        if rdata_end > packet.len() {
            return None;
        }

        if let Some(answer) = parse_dns_answer_rdata(packet, rdata_offset, rdlength, record_type) {
            min_ttl = Some(min_ttl.map_or(ttl, |current: u32| current.min(ttl)));
            answers.push(answer);
        }
        offset = rdata_end;
    }

    Some(DnsResponseSummary {
        status: dns_rcode_name(flags & 0x000f).to_string(),
        answers,
        min_ttl,
    })
}

fn parse_dns_answer_rdata(
    packet: &[u8],
    rdata_offset: usize,
    rdlength: usize,
    record_type: u16,
) -> Option<String> {
    let rdata = packet.get(rdata_offset..rdata_offset.checked_add(rdlength)?)?;
    match record_type {
        1 if rdata.len() == 4 => {
            Some(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string())
        }
        2 | 5 | 12 => {
            let mut offset = rdata_offset;
            parse_dns_name(packet, &mut offset)
        }
        15 if rdata.len() >= 3 => {
            let preference = u16::from_be_bytes([rdata[0], rdata[1]]);
            let mut offset = rdata_offset + 2;
            parse_dns_name(packet, &mut offset).map(|exchange| format!("{preference} {exchange}"))
        }
        16 => Some(parse_txt_rdata(rdata)),
        28 if rdata.len() == 16 => {
            let bytes: [u8; 16] = rdata.try_into().ok()?;
            Some(Ipv6Addr::from(bytes).to_string())
        }
        33 if rdata.len() >= 7 => {
            let port = u16::from_be_bytes([rdata[4], rdata[5]]);
            let mut offset = rdata_offset + 6;
            parse_dns_name(packet, &mut offset).map(|target| format!("{target}:{port}"))
        }
        64 | 65 if rdata.len() >= 3 => {
            let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
            let mut offset = rdata_offset + 2;
            parse_dns_name(packet, &mut offset).map(|target| {
                if target == "." {
                    format!("priority {priority}")
                } else {
                    format!("priority {priority} {target}")
                }
            })
        }
        _ => None,
    }
}

fn parse_txt_rdata(rdata: &[u8]) -> String {
    let mut cursor = 0;
    let mut values = Vec::new();
    while cursor < rdata.len() {
        let Some(length) = rdata.get(cursor).copied().map(usize::from) else {
            break;
        };
        cursor += 1;
        let end = (cursor + length).min(rdata.len());
        values.push(String::from_utf8_lossy(&rdata[cursor..end]).to_string());
        cursor = end;
    }
    values.join(" ")
}

fn parse_dns_name(packet: &[u8], offset: &mut usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut cursor = *offset;
    let mut jumped = false;
    let mut jumps = 0usize;

    loop {
        let length = *packet.get(cursor)?;
        if length & 0xc0 == 0xc0 {
            let next = *packet.get(cursor + 1)?;
            let pointer = ((((length & 0x3f) as u16) << 8) | next as u16) as usize;
            if !jumped {
                *offset = cursor + 2;
            }
            cursor = pointer;
            jumped = true;
            jumps += 1;
            if jumps > 16 {
                return None;
            }
            continue;
        }
        if length & 0xc0 != 0 {
            return None;
        }
        if length == 0 {
            if !jumped {
                *offset = cursor + 1;
            }
            break;
        }

        cursor += 1;
        let end = cursor.checked_add(length as usize)?;
        let label = packet.get(cursor..end)?;
        labels.push(String::from_utf8_lossy(label).to_string());
        cursor = end;
        if !jumped {
            *offset = cursor;
        }
    }

    if labels.is_empty() {
        Some(".".to_string())
    } else {
        Some(labels.join("."))
    }
}

fn read_u16(packet: &[u8], offset: usize) -> Option<u16> {
    let bytes = packet.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(packet: &[u8], offset: usize) -> Option<u32> {
    let bytes = packet.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn dns_rcode_name(rcode: u16) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "ERROR",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dns_query_name_and_type() {
        let packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];

        assert_eq!(
            parse_dns_query(&packet),
            Some(("example.com".to_string(), "A".to_string()))
        );
    }

    #[test]
    fn rejects_dns_response_as_query() {
        let packet = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x5d,
            0xb8, 0xd8, 0x22,
        ];

        assert_eq!(parse_dns_query(&packet), None);
    }

    #[test]
    fn rejects_dns_query_with_trailing_bytes() {
        let mut packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        packet.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

        assert_eq!(parse_dns_query(&packet), None);
    }

    #[test]
    fn parses_dns_response_answers() {
        let response = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x5d,
            0xb8, 0xd8, 0x22,
        ];

        let parsed = parse_dns_response(&response).unwrap();
        assert_eq!(parsed.status, "NOERROR");
        assert_eq!(parsed.answers, vec!["93.184.216.34"]);
        assert_eq!(parsed.min_ttl, Some(60));
    }

    #[test]
    fn dns_response_cache_rewrites_transaction_id_on_hit() {
        let response = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x5d,
            0xb8, 0xd8, 0x22,
        ];
        let summary = parse_dns_response(&response).unwrap();
        let mut cache = DnsResponseCache::default();

        cache.insert("Example.COM.", "a", &summary, &response);

        let cached = cache.get("example.com", "A", 0xabcd).unwrap();
        assert_eq!(dns_id(&cached), Some(0xabcd));
        assert_eq!(&cached[2..], &response[2..]);
    }
}
