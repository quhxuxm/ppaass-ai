use std::collections::HashMap;
use std::convert::TryInto;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::spawn_guarded;
use futures::SinkExt;
use protocol::{Address, TransportProtocol};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use super::ForwardContext;
use super::udp::UdpWriter;
use crate::error::Result;
use crate::traffic_stats::{self, DnsResolutionRecord};

const DNS_PENDING_TTL: Duration = Duration::from_secs(10);
const DNS_PROXY_CONNECTION_IDLE: Duration = Duration::from_secs(15);
const DNS_REQUEST_CHANNEL_SIZE: usize = 1024;

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

        let connected = connect_dns_stream(&context).await;
        let proxy_io = match connected {
            Ok(proxy_io) => {
                reconnect_delay = Duration::from_millis(200);
                proxy_io
            }
            Err(e) => {
                warn!("Android TUN DNS proxy connection failed: {e}");
                android_log_error(format!("Android TUN DNS proxy connection failed: {e}"));
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
        .udp_pool
        .get_connected_stream(Address::ProxyDns { port: 53 }, TransportProtocol::Udp)
        .await
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
    });
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

fn parse_dns_query(packet: &[u8]) -> Option<(String, String)> {
    if packet.len() < 12 || read_u16(packet, 4)? == 0 {
        return None;
    }

    let mut offset = 12;
    let query = parse_dns_name(packet, &mut offset)?;
    let record_type = dns_type_name(read_u16(packet, offset)?).to_string();
    Some((query, record_type))
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
    for _ in 0..ancount {
        parse_dns_name(packet, &mut offset)?;
        let record_type = read_u16(packet, offset)?;
        offset = offset.checked_add(2)?;
        let _class = read_u16(packet, offset)?;
        offset = offset.checked_add(2)?;
        let _ttl = read_u32(packet, offset)?;
        offset = offset.checked_add(4)?;
        let rdlength = read_u16(packet, offset)? as usize;
        offset = offset.checked_add(2)?;
        let rdata_offset = offset;
        let rdata_end = offset.checked_add(rdlength)?;
        if rdata_end > packet.len() {
            return None;
        }

        if let Some(answer) = parse_dns_answer_rdata(packet, rdata_offset, rdlength, record_type) {
            answers.push(answer);
        }
        offset = rdata_end;
    }

    Some(DnsResponseSummary {
        status: dns_rcode_name(flags & 0x000f).to_string(),
        answers,
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

fn dns_type_name(record_type: u16) -> String {
    match record_type {
        1 => "A".to_string(),
        2 => "NS".to_string(),
        5 => "CNAME".to_string(),
        6 => "SOA".to_string(),
        12 => "PTR".to_string(),
        15 => "MX".to_string(),
        16 => "TXT".to_string(),
        28 => "AAAA".to_string(),
        33 => "SRV".to_string(),
        64 => "SVCB".to_string(),
        65 => "HTTPS".to_string(),
        255 => "ANY".to_string(),
        other => format!("TYPE{other}"),
    }
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

fn android_log_error(message: impl AsRef<str>) {
    #[cfg(target_os = "android")]
    {
        use std::ffi::CString;

        const ANDROID_LOG_ERROR: libc::c_int = 6;
        let text = message.as_ref().replace('\0', " ");
        let Ok(tag) = CString::new("PPAASS-Native") else {
            return;
        };
        let Ok(text) = CString::new(text) else {
            return;
        };
        unsafe {
            __android_log_write(ANDROID_LOG_ERROR, tag.as_ptr(), text.as_ptr());
        }
    }

    #[cfg(not(target_os = "android"))]
    {
        let _ = message;
    }
}

#[cfg(target_os = "android")]
#[link(name = "log")]
unsafe extern "C" {
    fn __android_log_write(
        prio: libc::c_int,
        tag: *const libc::c_char,
        text: *const libc::c_char,
    ) -> libc::c_int;
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
    }
}
