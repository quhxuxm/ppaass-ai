use super::udp::UdpWriter;
use crate::connection_pool::ConnectionPool;
use futures::SinkExt;
use protocol::{Address, TransportProtocol};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

const DNS_PENDING_TTL: Duration = Duration::from_secs(10);
const DNS_REQUEST_CHANNEL_SIZE: usize = 1024;
const DNS_PROXY_CONNECTION_IDLE: Duration = Duration::from_secs(15);

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
    expires_at: Instant,
}

impl DnsProxy {
    pub(super) fn spawn(
        pool: Arc<ConnectionPool>,
        netstack_tx: UdpWriter,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(DNS_REQUEST_CHANNEL_SIZE);
        tokio::spawn(run_dns_proxy(pool, netstack_tx, rx, shutdown));
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

    cleanup_pending_dns(pending);
    let Some(upstream_id) = allocate_dns_id(pending, next_id) else {
        warn!("TUN UDP DNS 待处理请求过多，已丢弃一个请求");
        return Ok(());
    };

    let mut packet = request.packet.clone();
    write_dns_id(&mut packet, upstream_id);
    pending.insert(
        upstream_id,
        PendingDnsRequest {
            client: request.client,
            target: request.target,
            original_id,
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
        debug!("TUN UDP DNS 回复过短，已丢弃");
        return Ok(());
    };

    let Some(request) = pending.remove(&upstream_id) else {
        debug!("TUN UDP DNS 收到无匹配请求的回复 id={upstream_id}");
        return Ok(());
    };

    write_dns_id(response, request.original_id);
    let mut s = netstack_tx.lock().await;
    s.send((response.to_vec(), request.target, request.client))
        .await
}

fn cleanup_pending_dns(pending: &mut HashMap<u16, PendingDnsRequest>) {
    let now = Instant::now();
    pending.retain(|_, request| request.expires_at > now);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_skips_pending_ids() {
        let mut pending = HashMap::new();
        pending.insert(
            0,
            PendingDnsRequest {
                client: "127.0.0.1:10000".parse().unwrap(),
                target: "10.10.10.2:53".parse().unwrap(),
                original_id: 42,
                expires_at: Instant::now() + DNS_PENDING_TTL,
            },
        );
        let mut next_id = 0;

        assert_eq!(allocate_dns_id(&pending, &mut next_id), Some(1));
        assert_eq!(next_id, 2);
    }

    #[test]
    fn rewrites_dns_transaction_id() {
        let mut packet = vec![0x12, 0x34, 0x01, 0x00];
        assert_eq!(dns_id(&packet), Some(0x1234));

        write_dns_id(&mut packet, 0xabcd);
        assert_eq!(dns_id(&packet), Some(0xabcd));
        assert_eq!(&packet[2..], &[0x01, 0x00]);
    }
}
