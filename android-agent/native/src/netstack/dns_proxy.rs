use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
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
    expires_at: Instant,
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

    cleanup_pending_dns(pending);
    let Some(upstream_id) = allocate_dns_id(pending, next_id) else {
        warn!("Android TUN DNS pending table is full; dropping request");
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
        debug!("Android TUN DNS response is too short; dropping");
        return Ok(());
    };

    let Some(request) = pending.remove(&upstream_id) else {
        debug!("Android TUN DNS response had no matching id={upstream_id}");
        return Ok(());
    };

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
