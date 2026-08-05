use std::collections::HashMap;
use std::convert::TryInto;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{dns::parse_dns_query_packet, spawn_guarded};
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
use super::udp_writer::UdpWriter;
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

pub struct DnsResponseSummary {
    pub status: String,
    pub answers: Vec<String>,
    pub min_ttl: Option<u32>,
}

mod cache;
mod direct;
mod wire;
pub use cache::DnsResponseCache;
use direct::*;
use wire::*;
pub use wire::{dns_id, parse_dns_query, parse_dns_response};

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
                warn!("Android TUN DNS proxy connection failed; retrying");
                debug!(error = %e, "Android TUN DNS proxy connection failure details");
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
