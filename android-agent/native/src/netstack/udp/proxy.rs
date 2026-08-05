use std::net::SocketAddr;
use std::sync::Arc;

use protocol::{Address, TransportProtocol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace};

use super::{UDP_SESSION_IDLE, UdpWriter};
use crate::error::Result;
use crate::yamux_session::AndroidYamuxSessionManager;

pub(super) struct ProxyUdpRelayContext {
    pub(super) client: SocketAddr,
    pub(super) target: SocketAddr,
    pub(super) target_label: String,
    pub(super) proxy_label: String,
    pub(super) proxy_dns_request: bool,
    pub(super) proxy_address: Address,
    pub(super) rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    pub(super) netstack_tx: UdpWriter,
    pub(super) udp_sessions: Arc<AndroidYamuxSessionManager>,
    pub(super) shutdown: CancellationToken,
}

pub(super) async fn relay_proxy_udp(context: ProxyUdpRelayContext) -> Result<()> {
    let ProxyUdpRelayContext {
        client,
        target,
        target_label,
        proxy_label,
        proxy_dns_request,
        proxy_address,
        mut rx,
        netstack_tx,
        udp_sessions,
        shutdown,
    } = context;

    if proxy_dns_request {
        debug!("Android TUN UDP DNS -> proxy -> {}", target_label);
    } else {
        debug!("Android TUN UDP fallback proxy -> {}", proxy_label);
    }
    let proxy_io = match udp_sessions
        .connect_to_target(proxy_address, TransportProtocol::Udp)
        .await
    {
        Ok(proxy_io) => proxy_io,
        Err(error) => {
            debug!("Android TUN UDP proxy connect failed {proxy_label}: {error}");
            return Err(error);
        }
    };
    let (mut reader, mut writer) = tokio::io::split(proxy_io);
    let idle_sleep = tokio::time::sleep(UDP_SESSION_IDLE);
    tokio::pin!(idle_sleep);
    let mut response_buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = &mut idle_sleep => {
                debug!("Android UDP proxy session idle; closing -> {}", target_label);
                break;
            }
            maybe_data = rx.recv() => {
                let Some(data) = maybe_data else { break };
                trace!("Android UDP proxy write -> {} bytes={}", target_label, data.len());
                if let Err(error) = writer.write_all(&data).await {
                    debug!("Android UDP proxy write failed: {error}");
                    break;
                }
                if let Err(error) = writer.flush().await {
                    debug!("Android UDP proxy flush failed: {error}");
                    break;
                }
                idle_sleep.as_mut().reset(tokio::time::Instant::now() + UDP_SESSION_IDLE);
            }
            read = reader.read(&mut response_buf) => {
                match read {
                    Ok(0) => break,
                    Ok(size) => {
                        trace!(
                            "Android UDP proxy read <- {} bytes={} writeback {} -> {}",
                            target_label, size, target, client
                        );
                        let packet = response_buf[..size].to_vec();
                        if let Err(error) = netstack_tx.send((packet, target, client)).await {
                            debug!("Android UDP proxy response writeback failed: {error}");
                            break;
                        }
                        idle_sleep.as_mut().reset(
                            tokio::time::Instant::now() + UDP_SESSION_IDLE,
                        );
                    }
                    Err(error) => {
                        debug!("Android UDP proxy read failed: {error}");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}
