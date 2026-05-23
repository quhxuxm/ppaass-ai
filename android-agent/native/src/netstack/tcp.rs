use std::net::SocketAddr;

use common::{DEFAULT_STREAM_RELAY_BUFFER_SIZE, spawn_guarded};
use futures::StreamExt;
use protocol::TransportProtocol;
use tokio::io::AsyncWriteExt;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use super::ForwardContext;
use super::network::{address_for_tun_target, reject_tun_target};
use crate::error::{AndroidAgentError, Result};

pub(super) fn spawn_tcp_listener(
    mut tcp_listener: netstack_smoltcp::TcpListener,
    context: ForwardContext,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    spawn_guarded("android tcp listener", async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                accepted = tcp_listener.next() => {
                    let Some((stream, source, target)) = accepted else { break };
                    let context = context.clone();
                    spawn_guarded("android tun tcp flow", async move {
                        if let Err(err) = handle_tcp(stream, source, target, context).await {
                            debug!("TUN TCP flow ended: {err}");
                        }
                    });
                }
            }
        }
        debug!("android TCP listener task exited");
    })
}

async fn handle_tcp(
    mut client: netstack_smoltcp::TcpStream,
    source: SocketAddr,
    target: SocketAddr,
    context: ForwardContext,
) -> Result<()> {
    let (address, proxy_dns_request) = address_for_tun_target(target, context.proxy_dns);
    if !proxy_dns_request {
        reject_tun_target("TCP", source, target, context.tun_networks)?;
    }

    debug!("Android TUN TCP proxy -> {}", target);
    let mut proxy_io = context
        .tcp_pool
        .get_connected_stream(address, TransportProtocol::Tcp)
        .await
        .map_err(|e| AndroidAgentError::Connection(e.to_string()))?;
    if let Err(e) = tokio::io::copy_bidirectional_with_sizes(
        &mut client,
        &mut proxy_io,
        DEFAULT_STREAM_RELAY_BUFFER_SIZE,
        DEFAULT_STREAM_RELAY_BUFFER_SIZE,
    )
    .await
    {
        debug!("Android TUN TCP proxy relay ended: {e}");
    }
    let _ = client.shutdown().await;
    Ok(())
}
