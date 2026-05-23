use std::sync::Arc;

use common::spawn_guarded;
use futures::StreamExt;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use super::ForwardContext;
use super::dns_proxy::DnsProxy;
use super::network::reject_tun_target;
use super::udp_relay::UdpRelay;

pub(super) type UdpWriter = Arc<tokio::sync::Mutex<netstack_smoltcp::udp::WriteHalf>>;

pub(super) fn spawn_udp_sessions(
    udp_socket: netstack_smoltcp::UdpSocket,
    context: ForwardContext,
    block_quic: bool,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    spawn_guarded("android udp sessions", async move {
        let (mut udp_rx, udp_tx) = udp_socket.split();
        let udp_tx = Arc::new(tokio::sync::Mutex::new(udp_tx));
        let dns_proxy = context
            .proxy_dns
            .then(|| DnsProxy::spawn(context.clone(), udp_tx.clone(), shutdown.clone()));
        let udp_relay = UdpRelay::spawn(context.clone(), udp_tx.clone(), shutdown.clone());

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                message = udp_rx.next() => {
                    let Some((data, source, target)) = message else { break };
                    if context.proxy_dns && target.port() == 53 {
                        if let Some(dns_proxy) = &dns_proxy {
                            dns_proxy.send(source, target, data);
                        }
                        continue;
                    }

                    if context.tun_networks.is_ipv4_broadcast(target.ip()) {
                        debug!("Android TUN UDP broadcast dropped -> {}", target);
                        continue;
                    }
                    if let Err(e) = reject_tun_target("UDP", source, target, context.tun_networks)
                    {
                        debug!("Android TUN UDP target rejected: {e}");
                        continue;
                    }
                    if block_quic && target.port() == 443 {
                        debug!("Android TUN UDP/443 QUIC dropped -> {}", target);
                        continue;
                    }
                    udp_relay.send(source, target, data);
                }
            }
        }
        debug!("android UDP session task exited");
    })
}
