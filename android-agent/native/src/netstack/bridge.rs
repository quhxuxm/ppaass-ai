use std::sync::Arc;

use common::spawn_guarded;
use futures::{SinkExt, StreamExt};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::fd_device::AndroidTunDevice;

pub(super) fn spawn_packet_bridge(
    device: Arc<AndroidTunDevice>,
    stack: netstack_smoltcp::Stack,
    mtu: usize,
    shutdown: CancellationToken,
) -> (JoinHandle<()>, JoinHandle<()>) {
    let (mut stack_sink, mut stack_stream) = stack.split();

    let input_device = device.clone();
    let input_shutdown = shutdown.clone();
    let tun_to_stack = spawn_guarded("android tun_to_stack", async move {
        let mut buf = vec![0u8; mtu.max(1500) + 64];
        loop {
            tokio::select! {
                _ = input_shutdown.cancelled() => break,
                read = input_device.recv(&mut buf) => {
                    match read {
                        Ok(n) if n > 0 => {
                            if let Err(e) = stack_sink.send(buf[..n].to_vec()).await {
                                warn!("failed to push packet into netstack: {e}");
                                break;
                            }
                        }
                        Ok(_) => continue,
                        Err(e) => {
                            warn!("failed to read Android VPN fd: {e}");
                            break;
                        }
                    }
                }
            }
        }
        debug!("android tun_to_stack task exited");
    });

    let output_shutdown = shutdown;
    let stack_to_tun = spawn_guarded("android stack_to_tun", async move {
        loop {
            tokio::select! {
                _ = output_shutdown.cancelled() => break,
                packet = stack_stream.next() => {
                    match packet {
                        Some(Ok(packet)) => {
                            if let Err(e) = device.send(&packet).await {
                                warn!("failed to write packet to Android VPN fd: {e}");
                                break;
                            }
                        }
                        Some(Err(e)) => warn!("netstack stream error: {e}"),
                        None => break,
                    }
                }
            }
        }
        debug!("android stack_to_tun task exited");
    });

    (tun_to_stack, stack_to_tun)
}
