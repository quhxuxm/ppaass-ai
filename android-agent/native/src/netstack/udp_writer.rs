//! Buffered single-writer path for UDP packets returning to netstack.

use std::io;

use common::spawn_guarded;
use futures::SinkExt;
use netstack_smoltcp::udp::{UdpMsg, WriteHalf};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::debug;

const UDP_WRITE_CHANNEL_SIZE: usize = 2048;
const UDP_WRITE_BATCH_LIMIT: usize = 64;

/// Decouples concurrent UDP socket reads from packet construction and TUN
/// backpressure while keeping the netstack sink serialized.
#[derive(Clone)]
pub(super) struct UdpWriter {
    tx: mpsc::Sender<UdpMsg>,
}

impl UdpWriter {
    pub(super) fn spawn(sink: WriteHalf, shutdown: CancellationToken) -> Self {
        let (tx, rx) = mpsc::channel(UDP_WRITE_CHANNEL_SIZE);
        spawn_guarded(
            "android UDP netstack writer",
            run_udp_writer(sink, rx, shutdown),
        );
        Self { tx }
    }

    pub(super) async fn send(&self, packet: UdpMsg) -> io::Result<()> {
        self.tx
            .send(packet)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "UDP netstack writer closed"))
    }
}

async fn run_udp_writer(
    mut sink: WriteHalf,
    mut rx: mpsc::Receiver<UdpMsg>,
    shutdown: CancellationToken,
) {
    loop {
        let first = tokio::select! {
            _ = shutdown.cancelled() => break,
            packet = rx.recv() => {
                let Some(packet) = packet else { break };
                packet
            }
        };

        if let Err(error) = sink.feed(first).await {
            debug!(%error, "Android UDP netstack writer stopped while feeding a packet");
            break;
        }

        for _ in 1..UDP_WRITE_BATCH_LIMIT {
            let packet = match rx.try_recv() {
                Ok(packet) => packet,
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => break,
            };
            if let Err(error) = sink.feed(packet).await {
                debug!(%error, "Android UDP netstack writer stopped while feeding a batch");
                return;
            }
        }

        if let Err(error) = sink.flush().await {
            debug!(%error, "Android UDP netstack writer stopped while flushing");
            break;
        }
    }
}
