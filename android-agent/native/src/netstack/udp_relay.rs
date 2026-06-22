use std::collections::{HashMap, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::spawn_guarded;
use futures::SinkExt;
use protocol::{Address, TransportProtocol, UdpRelayPacket};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use super::ForwardContext;
use super::udp::UdpWriter;
use crate::error::Result;

const UDP_FLOW_TTL: Duration = Duration::from_secs(300);
const UDP_RELAY_CHANNEL_SIZE: usize = 4096;
const UDP_RELAY_SHARD_COUNT: usize = 4;
const UDP_RELAY_CONNECTION_IDLE: Duration = Duration::from_secs(30);

pub(super) struct UdpRelay {
    shards: Vec<mpsc::Sender<UdpRelayRequest>>,
}

#[derive(Clone)]
struct UdpRelayRequest {
    client: SocketAddr,
    target: SocketAddr,
    address: Address,
    packet: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct UdpFlowKey {
    client: SocketAddr,
    target: SocketAddr,
}

struct UdpRelayState {
    flow_ids: HashMap<UdpFlowKey, u64>,
    flows: HashMap<u64, UdpFlowKey>,
    last_seen: HashMap<u64, Instant>,
    next_flow_id: u64,
}

impl UdpRelayState {
    fn new() -> Self {
        Self {
            flow_ids: HashMap::new(),
            flows: HashMap::new(),
            last_seen: HashMap::new(),
            next_flow_id: 1,
        }
    }

    fn flow_id(&mut self, client: SocketAddr, target: SocketAddr) -> u64 {
        let key = UdpFlowKey { client, target };
        if let Some(id) = self.flow_ids.get(&key) {
            self.last_seen.insert(*id, Instant::now());
            return *id;
        }

        let id = self.next_available_flow_id();
        self.flow_ids.insert(key, id);
        self.flows.insert(id, key);
        self.last_seen.insert(id, Instant::now());
        id
    }

    fn flow(&self, flow_id: u64) -> Option<UdpFlowKey> {
        self.flows.get(&flow_id).copied()
    }

    fn active_flows(&self) -> usize {
        self.flows.len()
    }

    fn tracked_flow_keys(&self) -> usize {
        self.flow_ids.len()
    }

    fn next_available_flow_id(&mut self) -> u64 {
        loop {
            let id = self.next_flow_id;
            self.next_flow_id = self.next_flow_id.wrapping_add(1).max(1);
            if !self.flows.contains_key(&id) {
                return id;
            }
        }
    }

    fn cleanup_expired(&mut self) {
        let now = Instant::now();
        let expired: Vec<u64> = self
            .last_seen
            .iter()
            .filter_map(|(id, last_seen)| ((*last_seen + UDP_FLOW_TTL) <= now).then_some(*id))
            .collect();

        for id in expired {
            self.last_seen.remove(&id);
            if let Some(key) = self.flows.remove(&id) {
                self.flow_ids.remove(&key);
            }
        }
    }
}

impl UdpRelay {
    pub(super) fn spawn(
        context: ForwardContext,
        netstack_tx: UdpWriter,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        let mut shards = Vec::with_capacity(UDP_RELAY_SHARD_COUNT);
        for shard_index in 0..UDP_RELAY_SHARD_COUNT {
            let (tx, rx) = mpsc::channel(UDP_RELAY_CHANNEL_SIZE);
            shards.push(tx);
            debug!("starting Android TUN UDP relay shard {shard_index}");
            spawn_guarded(
                "android tun udp relay",
                run_udp_relay(context.clone(), netstack_tx.clone(), rx, shutdown.clone()),
            );
        }
        Arc::new(Self { shards })
    }

    pub(super) fn send(
        &self,
        client: SocketAddr,
        target: SocketAddr,
        address: Address,
        packet: Vec<u8>,
    ) {
        let shard_index = udp_relay_shard_index(client, target, self.shards.len());
        match self.shards[shard_index].try_send(UdpRelayRequest {
            client,
            target,
            address,
            packet,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                debug!("Android TUN UDP relay queue is full; dropping packet");
            }
            Err(TrySendError::Closed(_)) => {
                debug!("Android TUN UDP relay is closed; dropping packet");
            }
        }
    }
}

fn udp_relay_shard_index(client: SocketAddr, target: SocketAddr, shard_count: usize) -> usize {
    debug_assert!(shard_count > 0);
    let key = UdpFlowKey { client, target };
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    (hasher.finish() % shard_count as u64) as usize
}

async fn run_udp_relay(
    context: ForwardContext,
    netstack_tx: UdpWriter,
    mut rx: mpsc::Receiver<UdpRelayRequest>,
    shutdown: CancellationToken,
) {
    let mut state = UdpRelayState::new();
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

        let connected = connect_udp_relay_stream(&context).await;
        let proxy_io = match connected {
            Ok(proxy_io) => {
                reconnect_delay = Duration::from_millis(200);
                proxy_io
            }
            Err(e) => {
                warn!("Android TUN UDP relay connection failed: {e}");
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(reconnect_delay) => {}
                }
                reconnect_delay = (reconnect_delay * 2).min(Duration::from_secs(5));
                retry_request = Some(first_request);
                continue;
            }
        };

        debug!("Android TUN UDP relay connected");
        let (mut reader, mut writer) = tokio::io::split(proxy_io);
        let mut cleanup = tokio::time::interval(Duration::from_secs(60));
        cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let idle_sleep = tokio::time::sleep(UDP_RELAY_CONNECTION_IDLE);
        tokio::pin!(idle_sleep);
        retry_request = Some(first_request);
        let mut response_buf = vec![0u8; 65535];

        loop {
            if let Some(request) = retry_request.take() {
                if let Err(e) = send_udp_relay_request(&mut writer, &mut state, &request).await {
                    debug!("Android TUN UDP relay write failed: {e}");
                    retry_request = Some(request);
                    break;
                }
                idle_sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + UDP_RELAY_CONNECTION_IDLE);
                continue;
            }

            tokio::select! {
                _ = shutdown.cancelled() => {
                    let _ = writer.shutdown().await;
                    return;
                }
                _ = &mut idle_sleep => {
                    debug!("Android TUN UDP relay idle; closing connection");
                    let _ = writer.shutdown().await;
                    break;
                }
                _ = cleanup.tick() => {
                    state.cleanup_expired();
                    debug!(
                        "Android TUN UDP relay shard stats: active_flows={} tracked_flow_keys={}",
                        state.active_flows(),
                        state.tracked_flow_keys()
                    );
                },
                maybe_request = rx.recv() => {
                    let Some(request) = maybe_request else {
                        let _ = writer.shutdown().await;
                        return;
                    };
                    if let Err(e) = send_udp_relay_request(&mut writer, &mut state, &request).await {
                        debug!("Android TUN UDP relay write failed: {e}");
                        retry_request = Some(request);
                        break;
                    }
                    idle_sleep.as_mut().reset(
                        tokio::time::Instant::now() + UDP_RELAY_CONNECTION_IDLE,
                    );
                }
                read = reader.read(&mut response_buf) => {
                    match read {
                        Ok(0) => {
                            debug!("Android TUN UDP relay closed");
                            break;
                        }
                        Ok(n) => {
                            if let Err(e) = handle_udp_relay_response(
                                &netstack_tx,
                                &state,
                                &response_buf[..n],
                            ).await {
                                debug!("Android TUN UDP relay response failed: {e}");
                            }
                            idle_sleep.as_mut().reset(
                                tokio::time::Instant::now() + UDP_RELAY_CONNECTION_IDLE,
                            );
                        }
                        Err(e) => {
                            debug!("Android TUN UDP relay read failed: {e}");
                            break;
                        }
                    }
                }
            }
        }
    }

    debug!("Android TUN UDP relay exited");
}

async fn connect_udp_relay_stream(
    context: &ForwardContext,
) -> Result<impl AsyncRead + AsyncWrite + Unpin + Send + 'static> {
    context
        .udp_pool
        .get_connected_stream(Address::UdpRelay, TransportProtocol::Udp)
        .await
}

async fn send_udp_relay_request<W>(
    writer: &mut W,
    state: &mut UdpRelayState,
    request: &UdpRelayRequest,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let flow_id = state.flow_id(request.client, request.target);
    let packet = UdpRelayPacket {
        flow_id,
        address: request.address.clone(),
        data: request.packet.clone(),
    }
    .encode()
    .map_err(io::Error::other)?;

    writer.write_all(&packet).await?;
    writer.flush().await
}

async fn handle_udp_relay_response(
    netstack_tx: &UdpWriter,
    state: &UdpRelayState,
    response: &[u8],
) -> io::Result<()> {
    let packet = UdpRelayPacket::decode(response).map_err(io::Error::other)?;
    let Some(flow) = state.flow(packet.flow_id) else {
        debug!(
            "Android TUN UDP relay response had no matching flow id={}",
            packet.flow_id
        );
        return Ok(());
    };

    let mut tx = netstack_tx.lock().await;
    tx.send((packet.data, flow.target, flow.client)).await
}
