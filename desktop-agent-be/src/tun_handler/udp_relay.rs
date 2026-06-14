//! TUN 普通 UDP 的共享 proxy relay。
//!
//! 与 `handle_tun_udp` 的单会话 proxy stream 不同，这里把多个 UDP source/target flow
//! 复用到一条 `Address::UdpRelay` 连接上。适合 QUIC 等高并发 UDP，能减少频繁建连。

use super::udp::UdpWriter;
use crate::connection_pool::ConnectionPool;
use common::spawn_guarded;
use futures::SinkExt;
use protocol::{Address, TransportProtocol, UdpRelayPacket};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

const UDP_RELAY_CHANNEL_SIZE: usize = 4096;
const UDP_FLOW_TTL: Duration = Duration::from_secs(300);
const UDP_RELAY_CONNECTION_IDLE: Duration = Duration::from_secs(30);

pub(super) struct UdpRelay {
    tx: mpsc::Sender<UdpRelayRequest>,
}

#[derive(Clone)]
struct UdpRelayRequest {
    client: SocketAddr,
    target: SocketAddr,
    address: Address,
    packet: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq)]
struct UdpFlowKey {
    client: SocketAddr,
    target: SocketAddr,
}

impl PartialEq for UdpFlowKey {
    fn eq(&self, other: &Self) -> bool {
        self.client == other.client && self.target == other.target
    }
}

impl Hash for UdpFlowKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.client.hash(state);
        self.target.hash(state);
    }
}

struct UdpRelayState {
    // (client,target) -> flow_id，保证同一 UDP flow 在 proxy 端对应同一个 UDP socket。
    flow_ids: HashMap<UdpFlowKey, u64>,
    // flow_id -> (client,target)，用于把 proxy 响应写回正确的 netstack 方向。
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
        pool: Arc<ConnectionPool>,
        netstack_tx: UdpWriter,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(UDP_RELAY_CHANNEL_SIZE);
        spawn_guarded(
            "desktop tun udp relay",
            run_udp_relay(pool, netstack_tx, rx, shutdown),
        );
        Arc::new(Self { tx })
    }

    pub(super) fn send(
        &self,
        client: SocketAddr,
        target: SocketAddr,
        address: Address,
        packet: Vec<u8>,
    ) {
        match self.tx.try_send(UdpRelayRequest {
            client,
            target,
            address,
            packet,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => debug!("TUN UDP 共享转发队列已满，丢弃一个 UDP 包"),
            Err(TrySendError::Closed(_)) => debug!("TUN UDP 共享转发器已关闭，丢弃请求"),
        }
    }
}

async fn run_udp_relay(
    pool: Arc<ConnectionPool>,
    netstack_tx: UdpWriter,
    mut rx: mpsc::Receiver<UdpRelayRequest>,
    shutdown: CancellationToken,
) {
    let mut state = UdpRelayState::new();
    // 写入失败时保留当前请求，重建共享连接后优先重发，避免首包直接丢失。
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

        let connected = connect_udp_relay_stream(&pool).await;
        let proxy_io = match connected {
            Ok(proxy_io) => {
                reconnect_delay = Duration::from_millis(200);
                proxy_io
            }
            Err(e) => {
                warn!("TUN UDP 共享连接创建失败：{e}");
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(reconnect_delay) => {}
                }
                reconnect_delay = (reconnect_delay * 2).min(Duration::from_secs(5));
                retry_request = Some(first_request);
                continue;
            }
        };

        debug!("TUN UDP 已建立共享 proxy 连接");
        let (mut reader, mut writer) = tokio::io::split(proxy_io);
        let mut cleanup = tokio::time::interval(Duration::from_secs(60));
        cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let idle = tokio::time::sleep(UDP_RELAY_CONNECTION_IDLE);
        tokio::pin!(idle);
        retry_request = Some(first_request);
        let mut response_buf = vec![0u8; 65535];

        loop {
            if let Some(request) = retry_request.take() {
                if let Err(e) = send_udp_request(&mut writer, &mut state, &request).await {
                    debug!("TUN UDP 共享连接写入失败：{e}");
                    retry_request = Some(request);
                    break;
                }
                idle.as_mut()
                    .reset(tokio::time::Instant::now() + UDP_RELAY_CONNECTION_IDLE);
                continue;
            }

            tokio::select! {
                _ = shutdown.cancelled() => {
                    let _ = writer.shutdown().await;
                    return;
                }
                _ = &mut idle => {
                    debug!(
                        "TUN UDP 共享连接空闲超过 {} 秒，主动关闭 proxy 连接",
                        UDP_RELAY_CONNECTION_IDLE.as_secs()
                    );
                    let _ = writer.shutdown().await;
                    break;
                }
                _ = cleanup.tick() => state.cleanup_expired(),
                maybe_request = rx.recv() => {
                    let Some(request) = maybe_request else {
                        let _ = writer.shutdown().await;
                        return;
                    };
                    if let Err(e) = send_udp_request(&mut writer, &mut state, &request).await {
                        debug!("TUN UDP 共享连接写入失败：{e}");
                        retry_request = Some(request);
                        break;
                    }
                    idle.as_mut().reset(tokio::time::Instant::now() + UDP_RELAY_CONNECTION_IDLE);
                }
                read = reader.read(&mut response_buf) => {
                    match read {
                        Ok(0) => {
                            debug!("TUN UDP 共享连接已关闭");
                            break;
                        }
                        Ok(n) => {
                            if let Err(e) = handle_udp_response(
                                &netstack_tx,
                                &state,
                                &response_buf[..n],
                            ).await {
                                debug!("TUN UDP 回复写回失败：{e}");
                            }
                            idle.as_mut().reset(tokio::time::Instant::now() + UDP_RELAY_CONNECTION_IDLE);
                        }
                        Err(e) => {
                            debug!("TUN UDP 共享连接读取失败：{e}");
                            break;
                        }
                    }
                }
            }
        }
    }

    debug!("TUN UDP 共享转发器退出");
}

async fn connect_udp_relay_stream(
    pool: &ConnectionPool,
) -> crate::error::Result<impl AsyncRead + AsyncWrite + Unpin + Send + 'static> {
    let connected = pool
        .get_connected_stream(Address::UdpRelay, TransportProtocol::Udp)
        .await?;
    Ok(connected.into_async_io())
}

async fn send_udp_request<W>(
    writer: &mut W,
    state: &mut UdpRelayState,
    request: &UdpRelayRequest,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    // 每个 TUN UDP datagram 被编码成 UdpRelayPacket，proxy 根据 flow_id/address 发往目标。
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

async fn handle_udp_response(
    netstack_tx: &UdpWriter,
    state: &UdpRelayState,
    response: &[u8],
) -> io::Result<()> {
    // proxy 回复带 flow_id；agent 还原原始 client/target 后写回 netstack。
    let packet = UdpRelayPacket::decode(response).map_err(io::Error::other)?;
    let Some(flow) = state.flow(packet.flow_id) else {
        debug!("TUN UDP 收到无匹配 flow 的回复 id={}", packet.flow_id);
        return Ok(());
    };

    let mut s = netstack_tx.lock().await;
    s.send((packet.data, flow.target, flow.client)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assigns_stable_flow_ids() {
        let mut state = UdpRelayState::new();
        let client: SocketAddr = "10.10.10.2:10000".parse().unwrap();
        let target: SocketAddr = "8.8.8.8:443".parse().unwrap();

        let first = state.flow_id(client, target);
        let second = state.flow_id(client, target);

        assert_eq!(first, second);
        assert_eq!(state.flow(first).unwrap().client, client);
        assert_eq!(state.flow(first).unwrap().target, target);
    }
}
