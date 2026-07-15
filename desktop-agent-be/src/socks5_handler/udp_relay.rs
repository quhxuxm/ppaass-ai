//! SOCKS5 UDP 的共享 proxy relay。
//!
//! 多个 SOCKS5 UDP 目标会按稳定哈希分片到多条 `Address::UdpRelay` proxy stream。
//! 每个客户端/目标组合映射到一个 flow_id，proxy 端据此维护真实 UDP socket。

use super::udp_associate::create_udp_packet;
use super::*;
use crate::telemetry;
use protocol::udp_transport::UDP_MAX_MESSAGE_SIZE;
use std::collections::hash_map::DefaultHasher;

const SOCKS_UDP_RELAY_CHANNEL_SIZE: usize = 4096;
const SOCKS_UDP_RELAY_SHARD_COUNT: usize = 4;
const SOCKS_UDP_RELAY_CONNECTION_IDLE: Duration = Duration::from_secs(30);

pub(super) struct SocksUdpRelay {
    shards: Vec<tokio::sync::mpsc::Sender<SocksUdpRelayRequest>>,
}

#[derive(Clone)]
pub(super) struct SocksUdpRelayRequest {
    client: SocketAddr,
    target: Address,
    packet: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct SocksUdpFlowKey {
    client: SocketAddr,
    target: Address,
}

pub(super) struct SocksUdpRelayState {
    // (client,target) -> flow_id，保证同一 UDP 会话在 proxy 端复用同一个 socket。
    flow_ids: HashMap<SocksUdpFlowKey, u64>,
    // flow_id -> (client,target)，用于把 proxy 响应重新封装后发回 SOCKS 客户端。
    flows: HashMap<u64, (SocketAddr, Address)>,
    next_flow_id: u64,
}

impl SocksUdpRelayState {
    fn new() -> Self {
        Self {
            flow_ids: HashMap::new(),
            flows: HashMap::new(),
            next_flow_id: 1,
        }
    }

    fn flow_id(&mut self, client: SocketAddr, target: &Address) -> u64 {
        let key = SocksUdpFlowKey {
            client,
            target: target.clone(),
        };
        if let Some(id) = self.flow_ids.get(&key) {
            return *id;
        }

        let id = self.next_available_flow_id();
        self.flow_ids.insert(key, id);
        self.flows.insert(id, (client, target.clone()));
        id
    }

    fn flow(&self, flow_id: u64) -> Option<&(SocketAddr, Address)> {
        self.flows.get(&flow_id)
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
}

impl SocksUdpRelay {
    pub(super) fn spawn(
        sessions: Arc<YamuxSessionManager>,
        udp_socket: Arc<UdpSocket>,
    ) -> Arc<Self> {
        let mut shards = Vec::with_capacity(SOCKS_UDP_RELAY_SHARD_COUNT);
        for shard_index in 0..SOCKS_UDP_RELAY_SHARD_COUNT {
            let (tx, rx) = tokio::sync::mpsc::channel(SOCKS_UDP_RELAY_CHANNEL_SIZE);
            shards.push(tx);
            debug!("启动 SOCKS5 UDP 共享 relay shard {shard_index}");
            tokio::spawn(run_socks_udp_relay(
                sessions.clone(),
                udp_socket.clone(),
                rx,
            ));
        }
        Arc::new(Self { shards })
    }

    pub(super) async fn send(&self, client: SocketAddr, target: Address, packet: Vec<u8>) {
        let shard_index = socks_udp_relay_shard_index(client, &target, self.shards.len());
        if self.shards[shard_index]
            .send(SocksUdpRelayRequest {
                client,
                target,
                packet,
            })
            .await
            .is_err()
        {
            debug!("SOCKS5 UDP 共享转发器已关闭，丢弃请求");
        }
    }
}

fn socks_udp_relay_shard_index(client: SocketAddr, target: &Address, shard_count: usize) -> usize {
    debug_assert!(shard_count > 0);
    let mut hasher = DefaultHasher::new();
    client.hash(&mut hasher);
    target.hash(&mut hasher);
    (hasher.finish() % shard_count as u64) as usize
}

async fn run_socks_udp_relay(
    sessions: Arc<YamuxSessionManager>,
    udp_socket: Arc<UdpSocket>,
    mut rx: tokio::sync::mpsc::Receiver<SocksUdpRelayRequest>,
) {
    let mut state = SocksUdpRelayState::new();
    let mut retry_request = None;
    let mut reconnect_delay = Duration::from_millis(200);

    loop {
        let first_request = match retry_request.take() {
            Some(request) => request,
            None => {
                let Some(request) = rx.recv().await else {
                    break;
                };
                request
            }
        };

        let connected = connect_socks_udp_relay_stream(&sessions).await;
        let proxy_io = match connected {
            Ok(proxy_io) => {
                reconnect_delay = Duration::from_millis(200);
                proxy_io
            }
            Err(e) => {
                warn!("SOCKS5 UDP 共享连接创建失败：{e}");
                tokio::time::sleep(reconnect_delay).await;
                reconnect_delay = (reconnect_delay * 2).min(Duration::from_secs(5));
                retry_request = Some(first_request);
                continue;
            }
        };

        info!("SOCKS5 UDP 已建立共享 proxy 连接");
        let (mut reader, mut writer) = tokio::io::split(proxy_io);
        let mut metrics = tokio::time::interval(Duration::from_secs(60));
        metrics.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let idle = tokio::time::sleep(SOCKS_UDP_RELAY_CONNECTION_IDLE);
        tokio::pin!(idle);
        retry_request = Some(first_request);
        // UdpRelayPacket adds flow/address metadata to the original UDP payload.
        // Keep one complete native-UDP message in a single AsyncRead call.
        let mut response_buf = vec![0u8; UDP_MAX_MESSAGE_SIZE];

        loop {
            if let Some(request) = retry_request.take() {
                if let Err(e) = send_socks_udp_request(&mut writer, &mut state, &request).await {
                    debug!("SOCKS5 UDP 共享连接写入失败：{e}");
                    retry_request = Some(request);
                    break;
                }
                idle.as_mut()
                    .reset(tokio::time::Instant::now() + SOCKS_UDP_RELAY_CONNECTION_IDLE);
                continue;
            }

            tokio::select! {
                maybe_request = rx.recv() => {
                    let Some(request) = maybe_request else {
                        let _ = writer.shutdown().await;
                        return;
                    };
                    if let Err(e) = send_socks_udp_request(&mut writer, &mut state, &request).await {
                        debug!("SOCKS5 UDP 共享连接写入失败：{e}");
                        retry_request = Some(request);
                        break;
                    }
                    idle.as_mut().reset(tokio::time::Instant::now() + SOCKS_UDP_RELAY_CONNECTION_IDLE);
                }
                _ = &mut idle => {
                    debug!(
                        "SOCKS5 UDP 共享连接空闲超过 {} 秒，主动关闭 proxy 连接",
                        SOCKS_UDP_RELAY_CONNECTION_IDLE.as_secs()
                    );
                    let _ = writer.shutdown().await;
                    break;
                }
                _ = metrics.tick() => {
                    debug!(
                        "SOCKS5 UDP relay shard 观测：active_flows={} tracked_flow_keys={}",
                        state.active_flows(),
                        state.tracked_flow_keys()
                    );
                }
                read = reader.read(&mut response_buf) => {
                    match read {
                        Ok(0) => {
                            debug!("SOCKS5 UDP 共享连接已关闭");
                            break;
                        }
                        Ok(n) => {
                            if let Err(e) = handle_socks_udp_response(
                                &udp_socket,
                                &state,
                                &response_buf[..n],
                            ).await {
                                debug!("SOCKS5 UDP 回复写回失败：{e}");
                            }
                            idle.as_mut().reset(tokio::time::Instant::now() + SOCKS_UDP_RELAY_CONNECTION_IDLE);
                        }
                        Err(e) => {
                            debug!("SOCKS5 UDP 共享连接读取失败：{e}");
                            break;
                        }
                    }
                }
            }
        }
    }

    debug!("SOCKS5 UDP 共享转发器退出");
}

async fn connect_socks_udp_relay_stream(
    sessions: &YamuxSessionManager,
) -> Result<impl AsyncRead + AsyncWrite + Unpin + Send + 'static> {
    let connected = sessions
        .connect_to_target(Address::UdpRelay, TransportProtocol::Udp)
        .await?;
    Ok(connected.into_async_io())
}

async fn send_socks_udp_request<W>(
    writer: &mut W,
    state: &mut SocksUdpRelayState,
    request: &SocksUdpRelayRequest,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    // SOCKS5 UDP payload 先包成 UdpRelayPacket，再写入共享 proxy stream。
    let flow_id = state.flow_id(request.client, &request.target);
    let packet = UdpRelayPacket {
        flow_id,
        address: request.target.clone(),
        data: request.packet.clone(),
    }
    .encode()
    .map_err(std::io::Error::other)?;

    writer.write_all(&packet).await?;
    writer.flush().await?;
    telemetry::record_traffic(request.packet.len() as u64, 0);
    Ok(())
}

async fn handle_socks_udp_response(
    udp_socket: &UdpSocket,
    state: &SocksUdpRelayState,
    response: &[u8],
) -> std::io::Result<()> {
    // proxy 返回的 UdpRelayPacket 需要恢复成 SOCKS5 UDP response packet。
    let packet = UdpRelayPacket::decode(response).map_err(std::io::Error::other)?;
    let Some((client, target)) = state.flow(packet.flow_id) else {
        debug!("SOCKS5 UDP 收到无匹配 flow 的回复 id={}", packet.flow_id);
        return Ok(());
    };

    let response = create_udp_packet(target, &packet.data).map_err(std::io::Error::other)?;
    let response_payload_len = packet.data.len();
    udp_socket.send_to(&response, client).await?;
    telemetry::record_traffic(0, response_payload_len as u64);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn youtube_address() -> Address {
        Address::Domain {
            host: "www.youtube.com".to_string(),
            port: 443,
        }
    }

    #[test]
    fn structurally_equal_targets_reuse_the_same_flow() {
        let client = SocketAddr::from(([127, 0, 0, 1], 51_000));
        let mut state = SocksUdpRelayState::new();

        let first = state.flow_id(client, &youtube_address());
        let second = state.flow_id(client, &youtube_address());

        assert_eq!(first, second);
        assert_eq!(state.active_flows(), 1);
        assert_eq!(state.tracked_flow_keys(), 1);
    }

    #[test]
    fn client_and_target_are_both_part_of_the_flow_key() {
        let first_client = SocketAddr::from(([127, 0, 0, 1], 51_000));
        let second_client = SocketAddr::from(([127, 0, 0, 1], 51_001));
        let mut state = SocksUdpRelayState::new();

        let first = state.flow_id(first_client, &youtube_address());
        let different_client = state.flow_id(second_client, &youtube_address());
        let different_target = state.flow_id(
            first_client,
            &Address::Domain {
                host: "www.youtube.com".to_string(),
                port: 8443,
            },
        );

        assert_ne!(first, different_client);
        assert_ne!(first, different_target);
        assert_eq!(state.active_flows(), 3);
        assert_eq!(state.tracked_flow_keys(), 3);
    }

    #[test]
    fn equal_structured_targets_choose_the_same_shard() {
        let client = SocketAddr::from(([127, 0, 0, 1], 51_000));

        let first = socks_udp_relay_shard_index(client, &youtube_address(), 4);
        let second = socks_udp_relay_shard_index(client, &youtube_address(), 4);

        assert_eq!(first, second);
    }
}
