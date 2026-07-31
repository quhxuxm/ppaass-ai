//! UDP relay flow 之间共享的小型数据结构和公共调度逻辑。
//!
//! 每个 `flow_id` 对应一个已 connect 到目标地址的 UDP socket。主 relay 循环只负责
//! 解包/打包 PPAASS 数据帧，flow 任务负责和目标 UDP 地址收发 payload。

use super::target::relay_target_addr;
use super::*;
use crate::config::PERMISSION_PROXY_CONNECT_UDP;
use std::collections::HashMap;
use tokio::time::Instant;

// 主 relay 循环收到一个下行响应后，会顺手把队列里已经就绪的响应一起写出。
// 这个上限避免高回包流量下每个 UDP 包都触发一次 flush，同时也避免单次 drain
// 过久导致上行读取和 flow_done 清理被饿住。
pub const UDP_RELAY_RESPONSE_BATCH_LIMIT: usize = 32;
const FLOW_CREATION_BURST: f64 = 64.0;
const FLOW_CREATION_REFILL_PER_SECOND: f64 = 16.0;
pub const FLOW_AUTHORIZATION_COALESCE_WINDOW: Duration = Duration::from_secs(1);

pub(super) struct UdpRelayFlow {
    pub(super) tx: tokio::sync::mpsc::Sender<QueuedUdpRelayData>,
}

pub(super) struct QueuedUdpRelayData {
    pub(super) data: Vec<u8>,
}

pub struct QueuedUdpRelayResponse {
    pub packet: UdpRelayPacket,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpRelayResponseQueueResult {
    Queued,
    Full,
    Closed,
}

#[derive(Clone)]
pub struct UdpRelayFlowChannels {
    pub response_tx: tokio::sync::mpsc::Sender<QueuedUdpRelayResponse>,
    pub flow_done_tx: tokio::sync::mpsc::Sender<u64>,
}

#[derive(Clone, Copy)]
pub(super) struct UdpRelayFlowOptions {
    pub(super) idle_timeout: Duration,
    pub(super) channel_size: usize,
    pub(super) max_flows: usize,
}

#[derive(Clone)]
pub(super) struct UdpRelayFlowContext {
    egress_state: Arc<EgressState>,
    access_recorder: crate::access_log::AccessRecorder,
    username: String,
    channels: UdpRelayFlowChannels,
    relay_label: &'static str,
    flow_task_name: &'static str,
}

pub struct UdpRelayFlowSet {
    flows: HashMap<u64, UdpRelayFlow>,
    options: UdpRelayFlowOptions,
    context: UdpRelayFlowContext,
    flow_authorization: Option<ConnectionAuthorization>,
    flow_creation_budget: FlowCreationBudget,
    authorization_freshness: AuthorizationFreshness,
}

struct FlowCreationBudget {
    tokens: f64,
    updated_at: Instant,
}

#[derive(Default)]
struct AuthorizationFreshness {
    last_success_at: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpRelayFlowAdmission {
    Existing,
    AtCapacity,
    Create,
}

pub fn classify_udp_relay_flow_admission(
    flow_exists: bool,
    active_flow_count: usize,
    max_flows: usize,
) -> UdpRelayFlowAdmission {
    if flow_exists {
        UdpRelayFlowAdmission::Existing
    } else if active_flow_count >= max_flows {
        UdpRelayFlowAdmission::AtCapacity
    } else {
        UdpRelayFlowAdmission::Create
    }
}

impl FlowCreationBudget {
    fn new(now: Instant) -> Self {
        Self {
            tokens: FLOW_CREATION_BURST,
            updated_at: now,
        }
    }

    fn try_take_at(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.updated_at);
        self.tokens = (self.tokens + elapsed.as_secs_f64() * FLOW_CREATION_REFILL_PER_SECOND)
            .min(FLOW_CREATION_BURST);
        self.updated_at = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

impl AuthorizationFreshness {
    fn requires_recheck(&self, now: Instant) -> bool {
        self.last_success_at.is_none_or(|last_success_at| {
            now.saturating_duration_since(last_success_at) >= FLOW_AUTHORIZATION_COALESCE_WINDOW
        })
    }

    fn record_success(&mut self, now: Instant) {
        self.last_success_at = Some(now);
    }
}

impl UdpRelayFlowSet {
    pub fn new(
        proxy_config: &ProxyConfig,
        egress_state: Arc<EgressState>,
        access_recorder: crate::access_log::AccessRecorder,
        username: String,
        channels: UdpRelayFlowChannels,
        relay_label: &'static str,
        flow_task_name: &'static str,
    ) -> Self {
        let channel_size = udp_relay_channel_size(proxy_config);
        Self {
            flows: HashMap::new(),
            options: UdpRelayFlowOptions {
                idle_timeout: Duration::from_secs(proxy_config.udp_relay_idle_timeout_secs),
                channel_size,
                max_flows: proxy_config.udp_relay_max_flows,
            },
            context: UdpRelayFlowContext {
                egress_state,
                access_recorder,
                username,
                channels,
                relay_label,
                flow_task_name,
            },
            flow_authorization: None,
            flow_creation_budget: FlowCreationBudget::new(Instant::now()),
            authorization_freshness: AuthorizationFreshness::default(),
        }
    }

    pub fn with_authorization(mut self, authorization: ConnectionAuthorization) -> Self {
        self.flow_authorization = Some(authorization);
        self
    }

    pub fn idle_timeout(&self) -> Duration {
        self.options.idle_timeout
    }

    pub fn remove(&mut self, flow_id: u64) {
        if self.flows.remove(&flow_id).is_some() {
            debug!(
                "{} flow {flow_id} 已清理，active_flows={}",
                self.context.relay_label,
                self.flows.len()
            );
        }
    }

    pub fn record_authorization_success(&mut self, now: Instant) {
        if self.flow_authorization.is_some() {
            self.authorization_freshness.record_success(now);
        }
    }

    pub async fn dispatch(&mut self, relay_packet: UdpRelayPacket) -> Result<()> {
        let flow_id = relay_packet.flow_id;

        match classify_udp_relay_flow_admission(
            self.flows.contains_key(&flow_id),
            self.flows.len(),
            self.options.max_flows,
        ) {
            UdpRelayFlowAdmission::Existing => {}
            UdpRelayFlowAdmission::AtCapacity => {
                debug!(
                    "{} flow 数已达上限 {}，丢弃新 flow {flow_id} 的数据报",
                    self.context.relay_label, self.options.max_flows
                );
                return Ok(());
            }
            UdpRelayFlowAdmission::Create => {
                if let Some(authorization) = self.flow_authorization.as_ref() {
                    let now = Instant::now();
                    if !self.flow_creation_budget.try_take_at(now) {
                        debug!(
                            "{} 新 flow 创建速率过高，丢弃 flow {flow_id}",
                            self.context.relay_label
                        );
                        return Ok(());
                    }
                    if self.authorization_freshness.requires_recheck(now) {
                        authorization.validate(PERMISSION_PROXY_CONNECT_UDP).await?;
                        // 从查询开始时计时会缩短而不会延长合并窗口。
                        self.authorization_freshness.record_success(now);
                    }
                }
                if !self
                    .create_flow(flow_id, relay_packet.address.clone())
                    .await
                {
                    return Ok(());
                }
            }
        }

        let Some(flow) = self.flows.get(&flow_id) else {
            return Ok(());
        };
        match flow.tx.try_send(QueuedUdpRelayData {
            data: relay_packet.data,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                // UDP 没有可靠传输语义；内部队列满时直接丢包，避免一个慢 flow 阻塞共享 relay。
                debug!(
                    "{} flow {flow_id} 发送队列已满，丢弃一个 UDP 数据包",
                    self.context.relay_label
                );
            }
            Err(TrySendError::Closed(_)) => {
                self.flows.remove(&flow_id);
            }
        }
        Ok(())
    }

    async fn create_flow(&mut self, flow_id: u64, address: Address) -> bool {
        if self.flows.len() >= self.options.max_flows {
            debug!(
                "{} flow 数已达上限 {}，拒绝新 flow {flow_id}",
                self.context.relay_label, self.options.max_flows
            );
            return false;
        }
        match spawn_udp_relay_flow(flow_id, address, self.options, self.context.clone()).await {
            Ok(flow) => {
                self.flows.insert(flow_id, flow);
                debug!(
                    "{} flow {flow_id} 已创建，active_flows={}",
                    self.context.relay_label,
                    self.flows.len()
                );
                true
            }
            Err(e) => {
                debug!(
                    "{} flow {} 连接目标失败：{}",
                    self.context.relay_label, flow_id, e
                );
                false
            }
        }
    }
}

pub fn udp_relay_channel_size(config: &ProxyConfig) -> usize {
    config.udp_relay_channel_size.max(1)
}

async fn spawn_udp_relay_flow(
    flow_id: u64,
    address: Address,
    options: UdpRelayFlowOptions,
    context: UdpRelayFlowContext,
) -> Result<UdpRelayFlow> {
    let target_addr = relay_target_addr(&address)?;
    let socket = context
        .egress_state
        .connect_udp(&target_addr)
        .await
        .map_err(|e| ProxyError::Connection(format!("Failed to connect UDP relay target: {e}")))?;
    context
        .access_recorder
        .record(&context.username, TransportProtocol::Udp, &address);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<QueuedUdpRelayData>(options.channel_size);
    let response_address = address.clone();
    let response_tx = context.channels.response_tx;
    let flow_done_tx = context.channels.flow_done_tx;
    let relay_label = context.relay_label;
    let flow_idle_timeout = options.idle_timeout;

    spawn_guarded(context.flow_task_name, async move {
        let mut buf = vec![0u8; 65535];
        let idle = tokio::time::sleep(flow_idle_timeout);
        tokio::pin!(idle);

        loop {
            tokio::select! {
                _ = &mut idle => break,
                maybe_data = rx.recv() => {
                    let Some(queued) = maybe_data else { break };
                    match tokio::time::timeout(flow_idle_timeout, socket.send(&queued.data)).await {
                        Ok(Ok(_)) => {
                            idle.as_mut().reset(tokio::time::Instant::now() + flow_idle_timeout);
                        }
                        Ok(Err(e)) => {
                            debug!("{relay_label} flow {flow_id} 发送失败：{e}");
                            break;
                        }
                        Err(_) => {
                            debug!(
                                "{relay_label} flow {flow_id} 发送超过 {} 秒，关闭该 flow",
                                flow_idle_timeout.as_secs()
                            );
                            break;
                        }
                    }
                }
                read = socket.recv(&mut buf) => {
                    match read {
                        Ok(n) => {
                            let response = QueuedUdpRelayResponse {
                                packet: UdpRelayPacket {
                                    flow_id,
                                    address: response_address.clone(),
                                    data: buf[..n].to_vec(),
                                },
                            };
                            match try_queue_udp_relay_response(
                                &response_tx,
                                response,
                                relay_label,
                                flow_id,
                            ) {
                                UdpRelayResponseQueueResult::Queued => {
                                    idle.as_mut().reset(tokio::time::Instant::now() + flow_idle_timeout);
                                }
                                // UDP/QUIC 可以从单包丢失中恢复；不能因短暂背压关闭 socket，
                                // 否则源端口变化会迫使内层 HTTP/3/QUIC 整条连接重建。
                                UdpRelayResponseQueueResult::Full => {}
                                UdpRelayResponseQueueResult::Closed => break,
                            }
                        }
                        Err(e) => {
                            debug!("{relay_label} flow {flow_id} 接收失败：{e}");
                            break;
                        }
                    }
                }
            }
        }
        drop(socket);
        let _ = flow_done_tx.send(flow_id).await;
        debug!("{relay_label} flow {flow_id} 已结束");
    });

    Ok(UdpRelayFlow { tx })
}

pub fn try_queue_udp_relay_response(
    response_tx: &tokio::sync::mpsc::Sender<QueuedUdpRelayResponse>,
    response: QueuedUdpRelayResponse,
    relay_label: &str,
    flow_id: u64,
) -> UdpRelayResponseQueueResult {
    match response_tx.try_send(response) {
        Ok(()) => UdpRelayResponseQueueResult::Queued,
        Err(TrySendError::Full(_)) => {
            debug!("{relay_label} flow {flow_id} 响应队列已满，丢弃一个 UDP 响应并保持 flow");
            UdpRelayResponseQueueResult::Full
        }
        Err(TrySendError::Closed(_)) => UdpRelayResponseQueueResult::Closed,
    }
}
