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
pub(super) const UDP_RELAY_RESPONSE_BATCH_LIMIT: usize = 32;
const FLOW_CREATION_BURST: f64 = 64.0;
const FLOW_CREATION_REFILL_PER_SECOND: f64 = 16.0;
const FLOW_AUTHORIZATION_COALESCE_WINDOW: Duration = Duration::from_secs(1);

pub(super) struct UdpRelayFlow {
    pub(super) tx: tokio::sync::mpsc::Sender<QueuedUdpRelayData>,
}

pub(super) struct QueuedUdpRelayData {
    pub(super) data: Vec<u8>,
}

pub(crate) struct QueuedUdpRelayResponse {
    pub(crate) packet: UdpRelayPacket,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UdpRelayResponseQueueResult {
    Queued,
    Full,
    Closed,
}

#[derive(Clone)]
pub(crate) struct UdpRelayFlowChannels {
    pub(crate) response_tx: tokio::sync::mpsc::Sender<QueuedUdpRelayResponse>,
    pub(crate) flow_done_tx: tokio::sync::mpsc::Sender<u64>,
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

pub(crate) struct UdpRelayFlowSet {
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
enum UdpRelayFlowAdmission {
    Existing,
    AtCapacity,
    Create,
}

fn classify_udp_relay_flow_admission(
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
    pub(crate) fn new(
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

    pub(crate) fn with_authorization(mut self, authorization: ConnectionAuthorization) -> Self {
        self.flow_authorization = Some(authorization);
        self
    }

    pub(crate) fn idle_timeout(&self) -> Duration {
        self.options.idle_timeout
    }

    pub(crate) fn remove(&mut self, flow_id: u64) {
        if self.flows.remove(&flow_id).is_some() {
            debug!(
                "{} flow {flow_id} 已清理，active_flows={}",
                self.context.relay_label,
                self.flows.len()
            );
        }
    }

    pub(crate) fn record_authorization_success(&mut self, now: Instant) {
        if self.flow_authorization.is_some() {
            self.authorization_freshness.record_success(now);
        }
    }

    pub(crate) async fn dispatch(&mut self, relay_packet: UdpRelayPacket) -> Result<()> {
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

pub(crate) fn udp_relay_channel_size(config: &ProxyConfig) -> usize {
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

fn try_queue_udp_relay_response(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PERMISSION_PROXY_CONNECT_TCP, PERMISSION_PROXY_CONNECT_UDP, UserConfig};
    use crate::user_manager::UserManager;
    use proxy_user_store::{UserOrigin, UserRecord, UserRepository, UserUpdate};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingUserRepository {
        user: UserRecord,
        get_count: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl UserRepository for CountingUserRepository {
        async fn get_user(&self, username: &str) -> proxy_user_store::Result<Option<UserRecord>> {
            self.get_count.fetch_add(1, Ordering::AcqRel);
            Ok((username == self.user.username).then(|| self.user.clone()))
        }

        async fn list_users(&self) -> proxy_user_store::Result<Vec<UserRecord>> {
            unreachable!("flow authorization tests only query one user")
        }

        async fn create_user(
            &self,
            _username: &str,
            _public_key_pem: &str,
            _expires_at: Option<i64>,
        ) -> proxy_user_store::Result<UserRecord> {
            unreachable!("flow authorization tests never create users")
        }

        async fn update_user(
            &self,
            _username: &str,
            _update: UserUpdate,
        ) -> proxy_user_store::Result<UserRecord> {
            unreachable!("flow authorization tests never update users")
        }

        async fn delete_user(&self, _username: &str) -> proxy_user_store::Result<()> {
            unreachable!("flow authorization tests never delete users")
        }
    }

    fn test_config(max_flows: usize) -> ProxyConfig {
        toml::from_str(&format!(
            r#"
listen_addr = "127.0.0.1:0"
users_database_path = "users.sqlite3"
access_log_database_path = "access.sqlite3"
udp_relay_max_flows = {max_flows}
"#
        ))
        .unwrap()
    }

    fn counting_repository() -> Arc<CountingUserRepository> {
        Arc::new(CountingUserRepository {
            user: UserRecord {
                username: "alice".to_string(),
                public_key_pem: "handshake-key".to_string(),
                permissions: vec![
                    PERMISSION_PROXY_CONNECT_TCP.to_string(),
                    PERMISSION_PROXY_CONNECT_UDP.to_string(),
                ],
                enabled: true,
                origin: UserOrigin::Local,
                key_version: 7,
                expires_at: Some(i64::MAX),
                created_at: 1,
                updated_at: 1,
            },
            get_count: AtomicUsize::new(0),
        })
    }

    fn authorized_flow_set(
        max_flows: usize,
        repository: Arc<CountingUserRepository>,
    ) -> (
        UdpRelayFlowSet,
        tokio::sync::mpsc::Receiver<QueuedUdpRelayResponse>,
        tokio::sync::mpsc::Receiver<u64>,
    ) {
        let manager = Arc::new(UserManager::new(repository as Arc<dyn UserRepository>));
        let user = UserConfig {
            username: "alice".to_string(),
            public_key_pem: "handshake-key".to_string(),
            expires_at: Some(i64::MAX.to_string()),
            permissions: vec![
                PERMISSION_PROXY_CONNECT_TCP.to_string(),
                PERMISSION_PROXY_CONNECT_UDP.to_string(),
            ],
            enabled: true,
            key_version: Some(7),
        };
        let authorization = ConnectionAuthorization::new(manager, &user).unwrap();
        let config = test_config(max_flows);
        let channel_size = udp_relay_channel_size(&config);
        let (response_tx, response_rx) = tokio::sync::mpsc::channel(channel_size);
        let (flow_done_tx, flow_done_rx) = tokio::sync::mpsc::channel(channel_size);
        let flow_set = UdpRelayFlowSet::new(
            &config,
            Arc::new(EgressState::new(None, None).unwrap()),
            crate::access_log::AccessRecorder::default(),
            "alice".to_string(),
            UdpRelayFlowChannels {
                response_tx,
                flow_done_tx,
            },
            "test UDP relay",
            "test udp relay flow",
        )
        .with_authorization(authorization);
        (flow_set, response_rx, flow_done_rx)
    }

    fn relay_packet(flow_id: u64) -> UdpRelayPacket {
        UdpRelayPacket {
            flow_id,
            // 虚拟 relay 地址不能成为内层真实目标，因此在授权检查后会快速失败，
            // 测试不会访问网络或留下 flow worker。
            address: Address::UdpRelay,
            data: vec![1, 2, 3],
        }
    }

    fn queued_response(flow_id: u64) -> QueuedUdpRelayResponse {
        QueuedUdpRelayResponse {
            packet: UdpRelayPacket {
                flow_id,
                address: Address::UdpRelay,
                data: vec![flow_id as u8],
            },
        }
    }

    #[test]
    fn existing_inner_flow_remains_usable_at_capacity() {
        assert_eq!(
            classify_udp_relay_flow_admission(true, 256, 256),
            UdpRelayFlowAdmission::Existing
        );
    }

    #[test]
    fn new_inner_flow_is_rejected_at_capacity_without_off_by_one() {
        assert_eq!(
            classify_udp_relay_flow_admission(false, 255, 256),
            UdpRelayFlowAdmission::Create
        );
        assert_eq!(
            classify_udp_relay_flow_admission(false, 256, 256),
            UdpRelayFlowAdmission::AtCapacity
        );
    }

    #[tokio::test]
    async fn full_response_queue_drops_one_packet_but_remains_usable() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        tx.try_send(queued_response(1)).unwrap();

        assert_eq!(
            try_queue_udp_relay_response(&tx, queued_response(2), "test relay", 2),
            UdpRelayResponseQueueResult::Full
        );
        assert!(!tx.is_closed());
        assert_eq!(rx.recv().await.unwrap().packet.flow_id, 1);

        // 队列恢复容量后，同一 flow channel 仍可继续使用。
        assert_eq!(
            try_queue_udp_relay_response(&tx, queued_response(3), "test relay", 3),
            UdpRelayResponseQueueResult::Queued
        );
        assert_eq!(rx.recv().await.unwrap().packet.flow_id, 3);
    }

    #[test]
    fn closed_response_queue_stops_the_flow() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        drop(rx);

        assert_eq!(
            try_queue_udp_relay_response(&tx, queued_response(1), "test relay", 1),
            UdpRelayResponseQueueResult::Closed
        );
    }

    #[tokio::test(start_paused = true)]
    async fn authorization_queries_only_for_new_flows_and_coalesces_bursts() {
        let repository = counting_repository();
        let (mut full_set, _response_rx, _flow_done_rx) =
            authorized_flow_set(1, repository.clone());
        let (existing_tx, mut existing_rx) = tokio::sync::mpsc::channel(1);
        full_set.flows.insert(1, UdpRelayFlow { tx: existing_tx });

        // Existing 先于 capacity 分类，继续投递且不触发 DAO；新的 flow 在
        // capacity 满时直接丢弃，同样不触发 DAO。
        full_set.dispatch(relay_packet(1)).await.unwrap();
        assert_eq!(existing_rx.recv().await.unwrap().data, vec![1, 2, 3]);
        full_set.dispatch(relay_packet(2)).await.unwrap();
        assert_eq!(repository.get_count.load(Ordering::Acquire), 0);

        let (mut create_set, _response_rx, _flow_done_rx) =
            authorized_flow_set(4, repository.clone());
        create_set.dispatch(relay_packet(10)).await.unwrap();
        assert_eq!(repository.get_count.load(Ordering::Acquire), 1);
        create_set.dispatch(relay_packet(11)).await.unwrap();
        assert_eq!(
            repository.get_count.load(Ordering::Acquire),
            1,
            "successful authorization is coalesced for a one-second burst"
        );

        tokio::time::advance(FLOW_AUTHORIZATION_COALESCE_WINDOW).await;
        create_set.dispatch(relay_packet(12)).await.unwrap();
        assert_eq!(repository.get_count.load(Ordering::Acquire), 2);
    }
}
