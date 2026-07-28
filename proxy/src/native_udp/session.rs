use super::auth::validate_session_authorization;
use super::channel::run_channel_worker;
use super::session_label;
use crate::access_log::AccessRecorder;
use crate::config::ProxyConfig;
use crate::connection::EgressState;
use crate::error::{ProxyError, Result};
use crate::user_manager::UserManager;
use protocol::udp_transport::{UdpSessionCodec, UdpSessionMessage};
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::{AbortHandle, JoinSet};
use tokio::time::Instant;
use tracing::{debug, trace, warn};

const FLOW_CREATION_BURST: f64 = 64.0;
const FLOW_CREATION_REFILL_PER_SECOND: f64 = 16.0;
const FLOW_AUTHORIZATION_COALESCE_WINDOW: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub(super) struct SessionContext {
    pub(super) socket: Arc<UdpSocket>,
    pub(super) config: Arc<ProxyConfig>,
    pub(super) user_manager: Arc<UserManager>,
    pub(super) egress_state: Arc<EgressState>,
    pub(super) access_recorder: AccessRecorder,
    pub(super) username: String,
    pub(super) authenticated_public_key_pem: String,
    pub(super) authenticated_key_version: Option<i64>,
    pub(super) expires_at: Option<i64>,
    pub(super) peer: SocketAddr,
}

struct ChannelState {
    input_tx: Option<mpsc::Sender<Vec<u8>>>,
    abort_handle: AbortHandle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowAdmission {
    Existing,
    AtCapacity,
    Create,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowOpenDecision {
    Existing,
    AtCapacity,
    RateLimited,
    Create,
}

struct FlowCreationBudget {
    tokens: f64,
    updated_at: Instant,
}

#[derive(Default)]
struct AuthorizationFreshness {
    last_success_at: Option<Instant>,
}

fn classify_flow_admission(
    flow_exists: bool,
    active_flow_count: usize,
    max_flows: usize,
) -> FlowAdmission {
    if flow_exists {
        FlowAdmission::Existing
    } else if active_flow_count >= max_flows {
        FlowAdmission::AtCapacity
    } else {
        FlowAdmission::Create
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

async fn decide_flow_open<F, Fut>(
    admission: FlowAdmission,
    budget: &mut FlowCreationBudget,
    freshness: &mut AuthorizationFreshness,
    now: Instant,
    validate: F,
) -> Result<FlowOpenDecision>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<()>>,
{
    match admission {
        FlowAdmission::Existing => return Ok(FlowOpenDecision::Existing),
        FlowAdmission::AtCapacity => return Ok(FlowOpenDecision::AtCapacity),
        FlowAdmission::Create => {}
    }
    if !budget.try_take_at(now) {
        return Ok(FlowOpenDecision::RateLimited);
    }
    if freshness.requires_recheck(now) {
        validate().await?;
        // 从查询开始时计时会缩短而不会延长缓存窗口；慢查询后宁可提前再验。
        freshness.record_success(now);
    }
    Ok(FlowOpenDecision::Create)
}

pub(super) enum ChannelEvent {
    ConnectResult {
        flow_id: u64,
        response: UdpSessionMessage,
    },
    Closed {
        flow_id: u64,
        reason: Option<String>,
    },
}

pub(super) async fn run_session(
    context: SessionContext,
    mut codec: UdpSessionCodec,
    mut inbound_rx: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    let channel_size = context.config.udp_session_channel_size.max(1);
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<UdpSessionMessage>(channel_size);
    let (channel_event_tx, mut channel_event_rx) = mpsc::unbounded_channel::<ChannelEvent>();
    let mut channel_tasks = JoinSet::new();
    let mut channels = HashMap::<u64, ChannelState>::new();
    let mut flow_creation_budget = FlowCreationBudget::new(Instant::now());
    let mut authorization_freshness = AuthorizationFreshness::default();
    let idle_timeout = udp_idle_timeout(&context.config);
    let idle = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle);
    let authorization_recheck_interval = Duration::from_secs(
        context
            .config
            .udp_session_authorization_recheck_secs
            .clamp(1, 5),
    );
    let mut authorization_recheck = tokio::time::interval(authorization_recheck_interval);
    authorization_recheck.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // `interval` 的首次 tick 会立即完成；握手刚刚已经校验过，先消费它。
    authorization_recheck.tick().await;
    let absolute_expiry = wait_until_expired(context.expires_at);
    tokio::pin!(absolute_expiry);

    loop {
        tokio::select! {
            biased;
            _ = &mut absolute_expiry => {
                debug!(
                    username = %context.username,
                    session = %session_label(&codec.session_id()),
                    "原生 UDP 会话达到认证时的绝对过期时间，主动关闭"
                );
                break;
            }
            _ = authorization_recheck.tick() => {
                // A repository query may wait on I/O or pool capacity. Absolute
                // expiry is an independent upper bound and must remain able to
                // cancel that wait instead of being delayed by revalidation.
                let validation = revalidate_authorization(&context);
                tokio::pin!(validation);
                let validation_result = tokio::select! {
                    biased;
                    _ = &mut absolute_expiry => {
                        debug!(
                            username = %context.username,
                            session = %session_label(&codec.session_id()),
                            "原生 UDP 会话在授权复核期间达到绝对过期时间，主动关闭"
                        );
                        break;
                    }
                    result = &mut validation => result,
                };
                if let Err(error) = validation_result {
                    warn!(
                        username = %context.username,
                        session = %session_label(&codec.session_id()),
                        "原生 UDP 会话授权已失效，主动关闭：{error}"
                    );
                    break;
                }
                authorization_freshness.record_success(Instant::now());
            }
            _ = &mut idle => {
                debug!(
                    "原生 UDP 会话空闲超过 {} 秒，主动清理 session={}",
                    idle_timeout.as_secs(),
                    session_label(&codec.session_id())
                );
                break;
            }
            inbound = inbound_rx.recv() => {
                let Some(datagram) = inbound else { break };
                let message = match codec.decode_datagram(&datagram) {
                    Ok(message) => {
                        // codec 只会在 AEAD 校验成功后提交 replay 序号。分片尚未完整
                        // 也是有效活动；未知、重放或篡改包不得刷新 idle。
                        idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                        message
                    }
                    Err(error) => {
                        trace!(
                            "丢弃未通过原生 UDP AEAD/replay 校验的数据报 session={}: {error}",
                            session_label(&codec.session_id())
                        );
                        continue;
                    }
                };
                let Some(message) = message else { continue };
                if session_expired_at(context.expires_at, SystemTime::now()) {
                    debug!(
                        username = %context.username,
                        session = %session_label(&codec.session_id()),
                        "原生 UDP 会话已过期，拒绝继续处理数据"
                    );
                    break;
                }

                match message {
                    UdpSessionMessage::OpenData { flow_id, address, data } => {
                        let admission = classify_flow_admission(
                            channels.contains_key(&flow_id),
                            channels.len(),
                            context.config.udp_session_max_flows,
                        );
                        let decision = decide_flow_open(
                            admission,
                            &mut flow_creation_budget,
                            &mut authorization_freshness,
                            Instant::now(),
                            || revalidate_authorization(&context),
                        )
                        .await;
                        let decision = match decision {
                            Ok(decision) => decision,
                            Err(error) => {
                                warn!(
                                    username = %context.username,
                                    session = %session_label(&codec.session_id()),
                                    "创建原生 UDP flow 时授权已失效，主动关闭会话：{error}"
                                );
                                break;
                            }
                        };
                        match decision {
                            FlowOpenDecision::Existing => {
                                // OpenData is an application datagram, not a retryable
                                // control message. Never deliver a duplicate first packet.
                                continue;
                            }
                            FlowOpenDecision::AtCapacity => {
                                debug!(
                                    flow_id,
                                    limit = context.config.udp_session_max_flows,
                                    session = %session_label(&codec.session_id()),
                                    "原生 UDP 会话 flow 数已达上限，拒绝新 flow"
                                );
                                send_session_message(
                                    &context,
                                    &mut codec,
                                    &connect_response(
                                        flow_id,
                                        Some(format!(
                                            "native UDP session flow limit reached ({})",
                                            context.config.udp_session_max_flows
                                        )),
                                    ),
                                )
                                .await?;
                                continue;
                            }
                            FlowOpenDecision::RateLimited => {
                                debug!(
                                    flow_id,
                                    session = %session_label(&codec.session_id()),
                                    "原生 UDP flow 创建速率超过会话预算，拒绝新 flow"
                                );
                                send_session_message(
                                    &context,
                                    &mut codec,
                                    &connect_response(
                                        flow_id,
                                        Some("native UDP flow creation rate limited".to_string()),
                                    ),
                                )
                                .await?;
                                continue;
                            }
                            FlowOpenDecision::Create => {}
                        }

                        let (input_tx, input_rx) = mpsc::channel(channel_size);
                        input_tx
                            .try_send(data)
                            .expect("new native UDP flow queue has capacity");
                        let worker_context = context.clone();
                        let worker_outbound_tx = outbound_tx.clone();
                        let worker_event_tx = channel_event_tx.clone();
                        let abort_handle = channel_tasks.spawn(async move {
                            run_channel_worker(
                                worker_context,
                                flow_id,
                                address,
                                input_rx,
                                worker_outbound_tx,
                                worker_event_tx,
                            )
                            .await;
                        });
                        channels.insert(
                            flow_id,
                            ChannelState {
                                input_tx: Some(input_tx),
                                abort_handle,
                            },
                        );
                    }
                    UdpSessionMessage::Data { flow_id, data } => {
                        let Some(channel) = channels.get_mut(&flow_id) else {
                            trace!("丢弃未连接 channel 的 UDP 数据 flow_id={flow_id}");
                            continue;
                        };
                        let Some(input_tx) = channel.input_tx.as_ref() else {
                            continue;
                        };
                        match input_tx.try_send(data) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                debug!("UDP channel 入站队列已满，丢弃一个包 flow_id={flow_id}");
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                channel.input_tx = None;
                            }
                        }
                    }
                    UdpSessionMessage::Close { flow_id, .. } => {
                        if let Some(channel) = channels.remove(&flow_id) {
                            channel.abort_handle.abort();
                        }
                    }
                    UdpSessionMessage::Ping { token } => {
                        send_session_message(
                            &context,
                            &mut codec,
                            &UdpSessionMessage::Pong { token },
                        )
                        .await?;
                    }
                    UdpSessionMessage::Pong { .. }
                    | UdpSessionMessage::ConnectResponse { .. } => {
                        trace!("proxy 收到方向错误的原生 UDP 会话消息，已忽略");
                    }
                }
            }
            outbound = outbound_rx.recv() => {
                let Some(message) = outbound else { continue };
                send_session_message(&context, &mut codec, &message).await?;
            }
            event = channel_event_rx.recv() => {
                let Some(event) = event else { continue };
                match event {
                    ChannelEvent::ConnectResult { flow_id, response } => {
                        let Some(channel) = channels.get_mut(&flow_id) else { continue };
                        let success = matches!(
                            response,
                            UdpSessionMessage::ConnectResponse { success: true, .. }
                        );
                        if !success {
                            channel.input_tx = None;
                        }
                        send_session_message(&context, &mut codec, &response).await?;
                    }
                    ChannelEvent::Closed { flow_id, reason } => {
                        if channels.remove(&flow_id).is_some() {
                            send_session_message(
                                &context,
                                &mut codec,
                                &UdpSessionMessage::Close { flow_id, reason },
                            )
                            .await?;
                        }
                    }
                }
            }
            joined = channel_tasks.join_next(), if !channel_tasks.is_empty() => {
                if let Some(Err(error)) = joined
                    && !error.is_cancelled()
                {
                    warn!("proxy 原生 UDP channel worker 异常结束：{error}");
                }
            }
        }
    }

    for (_, channel) in channels.drain() {
        channel.abort_handle.abort();
    }
    channel_tasks.abort_all();
    while channel_tasks.join_next().await.is_some() {}
    Ok(())
}

async fn revalidate_authorization(context: &SessionContext) -> Result<()> {
    validate_session_authorization(
        &context.user_manager,
        &context.username,
        &context.authenticated_public_key_pem,
        context.authenticated_key_version,
    )
    .await
}

async fn wait_until_expired(expires_at: Option<i64>) {
    let Some(expires_at) = expires_at else {
        std::future::pending::<()>().await;
        return;
    };
    let Some(delay) = duration_until_expiry(expires_at, SystemTime::now()) else {
        std::future::pending::<()>().await;
        return;
    };
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
}

fn duration_until_expiry(expires_at: i64, now: SystemTime) -> Option<Duration> {
    if expires_at < 0 {
        return Some(Duration::ZERO);
    }
    let expires_at = u64::try_from(expires_at).ok()?;
    let deadline = UNIX_EPOCH.checked_add(Duration::from_secs(expires_at))?;
    Some(deadline.duration_since(now).unwrap_or_default())
}

fn session_expired_at(expires_at: Option<i64>, now: SystemTime) -> bool {
    let Some(expires_at) = expires_at else {
        return false;
    };
    let Ok(expires_at) = u64::try_from(expires_at) else {
        return true;
    };
    UNIX_EPOCH
        .checked_add(Duration::from_secs(expires_at))
        .is_some_and(|deadline| now >= deadline)
}

fn ensure_session_not_expired(context: &SessionContext) -> Result<()> {
    if session_expired_at(context.expires_at, SystemTime::now()) {
        return Err(ProxyError::Authentication(
            "Native UDP session expired".to_string(),
        ));
    }
    Ok(())
}

async fn send_session_message(
    context: &SessionContext,
    codec: &mut UdpSessionCodec,
    message: &UdpSessionMessage,
) -> Result<()> {
    ensure_session_not_expired(context)?;
    let datagrams = codec
        .encode_message(message)
        .map_err(|error| ProxyError::Connection(error.to_string()))?;
    for datagram in datagrams {
        ensure_session_not_expired(context)?;
        let sent = context.socket.send_to(&datagram, context.peer).await?;
        if sent != datagram.len() {
            return Err(ProxyError::Connection(format!(
                "partial native UDP send: {sent}/{}",
                datagram.len()
            )));
        }
    }
    Ok(())
}

pub(super) fn udp_idle_timeout(config: &ProxyConfig) -> Duration {
    Duration::from_secs(config.udp_relay_idle_timeout_secs.max(1))
}

fn connect_response(flow_id: u64, error: Option<String>) -> UdpSessionMessage {
    UdpSessionMessage::ConnectResponse {
        flow_id,
        success: error.is_none(),
        error,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuthorizationFreshness, FLOW_CREATION_BURST, FlowAdmission, FlowCreationBudget,
        FlowOpenDecision, SessionContext, classify_flow_admission, decide_flow_open,
        duration_until_expiry, run_session, session_expired_at,
    };
    use crate::access_log::AccessRecorder;
    use crate::config::ProxyConfig;
    use crate::connection::EgressState;
    use crate::error::ProxyError;
    use crate::user_manager::UserManager;
    use protocol::udp_transport::{UdpSessionCodec, UdpSessionRole};
    use proxy_user_store::{
        Result as StoreResult, SqliteUserRepository, UserRecord, UserRepository, UserUpdate,
    };
    use std::cell::Cell;
    use std::sync::Arc;
    use std::time::{Duration, UNIX_EPOCH};
    use tempfile::TempDir;
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;
    use tokio::time::Instant;

    struct NeverRespondingUserRepository;

    #[async_trait::async_trait]
    impl UserRepository for NeverRespondingUserRepository {
        async fn get_user(&self, _username: &str) -> StoreResult<Option<UserRecord>> {
            std::future::pending().await
        }

        async fn list_users(&self) -> StoreResult<Vec<UserRecord>> {
            std::future::pending().await
        }

        async fn create_user(
            &self,
            _username: &str,
            _public_key_pem: &str,
            _expires_at: Option<i64>,
        ) -> StoreResult<UserRecord> {
            std::future::pending().await
        }

        async fn update_user(
            &self,
            _username: &str,
            _update: UserUpdate,
        ) -> StoreResult<UserRecord> {
            std::future::pending().await
        }

        async fn delete_user(&self, _username: &str) -> StoreResult<()> {
            std::future::pending().await
        }
    }

    #[test]
    fn existing_flow_remains_idempotent_when_session_is_full() {
        assert_eq!(
            classify_flow_admission(true, 256, 256),
            FlowAdmission::Existing
        );
    }

    #[test]
    fn new_flow_is_rejected_at_limit_without_off_by_one() {
        assert_eq!(
            classify_flow_admission(false, 255, 256),
            FlowAdmission::Create
        );
        assert_eq!(
            classify_flow_admission(false, 256, 256),
            FlowAdmission::AtCapacity
        );
        assert_eq!(
            classify_flow_admission(false, 257, 256),
            FlowAdmission::AtCapacity
        );
    }

    #[test]
    fn zero_flow_limit_disables_new_flow_creation() {
        assert_eq!(
            classify_flow_admission(false, 0, 0),
            FlowAdmission::AtCapacity
        );
    }

    #[tokio::test]
    async fn only_create_admission_revalidates_and_successes_are_coalesced() {
        let start = Instant::now();
        let mut budget = FlowCreationBudget::new(start);
        let mut freshness = AuthorizationFreshness::default();
        let queries = Cell::new(0_u32);

        for admission in [FlowAdmission::Existing, FlowAdmission::AtCapacity] {
            let decision =
                decide_flow_open(admission, &mut budget, &mut freshness, start, || async {
                    queries.set(queries.get() + 1);
                    Ok::<(), ProxyError>(())
                })
                .await
                .unwrap();
            assert_ne!(decision, FlowOpenDecision::Create);
        }
        assert_eq!(queries.get(), 0);

        assert_eq!(
            decide_flow_open(
                FlowAdmission::Create,
                &mut budget,
                &mut freshness,
                start,
                || async {
                    queries.set(queries.get() + 1);
                    Ok::<(), ProxyError>(())
                },
            )
            .await
            .unwrap(),
            FlowOpenDecision::Create
        );
        assert_eq!(queries.get(), 1);

        assert_eq!(
            decide_flow_open(
                FlowAdmission::Create,
                &mut budget,
                &mut freshness,
                start + Duration::from_millis(500),
                || async {
                    queries.set(queries.get() + 1);
                    Ok::<(), ProxyError>(())
                },
            )
            .await
            .unwrap(),
            FlowOpenDecision::Create
        );
        assert_eq!(queries.get(), 1, "同一秒内的新 flow 必须合并授权查询");

        decide_flow_open(
            FlowAdmission::Create,
            &mut budget,
            &mut freshness,
            start + Duration::from_secs(1),
            || async {
                queries.set(queries.get() + 1);
                Ok::<(), ProxyError>(())
            },
        )
        .await
        .unwrap();
        assert_eq!(queries.get(), 2);
    }

    #[tokio::test]
    async fn flow_creation_budget_has_a_bounded_burst_and_refill() {
        let start = Instant::now();
        let mut budget = FlowCreationBudget::new(start);
        let mut freshness = AuthorizationFreshness::default();
        for _ in 0..FLOW_CREATION_BURST as usize {
            assert_eq!(
                decide_flow_open(
                    FlowAdmission::Create,
                    &mut budget,
                    &mut freshness,
                    start,
                    || async { Ok(()) },
                )
                .await
                .unwrap(),
                FlowOpenDecision::Create
            );
        }
        assert_eq!(
            decide_flow_open(
                FlowAdmission::Create,
                &mut budget,
                &mut freshness,
                start,
                || async { Ok(()) },
            )
            .await
            .unwrap(),
            FlowOpenDecision::RateLimited
        );
        assert_eq!(
            decide_flow_open(
                FlowAdmission::Create,
                &mut budget,
                &mut freshness,
                start + Duration::from_secs(1),
                || async { Ok(()) },
            )
            .await
            .unwrap(),
            FlowOpenDecision::Create
        );
    }

    #[tokio::test]
    async fn failed_flow_revalidation_is_not_cached_and_fails_closed() {
        let start = Instant::now();
        let mut budget = FlowCreationBudget::new(start);
        let mut freshness = AuthorizationFreshness::default();
        let result = decide_flow_open(
            FlowAdmission::Create,
            &mut budget,
            &mut freshness,
            start,
            || async {
                Err(ProxyError::Authentication(
                    "revoked during test".to_string(),
                ))
            },
        )
        .await;
        assert!(result.is_err());
        assert!(freshness.requires_recheck(start + Duration::from_millis(1)));
    }

    #[test]
    fn absolute_expiry_uses_the_epoch_boundary_without_second_rounding() {
        let half_second_before = UNIX_EPOCH + Duration::from_millis(99_500);
        assert_eq!(
            duration_until_expiry(100, half_second_before),
            Some(Duration::from_millis(500))
        );
        assert_eq!(
            duration_until_expiry(-1, half_second_before),
            Some(Duration::ZERO)
        );
        assert!(!session_expired_at(Some(100), half_second_before));
        assert!(session_expired_at(
            Some(100),
            UNIX_EPOCH + Duration::from_secs(100)
        ));
        assert!(session_expired_at(Some(-1), UNIX_EPOCH));
        assert!(!session_expired_at(None, UNIX_EPOCH));
    }

    #[tokio::test]
    async fn session_closes_at_absolute_expiry_without_inbound_activity() {
        let expires_at = common::current_timestamp() + 10;
        let repository: Arc<dyn UserRepository> = Arc::new(NeverRespondingUserRepository);
        let user_manager = Arc::new(UserManager::new(repository));
        let config: ProxyConfig = toml::from_str(
            r#"
listen_addr = "127.0.0.1:0"
users_database_path = "users.sqlite3"
access_log_database_path = "access.sqlite3"
"#,
        )
        .unwrap();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = socket.local_addr().unwrap();
        let context = SessionContext {
            socket,
            config: Arc::new(config),
            user_manager,
            egress_state: Arc::new(EgressState::new(None, None).unwrap()),
            access_recorder: AccessRecorder::default(),
            username: "alice".to_string(),
            authenticated_public_key_pem: "unused".to_string(),
            authenticated_key_version: None,
            expires_at: Some(expires_at),
            peer,
        };
        let codec = UdpSessionCodec::new(UdpSessionRole::Proxy, [1; 16], [2; 32], [3; 32], [4; 32])
            .unwrap();
        let (_inbound_tx, inbound_rx) = mpsc::channel(1);
        tokio::time::pause();
        tokio::time::timeout(
            Duration::from_secs(11),
            run_session(context, codec, inbound_rx),
        )
        .await
        .expect("session must close at its absolute expiry")
        .unwrap();
    }

    #[tokio::test]
    async fn periodic_revalidation_fails_closed_within_five_seconds() {
        let directory = TempDir::new().unwrap();
        let repository: Arc<dyn UserRepository> = Arc::new(
            SqliteUserRepository::connect(directory.path().join("users.sqlite3"))
                .await
                .unwrap(),
        );
        let user_manager = Arc::new(UserManager::new(repository));
        let config: ProxyConfig = toml::from_str(
            r#"
listen_addr = "127.0.0.1:0"
users_database_path = "users.sqlite3"
access_log_database_path = "access.sqlite3"
udp_session_authorization_recheck_secs = 1
"#,
        )
        .unwrap();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = socket.local_addr().unwrap();
        let context = SessionContext {
            socket,
            config: Arc::new(config),
            user_manager,
            egress_state: Arc::new(EgressState::new(None, None).unwrap()),
            access_recorder: AccessRecorder::default(),
            username: "missing-user".to_string(),
            authenticated_public_key_pem: "unused".to_string(),
            authenticated_key_version: None,
            expires_at: None,
            peer,
        };
        let codec = UdpSessionCodec::new(UdpSessionRole::Proxy, [5; 16], [6; 32], [7; 32], [8; 32])
            .unwrap();
        let (_inbound_tx, inbound_rx) = mpsc::channel(1);
        tokio::time::timeout(
            Duration::from_secs(2),
            run_session(context, codec, inbound_rx),
        )
        .await
        .expect("missing user must fail closed within the configured one-second recheck")
        .unwrap();
    }
}
