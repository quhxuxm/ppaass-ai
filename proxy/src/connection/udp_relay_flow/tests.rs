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
    let (mut full_set, _response_rx, _flow_done_rx) = authorized_flow_set(1, repository.clone());
    let (existing_tx, mut existing_rx) = tokio::sync::mpsc::channel(1);
    full_set.flows.insert(1, UdpRelayFlow { tx: existing_tx });

    // Existing 先于 capacity 分类，继续投递且不触发 DAO；新的 flow 在
    // capacity 满时直接丢弃，同样不触发 DAO。
    full_set.dispatch(relay_packet(1)).await.unwrap();
    assert_eq!(existing_rx.recv().await.unwrap().data, vec![1, 2, 3]);
    full_set.dispatch(relay_packet(2)).await.unwrap();
    assert_eq!(repository.get_count.load(Ordering::Acquire), 0);

    let (mut create_set, _response_rx, _flow_done_rx) = authorized_flow_set(4, repository.clone());
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
