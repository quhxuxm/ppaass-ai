mod support;

use futures::StreamExt;
use protocol::{Address, CipherState, ProxyCodec, UdpRelayPacket};
use proxy_entry::access_log::AccessRecorder;
use proxy_entry::config::{
    PERMISSION_PROXY_CONNECT_TCP, PERMISSION_PROXY_CONNECT_UDP, ProxyConfig, UserConfig,
};
use proxy_entry::connection::{
    ConnectionAuthorization, EgressState, FLOW_AUTHORIZATION_COALESCE_WINDOW,
    QueuedUdpRelayResponse, UdpRelayFlowAdmission, UdpRelayFlowChannels, UdpRelayFlowSet,
    UdpRelayResponseQueueResult, classify_udp_relay_flow_admission,
    send_udp_relay_response_batch_with_timeout, try_queue_udp_relay_response,
    udp_relay_channel_size,
};
use proxy_entry::user_manager::{AuthorizationProvider, UserManager};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio_util::codec::Framed;

struct CountingUserRepository {
    user: UserConfig,
    get_count: AtomicUsize,
}

#[async_trait::async_trait]
impl AuthorizationProvider for CountingUserRepository {
    async fn get_user(&self, username: &str) -> proxy_entry::error::Result<Option<UserConfig>> {
        self.get_count.fetch_add(1, Ordering::AcqRel);
        Ok((username == self.user.username).then(|| self.user.clone()))
    }
}

fn test_config(max_flows: usize) -> ProxyConfig {
    support::proxy_config(&format!("udp_relay_max_flows = {max_flows}"))
}

fn counting_repository() -> Arc<CountingUserRepository> {
    Arc::new(CountingUserRepository {
        user: test_user(),
        get_count: AtomicUsize::new(0),
    })
}

fn test_user() -> UserConfig {
    UserConfig {
        username: "alice".to_string(),
        public_key_pem: "handshake-key".to_string(),
        expires_at: Some(i64::MAX.to_string()),
        permissions: vec![
            PERMISSION_PROXY_CONNECT_TCP.to_string(),
            PERMISSION_PROXY_CONNECT_UDP.to_string(),
        ],
        enabled: true,
        key_version: Some(7),
    }
}

fn authorized_flow_set(
    max_flows: usize,
    repository: Arc<CountingUserRepository>,
) -> (
    UdpRelayFlowSet,
    tokio::sync::mpsc::Receiver<QueuedUdpRelayResponse>,
    tokio::sync::mpsc::Receiver<u64>,
) {
    let manager = Arc::new(UserManager::new(repository));
    let authorization = ConnectionAuthorization::new(manager, &test_user()).unwrap();
    let config = test_config(max_flows);
    let channel_size = udp_relay_channel_size(&config);
    let (response_tx, response_rx) = tokio::sync::mpsc::channel(channel_size);
    let (flow_done_tx, flow_done_rx) = tokio::sync::mpsc::channel(channel_size);
    let flow_set = UdpRelayFlowSet::new(
        &config,
        Arc::new(EgressState::new(None, None).unwrap()),
        AccessRecorder::default(),
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

fn relay_packet(flow_id: u64, address: Address) -> UdpRelayPacket {
    UdpRelayPacket {
        flow_id,
        address,
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
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let address = Address::Ipv4 {
        addr: [127, 0, 0, 1],
        port: target_addr.port(),
    };

    full_set
        .dispatch(relay_packet(1, address.clone()))
        .await
        .unwrap();
    assert_eq!(repository.get_count.load(Ordering::Acquire), 1);
    full_set
        .dispatch(relay_packet(1, address.clone()))
        .await
        .unwrap();
    full_set.dispatch(relay_packet(2, address)).await.unwrap();
    assert_eq!(
        repository.get_count.load(Ordering::Acquire),
        1,
        "existing and at-capacity flows must not query authorization"
    );

    let (mut create_set, _response_rx, _flow_done_rx) = authorized_flow_set(4, repository.clone());
    create_set
        .dispatch(relay_packet(10, Address::UdpRelay))
        .await
        .unwrap();
    assert_eq!(repository.get_count.load(Ordering::Acquire), 2);
    create_set
        .dispatch(relay_packet(11, Address::UdpRelay))
        .await
        .unwrap();
    assert_eq!(repository.get_count.load(Ordering::Acquire), 2);

    tokio::time::advance(FLOW_AUTHORIZATION_COALESCE_WINDOW).await;
    create_set
        .dispatch(relay_packet(12, Address::UdpRelay))
        .await
        .unwrap();
    assert_eq!(repository.get_count.load(Ordering::Acquire), 3);
}

struct PendingAgentStream;

impl AsyncRead for PendingAgentStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for PendingAgentStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn udp_relay_response_write_times_out_when_agent_stalls() {
    let cipher_state = Arc::new(CipherState::new());
    cipher_state
        .set_session_cipher(Arc::new(
            protocol::tcp_transport::TcpSessionCipher::new(
                protocol::tcp_transport::TcpSessionRole::Proxy,
                [1; 32],
                [2; 32],
                [3; 32],
                [4; 32],
                [5; 16],
            )
            .unwrap(),
        ))
        .unwrap();
    let framed = Framed::new(PendingAgentStream, ProxyCodec::new(cipher_state));
    let (mut writer, _reader) = framed.split();
    let (_response_tx, mut response_rx) = tokio::sync::mpsc::channel(1);

    let err = send_udp_relay_response_batch_with_timeout(
        &mut writer,
        &mut response_rx,
        QueuedUdpRelayResponse {
            packet: UdpRelayPacket {
                flow_id: 7,
                address: Address::Ipv4 {
                    addr: [127, 0, 0, 1],
                    port: 443,
                },
                data: b"pong".to_vec(),
            },
        },
        "udp-relay-test",
        Duration::from_millis(20),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("Timed out writing UDP relay responses")
    );
}
