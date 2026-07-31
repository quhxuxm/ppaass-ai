use super::{
    AuthorizationFreshness, FLOW_CREATION_BURST, FlowAdmission, FlowCreationBudget,
    FlowOpenDecision, SessionContext, classify_flow_admission, decide_flow_open,
    duration_until_expiry, run_session, session_expired_at,
};
use crate::access_log::AccessRecorder;
use crate::config::{ProxyConfig, UserConfig};
use crate::connection::EgressState;
use crate::error::ProxyError;
use crate::user_manager::{AuthorizationProvider, TestAuthorizationProvider, UserManager};
use protocol::udp_transport::{UdpSessionCodec, UdpSessionRole};
use std::cell::Cell;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::Instant;

struct NeverRespondingUserRepository;

#[async_trait::async_trait]
impl AuthorizationProvider for NeverRespondingUserRepository {
    async fn get_user(&self, _username: &str) -> crate::error::Result<Option<UserConfig>> {
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
        let decision = decide_flow_open(admission, &mut budget, &mut freshness, start, || async {
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
    let user_manager = Arc::new(UserManager::new(Arc::new(NeverRespondingUserRepository)));
    let config: ProxyConfig = toml::from_str(
        r#"
listen_addr = "127.0.0.1:0"
entry_id = "entry-test"
registry_control_url = "http://127.0.0.1:8797"
registry_control_token_path = "control-token"
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
    let codec =
        UdpSessionCodec::new(UdpSessionRole::Proxy, [1; 16], [2; 32], [3; 32], [4; 32]).unwrap();
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
    let user_manager = Arc::new(UserManager::new(Arc::new(
        TestAuthorizationProvider::default(),
    )));
    let config: ProxyConfig = toml::from_str(
        r#"
listen_addr = "127.0.0.1:0"
entry_id = "entry-test"
registry_control_url = "http://127.0.0.1:8797"
registry_control_token_path = "control-token"
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
    let codec =
        UdpSessionCodec::new(UdpSessionRole::Proxy, [5; 16], [6; 32], [7; 32], [8; 32]).unwrap();
    let (_inbound_tx, inbound_rx) = mpsc::channel(1);
    tokio::time::timeout(
        Duration::from_secs(2),
        run_session(context, codec, inbound_rx),
    )
    .await
    .expect("missing user must fail closed within the configured one-second recheck")
    .unwrap();
}
