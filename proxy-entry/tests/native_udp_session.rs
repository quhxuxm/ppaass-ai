mod support;

use protocol::RsaKeyPair;
use protocol::udp_transport::{UdpSessionCodec, UdpSessionRole};
use proxy_entry::access_log::AccessRecorder;
use proxy_entry::config::{ProxyConfig, UserConfig};
use proxy_entry::connection::EgressState;
use proxy_entry::error::Result;
use proxy_entry::native_udp::auth::validate_session_authorization;
use proxy_entry::native_udp::session::{SessionContext, run_session};
use proxy_entry::user_manager::{AuthorizationProvider, UserManager};
use std::sync::Arc;
use std::time::Duration;
use support::TestAuthorizationProvider;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

struct NeverRespondingUserRepository;

#[async_trait::async_trait]
impl AuthorizationProvider for NeverRespondingUserRepository {
    async fn get_user(&self, _username: &str) -> Result<Option<UserConfig>> {
        std::future::pending().await
    }
}

fn test_user(
    public_key_pem: &str,
    enabled: bool,
    permissions: Vec<&str>,
    expires_at: Option<i64>,
    key_version: i64,
) -> UserConfig {
    UserConfig {
        username: "alice".to_string(),
        public_key_pem: public_key_pem.to_string(),
        expires_at: expires_at.map(|value| value.to_string()),
        permissions: permissions.into_iter().map(str::to_string).collect(),
        enabled,
        key_version: Some(key_version),
    }
}

fn session_context(
    config: ProxyConfig,
    user_manager: Arc<UserManager>,
    socket: Arc<UdpSocket>,
    expires_at: Option<i64>,
    username: &str,
) -> SessionContext {
    SessionContext {
        peer: socket.local_addr().unwrap(),
        socket,
        config: Arc::new(config),
        user_manager,
        egress_state: Arc::new(EgressState::new(None, None).unwrap()),
        access_recorder: AccessRecorder::default(),
        username: username.to_string(),
        authenticated_public_key_pem: "unused".to_string(),
        authenticated_key_version: None,
        expires_at,
    }
}

#[tokio::test]
async fn live_session_revalidation_detects_disable_permission_revocation_and_key_rotation() {
    let first_key = RsaKeyPair::generate(2048)
        .unwrap()
        .public_key_to_pem()
        .unwrap()
        .trim()
        .to_string();
    let provider = Arc::new(TestAuthorizationProvider::new([test_user(
        &first_key,
        true,
        vec!["proxy.connect.udp"],
        Some(i64::MAX),
        1,
    )]));
    let manager = UserManager::new(provider.clone());
    validate_session_authorization(&manager, "alice", &first_key, Some(1))
        .await
        .unwrap();

    for user in [
        test_user(
            &first_key,
            false,
            vec!["proxy.connect.udp"],
            Some(i64::MAX),
            1,
        ),
        test_user(
            &first_key,
            true,
            vec!["proxy.connect.tcp"],
            Some(i64::MAX),
            1,
        ),
        test_user(
            &first_key,
            true,
            vec!["proxy.connect.udp"],
            Some(common::current_timestamp()),
            1,
        ),
    ] {
        provider.set_user(user).await;
        assert!(
            validate_session_authorization(&manager, "alice", &first_key, Some(1))
                .await
                .is_err()
        );
    }

    let second_key = RsaKeyPair::generate(2048)
        .unwrap()
        .public_key_to_pem()
        .unwrap()
        .trim()
        .to_string();
    for user in [
        test_user(
            &second_key,
            true,
            vec!["proxy.connect.udp"],
            Some(i64::MAX),
            2,
        ),
        test_user(
            &first_key,
            true,
            vec!["proxy.connect.udp"],
            Some(i64::MAX),
            3,
        ),
    ] {
        provider.set_user(user).await;
        assert!(
            validate_session_authorization(&manager, "alice", &first_key, Some(1))
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn session_closes_at_absolute_expiry_without_inbound_activity() {
    let expires_at = common::current_timestamp() + 10;
    let manager = Arc::new(UserManager::new(Arc::new(NeverRespondingUserRepository)));
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let context = session_context(
        support::proxy_config(""),
        manager,
        socket,
        Some(expires_at),
        "alice",
    );
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
    let manager = Arc::new(UserManager::new(Arc::new(
        TestAuthorizationProvider::default(),
    )));
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let context = session_context(
        support::proxy_config("udp_session_authorization_recheck_secs = 1"),
        manager,
        socket,
        None,
        "missing-user",
    );
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
