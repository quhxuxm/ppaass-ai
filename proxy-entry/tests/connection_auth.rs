mod support;

use futures::{SinkExt, StreamExt};
use protocol::tcp_transport::{
    AuthFailureCode, TCP_AUTH_NONCE_LEN, TCP_HANDSHAKE_VERSION, tcp_auth_request_transcript,
};
use protocol::{
    AgentCodec, AuthRequest, AuthResponse, CipherState, CompressionMode, ProxyRequest,
    ProxyResponse, RsaKeyPair,
};
use proxy_entry::access_log::AccessRecorder;
use proxy_entry::config::{ProxyConfig, UserConfig};
use proxy_entry::connection::{
    EgressState, GENERIC_AUTH_FAILURE_MESSAGE, ServerConnection, terminal_auth_failure_response,
};
use proxy_entry::error::{ProxyError, Result};
use proxy_entry::user_manager::UserManager;
use std::sync::Arc;
use support::TestAuthorizationProvider;
use tokio::io::DuplexStream;
use tokio_util::codec::Framed;

#[test]
fn terminal_failures_are_limited_to_account_state_codes() {
    for (code, message) in [
        (AuthFailureCode::UserExpired, "User expired"),
        (AuthFailureCode::UserDisabled, "User disabled"),
    ] {
        let response = terminal_auth_failure_response(code, message).unwrap();
        assert!(!response.success);
        assert_eq!(response.failure_code, Some(code));
        assert_eq!(response.message, message);
        assert!(response.encrypted_session.is_empty());
        response.validate_shape().unwrap();
    }
    assert!(
        terminal_auth_failure_response(AuthFailureCode::Other, GENERIC_AUTH_FAILURE_MESSAGE)
            .is_err()
    );
}

fn test_proxy_config() -> Arc<ProxyConfig> {
    Arc::new(support::proxy_config("replay_attack_tolerance = 300"))
}

fn auth_request(
    username: &str,
    timestamp: i64,
    nonce_marker: u8,
    signer: &RsaKeyPair,
) -> AuthRequest {
    let client_nonce = [nonce_marker; TCP_AUTH_NONCE_LEN];
    let transcript =
        tcp_auth_request_transcript(TCP_HANDSHAKE_VERSION, username, timestamp, &client_nonce)
            .unwrap();
    AuthRequest {
        version: TCP_HANDSHAKE_VERSION,
        username: username.to_string(),
        timestamp,
        client_nonce,
        signature: signer.sign_pss_sha256(&transcript).unwrap(),
    }
}

fn user_config(public_key_pem: &str, enabled: bool, expires_at: Option<i64>) -> UserConfig {
    UserConfig {
        username: "alice".to_string(),
        public_key_pem: public_key_pem.to_string(),
        expires_at: expires_at.map(|value| value.to_string()),
        permissions: vec![],
        enabled,
        key_version: Some(1),
    }
}

fn test_user_manager() -> Arc<UserManager> {
    Arc::new(UserManager::new(Arc::new(
        TestAuthorizationProvider::default(),
    )))
}

fn connection_pair(
    proxy_config: Arc<ProxyConfig>,
    user_manager: Arc<UserManager>,
) -> (ServerConnection, Framed<DuplexStream, AgentCodec>) {
    let (client_io, server_io) = tokio::io::duplex(16 * 1024);
    let egress_state = Arc::new(EgressState::new(None, None).unwrap());
    let connection = ServerConnection::new(
        server_io,
        CompressionMode::None,
        proxy_config,
        user_manager,
        egress_state,
        AccessRecorder::default(),
    );
    let cipher_state = Arc::new(CipherState::with_compression(CompressionMode::None));
    (
        connection,
        Framed::new(client_io, AgentCodec::new(cipher_state)),
    )
}

async fn authenticate_request(
    request: AuthRequest,
    user: UserConfig,
    proxy_config: Arc<ProxyConfig>,
    user_manager: Arc<UserManager>,
) -> (Result<()>, AuthResponse) {
    let (mut connection, mut client) = connection_pair(proxy_config.clone(), user_manager);
    client.send(ProxyRequest::Auth(request)).await.unwrap();
    connection.peek_auth_username().await.unwrap();
    let result = connection.authenticate(proxy_config.as_ref(), user).await;
    let response = client.next().await.unwrap().unwrap();
    let ProxyResponse::Auth(response) = response else {
        panic!("expected authentication response");
    };
    (result, response)
}

async fn send_unknown_user_failure(request: AuthRequest) -> AuthResponse {
    let (mut connection, mut client) = connection_pair(test_proxy_config(), test_user_manager());
    client.send(ProxyRequest::Auth(request)).await.unwrap();
    connection.peek_auth_username().await.unwrap();
    connection.send_auth_error().await.unwrap();
    let response = client.next().await.unwrap().unwrap();
    let ProxyResponse::Auth(response) = response else {
        panic!("expected authentication response");
    };
    response
}

fn assert_generic_failure(response: &AuthResponse) {
    assert_eq!(response.version, TCP_HANDSHAKE_VERSION);
    assert!(!response.success);
    assert_eq!(response.message, GENERIC_AUTH_FAILURE_MESSAGE);
    assert_eq!(response.failure_code, None);
    assert!(response.encrypted_session.is_empty());
    response.validate_shape().unwrap();
}

fn assert_terminal_failure(
    response: &AuthResponse,
    expected_code: AuthFailureCode,
    expected_message: &str,
) {
    assert!(!response.success);
    assert_eq!(response.failure_code, Some(expected_code));
    assert_eq!(response.message, expected_message);
    assert!(response.encrypted_session.is_empty());
    response.validate_shape().unwrap();
}

#[tokio::test]
async fn forged_proof_cannot_distinguish_active_disabled_or_expired_users() {
    let legitimate_key = RsaKeyPair::generate(2048).unwrap();
    let attacker_key = RsaKeyPair::generate(2048).unwrap();
    let user_public_key = legitimate_key.public_key_to_pem().unwrap();
    let proxy_config = test_proxy_config();
    let user_manager = test_user_manager();
    let now = common::current_timestamp();
    let users = [
        user_config(&user_public_key, true, None),
        user_config(&user_public_key, false, None),
        user_config(&user_public_key, true, Some(now - 1)),
    ];

    for (index, user) in users.into_iter().enumerate() {
        let request = auth_request("alice", now, index as u8 + 1, &attacker_key);
        let (result, response) =
            authenticate_request(request, user, proxy_config.clone(), user_manager.clone()).await;
        assert!(matches!(
            result,
            Err(ProxyError::Authentication(ref message))
                if message == "Invalid authentication proof"
        ));
        assert_generic_failure(&response);
    }
}

#[tokio::test]
async fn unknown_user_receives_the_same_generic_failure() {
    let attacker_key = RsaKeyPair::generate(2048).unwrap();
    let request = auth_request(
        "missing-user",
        common::current_timestamp(),
        10,
        &attacker_key,
    );
    assert_generic_failure(&send_unknown_user_failure(request).await);
}

#[tokio::test]
async fn expired_challenge_cannot_distinguish_user_state() {
    let user_key = RsaKeyPair::generate(2048).unwrap();
    let user_public_key = user_key.public_key_to_pem().unwrap();
    let proxy_config = test_proxy_config();
    let user_manager = test_user_manager();
    let now = common::current_timestamp();
    let stale_timestamp = now - proxy_config.replay_attack_tolerance - 1;
    let users = [
        user_config(&user_public_key, true, None),
        user_config(&user_public_key, false, None),
        user_config(&user_public_key, true, Some(now - 1)),
    ];

    for (index, user) in users.into_iter().enumerate() {
        let request = auth_request("alice", stale_timestamp, index as u8 + 11, &user_key);
        let (result, response) =
            authenticate_request(request, user, proxy_config.clone(), user_manager.clone()).await;
        assert!(matches!(
            result,
            Err(ProxyError::Authentication(ref message)) if message == "Timestamp expired"
        ));
        assert_generic_failure(&response);
    }
}

#[tokio::test]
async fn replayed_terminal_request_receives_only_generic_failure() {
    let user_key = RsaKeyPair::generate(2048).unwrap();
    let public_key = user_key.public_key_to_pem().unwrap();
    let proxy_config = test_proxy_config();
    let user_manager = test_user_manager();
    let request = auth_request("alice", common::current_timestamp(), 20, &user_key);
    let disabled_user = user_config(&public_key, false, None);

    let (first_result, first_response) = authenticate_request(
        request.clone(),
        disabled_user.clone(),
        proxy_config.clone(),
        user_manager.clone(),
    )
    .await;
    assert!(matches!(
        first_result,
        Err(ProxyError::Authentication(ref message)) if message == "User disabled"
    ));
    assert_terminal_failure(
        &first_response,
        AuthFailureCode::UserDisabled,
        "User disabled",
    );

    let (replay_result, replay_response) =
        authenticate_request(request, disabled_user, proxy_config, user_manager).await;
    assert!(matches!(
        replay_result,
        Err(ProxyError::Authentication(ref message))
            if message == "Authentication request replayed"
    ));
    assert_generic_failure(&replay_response);
}

#[tokio::test]
async fn valid_proof_receives_account_status_or_encrypted_session() {
    let user_key = RsaKeyPair::generate(2048).unwrap();
    let public_key = user_key.public_key_to_pem().unwrap();
    let proxy_config = test_proxy_config();
    let user_manager = test_user_manager();
    let now = common::current_timestamp();

    for (marker, user, code, message) in [
        (
            21,
            user_config(&public_key, false, None),
            AuthFailureCode::UserDisabled,
            "User disabled",
        ),
        (
            22,
            user_config(&public_key, true, Some(now - 1)),
            AuthFailureCode::UserExpired,
            "User expired",
        ),
    ] {
        let request = auth_request("alice", now, marker, &user_key);
        let (result, response) =
            authenticate_request(request, user, proxy_config.clone(), user_manager.clone()).await;
        assert!(result.is_err());
        assert_terminal_failure(&response, code, message);
    }

    let request = auth_request("alice", now, 23, &user_key);
    let (result, response) = authenticate_request(
        request,
        user_config(&public_key, true, None),
        proxy_config,
        user_manager,
    )
    .await;
    result.unwrap();
    assert!(response.success);
    assert_eq!(response.failure_code, None);
    assert!(!response.encrypted_session.is_empty());
}
