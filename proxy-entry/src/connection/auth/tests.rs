use super::*;
use crate::user_manager::TestAuthorizationProvider;
use protocol::{AgentCodec, crypto::verify_pss_sha256, tcp_transport::TCP_AUTH_NONCE_LEN};
use tokio::io::DuplexStream;
use tokio_util::codec::Framed;

mod cases;

#[test]
fn proxy_signs_only_terminal_failure_codes_and_current_request_context() {
    let identity = RsaKeyPair::generate(2048).unwrap();
    let public_key =
        RsaKeyPair::from_public_key_pem(&identity.public_key_to_pem().unwrap()).unwrap();
    let request_hash = [42_u8; 32];

    for (code, message) in [
        (AuthFailureCode::UserExpired, "User expired"),
        (AuthFailureCode::UserDisabled, "User disabled"),
    ] {
        let response =
            signed_terminal_auth_failure_response(&identity, &request_hash, code, message).unwrap();
        assert!(!response.success);
        assert_eq!(response.failure_code, Some(code));
        assert!(response.encrypted_session.is_empty());
        assert!(!response.proxy_signature.is_empty());

        let transcript =
            tcp_auth_failure_signature_transcript(response.version, &request_hash, code, message)
                .unwrap();
        verify_pss_sha256(&public_key, &transcript, &response.proxy_signature).unwrap();

        let mut wrong_request_hash = request_hash;
        wrong_request_hash[0] ^= 1;
        let replayed = tcp_auth_failure_signature_transcript(
            response.version,
            &wrong_request_hash,
            code,
            message,
        )
        .unwrap();
        assert!(verify_pss_sha256(&public_key, &replayed, &response.proxy_signature).is_err());
    }

    assert!(
        signed_terminal_auth_failure_response(
            &identity,
            &request_hash,
            AuthFailureCode::Other,
            GENERIC_AUTH_FAILURE_MESSAGE,
        )
        .is_err()
    );
}

fn test_proxy_config() -> Arc<ProxyConfig> {
    Arc::new(
        toml::from_str(
            r#"
listen_addr = "127.0.0.1:0"
entry_id = "entry-test"
registry_control_url = "http://127.0.0.1:8797"
registry_control_token_path = "control-token"
replay_attack_tolerance = 300
"#,
        )
        .unwrap(),
    )
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

async fn test_user_manager() -> (Arc<TestAuthorizationProvider>, Arc<UserManager>) {
    let provider = Arc::new(TestAuthorizationProvider::default());
    let manager = Arc::new(UserManager::new(provider.clone()));
    (provider, manager)
}

async fn authenticate_request(
    request: AuthRequest,
    user: UserConfig,
    proxy_config: Arc<ProxyConfig>,
    user_manager: Arc<UserManager>,
    transport_identity: Arc<RsaKeyPair>,
) -> (Result<()>, AuthResponse) {
    let (client_io, server_io): (DuplexStream, DuplexStream) = tokio::io::duplex(16 * 1024);
    let egress_state = Arc::new(EgressState::new(None, None).unwrap());
    let mut connection = ServerConnection::new(
        server_io,
        CompressionMode::None,
        proxy_config,
        user_manager,
        transport_identity,
        egress_state,
        AccessRecorder::default(),
    );
    connection.pending_auth_request = Some(request);

    let result = connection
        .authenticate(connection.proxy_config.clone().as_ref(), user)
        .await;
    let cipher_state = Arc::new(CipherState::with_compression(CompressionMode::None));
    let mut client = Framed::new(client_io, AgentCodec::new(cipher_state));
    let response = client.next().await.unwrap().unwrap();
    let ProxyResponse::Auth(response) = response else {
        panic!("expected authentication response");
    };
    (result, response)
}

async fn send_unknown_user_failure(
    request: AuthRequest,
    proxy_config: Arc<ProxyConfig>,
    user_manager: Arc<UserManager>,
    transport_identity: Arc<RsaKeyPair>,
) -> AuthResponse {
    let (client_io, server_io): (DuplexStream, DuplexStream) = tokio::io::duplex(16 * 1024);
    let egress_state = Arc::new(EgressState::new(None, None).unwrap());
    let mut connection = ServerConnection::new(
        server_io,
        CompressionMode::None,
        proxy_config,
        user_manager,
        transport_identity,
        egress_state,
        AccessRecorder::default(),
    );
    connection.pending_auth_request = Some(request);
    connection.send_auth_error().await.unwrap();

    let cipher_state = Arc::new(CipherState::with_compression(CompressionMode::None));
    let mut client = Framed::new(client_io, AgentCodec::new(cipher_state));
    let response = client.next().await.unwrap().unwrap();
    let ProxyResponse::Auth(response) = response else {
        panic!("expected authentication response");
    };
    response
}

fn assert_unsigned_generic_failure(response: &AuthResponse) {
    assert_eq!(response.version, TCP_HANDSHAKE_VERSION);
    assert!(!response.success);
    assert_eq!(response.message, GENERIC_AUTH_FAILURE_MESSAGE);
    assert_eq!(response.failure_code, None);
    assert!(response.encrypted_session.is_empty());
    assert!(response.proxy_signature.is_empty());
    response.validate_shape().unwrap();
}

fn assert_signed_failure(
    request: &AuthRequest,
    response: &AuthResponse,
    proxy_public_key_pem: &str,
    expected_code: AuthFailureCode,
    expected_message: &str,
) {
    assert!(!response.success);
    assert_eq!(response.failure_code, Some(expected_code));
    assert_eq!(response.message, expected_message);
    let transcript = tcp_auth_request_transcript(
        request.version,
        &request.username,
        request.timestamp,
        &request.client_nonce,
    )
    .unwrap();
    let transcript_hash = tcp_auth_transcript_hash(&transcript);
    let failure_transcript = tcp_auth_failure_signature_transcript(
        response.version,
        &transcript_hash,
        expected_code,
        expected_message,
    )
    .unwrap();
    let proxy_public_key = RsaKeyPair::from_public_key_pem(proxy_public_key_pem).unwrap();
    verify_pss_sha256(
        &proxy_public_key,
        &failure_transcript,
        &response.proxy_signature,
    )
    .unwrap();
}
