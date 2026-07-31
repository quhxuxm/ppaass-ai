use common::ClientConnectionConfig;
use common::client_connection::authenticated::{
    AuthenticatedConnection, AuthenticationFailure, VerifiedAuthAttempt, VerifiedProxyAuthStatus,
    auth_failure_code, subscribe_verified_proxy_auth_statuses,
};
use futures::{SinkExt, StreamExt};
use protocol::crypto::encrypt_oaep_sha256_labelled;
use protocol::tcp_transport::{
    TCP_HANDSHAKE_VERSION, TCP_MASTER_SECRET_LEN, TCP_OAEP_LABEL, TCP_SERVER_NONCE_LEN,
    TCP_SESSION_ID_LEN, TcpSessionCipher, TcpSessionRole, TcpSessionSecret,
    encode_tcp_session_secret, tcp_auth_request_transcript, tcp_auth_transcript_hash,
};
use protocol::{
    Address, AuthFailureCode, AuthResponse, CipherState, ConnectResponse, ProxyCodec, ProxyRequest,
    ProxyResponse, TransportProtocol,
    crypto::{RsaKeyPair, verify_pss_sha256},
};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio_util::codec::Framed;

struct TestClientConfig {
    username: String,
    private_key_pem: String,
}

impl fmt::Debug for TestClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TestClientConfig")
            .field("username", &self.username)
            .field("private_key_pem", &"[REDACTED]")
            .finish()
    }
}

impl ClientConnectionConfig for TestClientConfig {
    fn remote_addr(&self) -> String {
        "unused.invalid:1".to_string()
    }

    fn username(&self) -> String {
        self.username.clone()
    }

    fn private_key_pem(&self) -> Result<String, String> {
        Ok(self.private_key_pem.clone())
    }

    fn timeout_duration(&self) -> Duration {
        Duration::from_secs(5)
    }
}

#[test]
fn older_authentication_result_cannot_replace_newer_status_for_same_user() {
    let username = "ordering-same-user".to_string();
    let mut statuses = subscribe_verified_proxy_auth_statuses();
    let older = VerifiedAuthAttempt::begin(username.clone());
    let newer = VerifiedAuthAttempt::begin(username.clone());

    assert!(newer.publish(VerifiedProxyAuthStatus::UserExpired {
        username: username.clone(),
    }));
    assert!(!older.publish(VerifiedProxyAuthStatus::Active {
        username: username.clone(),
    }));

    assert_eq!(
        collect_statuses_for(&mut statuses, &[&username]),
        vec![VerifiedProxyAuthStatus::UserExpired { username }]
    );
}

#[test]
fn authentication_result_ordering_is_independent_per_user() {
    let older_username = "ordering-older-user".to_string();
    let newer_username = "ordering-newer-user".to_string();
    let mut statuses = subscribe_verified_proxy_auth_statuses();
    let older = VerifiedAuthAttempt::begin(older_username.clone());
    let newer = VerifiedAuthAttempt::begin(newer_username.clone());

    assert!(newer.publish(VerifiedProxyAuthStatus::UserExpired {
        username: newer_username.clone(),
    }));
    assert!(older.publish(VerifiedProxyAuthStatus::Active {
        username: older_username.clone(),
    }));

    assert_eq!(
        collect_statuses_for(&mut statuses, &[&older_username, &newer_username]),
        vec![
            VerifiedProxyAuthStatus::UserExpired {
                username: newer_username,
            },
            VerifiedProxyAuthStatus::Active {
                username: older_username,
            },
        ]
    );
}

#[test]
fn authentication_attempt_without_result_does_not_publish_status() {
    let username = "ordering-network-error".to_string();
    let mut statuses = subscribe_verified_proxy_auth_statuses();
    drop(VerifiedAuthAttempt::begin(username.clone()));
    assert!(collect_statuses_for(&mut statuses, &[&username]).is_empty());
}

#[tokio::test]
async fn structured_terminal_failure_changes_status() {
    let mut statuses = subscribe_verified_proxy_auth_statuses();

    for (code, expected) in [
        (
            AuthFailureCode::UserExpired,
            VerifiedProxyAuthStatus::UserExpired {
                username: "failure-alice".to_string(),
            },
        ),
        (
            AuthFailureCode::UserDisabled,
            VerifiedProxyAuthStatus::UserDisabled {
                username: "failure-alice".to_string(),
            },
        ),
    ] {
        let error = authenticate_against_failure(Some(code)).await;
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(auth_failure_code(&error), Some(code));
        let typed = error
            .get_ref()
            .and_then(|source| source.downcast_ref::<AuthenticationFailure>())
            .unwrap();
        assert_eq!(typed.username(), "failure-alice");
        assert_eq!(typed.code(), code);
        loop {
            let published = statuses.recv().await.unwrap();
            if published.username() == "failure-alice" {
                assert_eq!(published, expected);
                break;
            }
        }
    }

    let other = authenticate_against_failure(Some(AuthFailureCode::Other)).await;
    assert_eq!(auth_failure_code(&other), Some(AuthFailureCode::Other));
    assert_no_status_for(&mut statuses, "failure-alice");

    let generic = authenticate_against_failure(None).await;
    assert_eq!(generic.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(auth_failure_code(&generic), None);
    assert_no_status_for(&mut statuses, "failure-alice");
}

#[tokio::test]
async fn framed_stream_switches_from_clear_auth_to_encrypted_connect() {
    let mut statuses = subscribe_verified_proxy_auth_statuses();
    let user_identity = RsaKeyPair::generate(2048).unwrap();
    let user_public_key =
        RsaKeyPair::from_public_key_pem(&user_identity.public_key_to_pem().unwrap()).unwrap();
    let config = TestClientConfig {
        username: "alice".to_string(),
        private_key_pem: user_identity.private_key_to_pem().unwrap(),
    };
    let expected_address = Address::Domain {
        host: "example.com".to_string(),
        port: 443,
    };
    let server_expected_address = expected_address.clone();
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let server_flow = async move {
        let cipher_state = Arc::new(CipherState::new());
        let framed = Framed::new(server_io, ProxyCodec::new(cipher_state.clone()));
        let (mut writer, mut reader) = framed.split();

        let auth = match reader.next().await.unwrap().unwrap() {
            ProxyRequest::Auth(auth) => auth,
            other => panic!("expected Auth request, got {other:?}"),
        };
        auth.validate_shape().unwrap();
        let transcript = tcp_auth_request_transcript(
            auth.version,
            &auth.username,
            auth.timestamp,
            &auth.client_nonce,
        )
        .unwrap();
        verify_pss_sha256(&user_public_key, &transcript, &auth.signature).unwrap();
        let transcript_hash = tcp_auth_transcript_hash(&transcript);
        let master_secret = [11_u8; TCP_MASTER_SECRET_LEN];
        let server_nonce = [22_u8; TCP_SERVER_NONCE_LEN];
        let session_id = [33_u8; TCP_SESSION_ID_LEN];
        let secret = TcpSessionSecret {
            version: TCP_HANDSHAKE_VERSION,
            auth_transcript_hash: transcript_hash,
            client_nonce: auth.client_nonce,
            server_nonce,
            session_id,
            master_secret,
        };
        let encrypted_session = encrypt_oaep_sha256_labelled(
            &user_public_key,
            TCP_OAEP_LABEL,
            &encode_tcp_session_secret(&secret).unwrap(),
        )
        .unwrap();
        let server_cipher = TcpSessionCipher::new(
            TcpSessionRole::Proxy,
            master_secret,
            transcript_hash,
            auth.client_nonce,
            server_nonce,
            session_id,
        )
        .unwrap();

        writer
            .send(ProxyResponse::Auth(AuthResponse::success(
                encrypted_session,
            )))
            .await
            .unwrap();
        cipher_state
            .set_session_cipher(Arc::new(server_cipher))
            .unwrap();

        let connect = match reader.next().await.unwrap().unwrap() {
            ProxyRequest::Connect(connect) => connect,
            other => panic!("expected encrypted Connect request, got {other:?}"),
        };
        assert_eq!(connect.address, server_expected_address);
        assert_eq!(connect.transport, TransportProtocol::Tcp);
        let request_id = connect.request_id.clone();
        writer
            .send(ProxyResponse::Connect(ConnectResponse {
                request_id: connect.request_id,
                success: true,
                message: "connected".to_string(),
            }))
            .await
            .unwrap();
        request_id
    };

    let client_flow = async {
        let connection = AuthenticatedConnection::authenticate_stream(client_io, &config)
            .await
            .unwrap();
        let (_stream, request_id) = connection
            .connect_to_target(expected_address, TransportProtocol::Tcp)
            .await
            .unwrap();
        request_id
    };

    let (server_request_id, client_request_id) =
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(server_flow, client_flow)
        })
        .await
        .unwrap();
    assert_eq!(server_request_id, client_request_id);
    loop {
        let status = statuses.recv().await.unwrap();
        if status.username() == "alice" {
            assert_eq!(
                status,
                VerifiedProxyAuthStatus::Active {
                    username: "alice".to_string(),
                }
            );
            break;
        }
    }
}

fn collect_statuses_for(
    statuses: &mut broadcast::Receiver<VerifiedProxyAuthStatus>,
    usernames: &[&str],
) -> Vec<VerifiedProxyAuthStatus> {
    let mut matching = Vec::new();
    loop {
        match statuses.try_recv() {
            Ok(status) if usernames.contains(&status.username()) => matching.push(status),
            Ok(_) | Err(broadcast::error::TryRecvError::Lagged(_)) => {}
            Err(broadcast::error::TryRecvError::Empty | broadcast::error::TryRecvError::Closed) => {
                break;
            }
        }
    }
    matching
}

async fn authenticate_against_failure(code: Option<AuthFailureCode>) -> std::io::Error {
    let user_identity = RsaKeyPair::generate(2048).unwrap();
    let config = TestClientConfig {
        username: "failure-alice".to_string(),
        private_key_pem: user_identity.private_key_to_pem().unwrap(),
    };
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let server_flow = async move {
        let cipher_state = Arc::new(CipherState::new());
        let framed = Framed::new(server_io, ProxyCodec::new(cipher_state));
        let (mut writer, mut reader) = framed.split();
        let _auth = match reader.next().await.unwrap().unwrap() {
            ProxyRequest::Auth(auth) => auth,
            other => panic!("expected Auth request, got {other:?}"),
        };
        let response = match code {
            Some(code) => {
                let message = match code {
                    AuthFailureCode::UserExpired => "User expired",
                    AuthFailureCode::UserDisabled => "User disabled",
                    AuthFailureCode::Other => "Authentication failed",
                };
                AuthResponse::terminal_failure(code, message)
            }
            None => AuthResponse::failure("Authentication failed"),
        };
        writer.send(ProxyResponse::Auth(response)).await.unwrap();
    };
    let client_flow = AuthenticatedConnection::authenticate_stream(client_io, &config);
    let (_, result) = tokio::join!(server_flow, client_flow);
    match result {
        Ok(_) => panic!("failed authentication unexpectedly succeeded"),
        Err(error) => error,
    }
}

fn assert_no_status_for(
    statuses: &mut broadcast::Receiver<VerifiedProxyAuthStatus>,
    username: &str,
) {
    while let Ok(status) = statuses.try_recv() {
        assert_ne!(status.username(), username);
    }
}
