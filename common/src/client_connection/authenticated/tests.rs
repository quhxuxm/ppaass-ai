use super::*;
use crate::client_connection::config::ClientConnectionConfig;
use futures::{SinkExt, StreamExt};
use protocol::crypto::encrypt_oaep_sha256_labelled;
use protocol::tcp_transport::{
    TCP_HANDSHAKE_VERSION, TCP_MASTER_SECRET_LEN, TCP_OAEP_LABEL, TCP_SERVER_NONCE_LEN,
    TCP_SESSION_ID_LEN, TcpSessionCipher, TcpSessionRole, TcpSessionSecret,
    encode_tcp_session_secret, tcp_auth_failure_signature_transcript, tcp_auth_request_transcript,
    tcp_auth_response_signature_transcript, tcp_auth_transcript_hash,
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
    proxy_identity_public_key_pem: String,
}

impl fmt::Debug for TestClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TestClientConfig")
            .field("username", &self.username)
            .field("private_key_pem", &"[REDACTED]")
            .field("proxy_identity_public_key_pem", &"[CONFIGURED]")
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

    fn proxy_identity_public_key_pem(&self) -> Result<String, String> {
        Ok(self.proxy_identity_public_key_pem.clone())
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
fn authentication_attempt_without_verified_result_does_not_publish_status() {
    let username = "ordering-network-error".to_string();
    let mut statuses = subscribe_verified_proxy_auth_statuses();

    drop(VerifiedAuthAttempt::begin(username.clone()));

    assert!(collect_statuses_for(&mut statuses, &[&username]).is_empty());
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

#[derive(Clone, Copy)]
enum FailureResponseMode {
    Signed(AuthFailureCode),
    UnsignedExpired,
    TamperedCode,
    WrongRequestContext,
}

async fn authenticate_against_failure(mode: FailureResponseMode) -> std::io::Error {
    let user_identity = RsaKeyPair::generate(2048).unwrap();
    let proxy_identity = RsaKeyPair::generate(2048).unwrap();
    let config = TestClientConfig {
        username: "failure-alice".to_string(),
        private_key_pem: user_identity.private_key_to_pem().unwrap(),
        proxy_identity_public_key_pem: proxy_identity.public_key_to_pem().unwrap(),
    };
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let server_flow = async move {
        let cipher_state = Arc::new(CipherState::new());
        let framed = Framed::new(server_io, ProxyCodec::new(cipher_state));
        let (mut writer, mut reader) = framed.split();
        let auth = match reader.next().await.unwrap().unwrap() {
            ProxyRequest::Auth(auth) => auth,
            other => panic!("expected Auth request, got {other:?}"),
        };
        let transcript = tcp_auth_request_transcript(
            auth.version,
            &auth.username,
            auth.timestamp,
            &auth.client_nonce,
        )
        .unwrap();
        let request_hash = tcp_auth_transcript_hash(&transcript);
        let response = match mode {
            FailureResponseMode::Signed(code) => {
                let message = match code {
                    AuthFailureCode::UserExpired => "User expired",
                    AuthFailureCode::UserDisabled => "User disabled",
                    AuthFailureCode::Other => "Authentication failed",
                };
                let failure_transcript = tcp_auth_failure_signature_transcript(
                    TCP_HANDSHAKE_VERSION,
                    &request_hash,
                    code,
                    message,
                )
                .unwrap();
                AuthResponse::signed_failure(
                    code,
                    message,
                    proxy_identity.sign_pss_sha256(&failure_transcript).unwrap(),
                )
            }
            FailureResponseMode::UnsignedExpired => AuthResponse::signed_failure(
                AuthFailureCode::UserExpired,
                "User expired",
                Vec::new(),
            ),
            FailureResponseMode::TamperedCode => {
                let failure_transcript = tcp_auth_failure_signature_transcript(
                    TCP_HANDSHAKE_VERSION,
                    &request_hash,
                    AuthFailureCode::UserExpired,
                    "User expired",
                )
                .unwrap();
                AuthResponse::signed_failure(
                    AuthFailureCode::UserDisabled,
                    "User expired",
                    proxy_identity.sign_pss_sha256(&failure_transcript).unwrap(),
                )
            }
            FailureResponseMode::WrongRequestContext => {
                let mut wrong_request_hash = request_hash;
                wrong_request_hash[0] ^= 1;
                let failure_transcript = tcp_auth_failure_signature_transcript(
                    TCP_HANDSHAKE_VERSION,
                    &wrong_request_hash,
                    AuthFailureCode::UserExpired,
                    "User expired",
                )
                .unwrap();
                AuthResponse::signed_failure(
                    AuthFailureCode::UserExpired,
                    "User expired",
                    proxy_identity.sign_pss_sha256(&failure_transcript).unwrap(),
                )
            }
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

#[tokio::test]
async fn only_pinned_proxy_terminal_failure_changes_verified_status() {
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
        let error = authenticate_against_failure(FailureResponseMode::Signed(code)).await;
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

    let other =
        authenticate_against_failure(FailureResponseMode::Signed(AuthFailureCode::Other)).await;
    assert_eq!(auth_failure_code(&other), Some(AuthFailureCode::Other));
    assert_no_status_for(&mut statuses, "failure-alice");

    for mode in [
        FailureResponseMode::UnsignedExpired,
        FailureResponseMode::TamperedCode,
        FailureResponseMode::WrongRequestContext,
    ] {
        let error = authenticate_against_failure(mode).await;
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(auth_failure_code(&error), None);
        assert_no_status_for(&mut statuses, "failure-alice");
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

mod handshake;
