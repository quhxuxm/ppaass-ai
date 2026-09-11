use common::ClientConnectionConfig;
use common::client_connection::authenticated::{AuthenticatedConnection, auth_failure_code};
use futures::{SinkExt, StreamExt};
use protocol::crypto::{RsaKeyPair, verify_pss_sha256};
use protocol::tcp_transport::{
    TCP_AUTH_CONNECT_RESPONSE_OAEP_LABEL, TCP_MASTER_SECRET_LEN, TcpSessionCipher,
    TcpSessionRole, tcp_auth_connect_request_transcript, tcp_auth_connect_transcript_hash,
};
use protocol::{
    Address, AuthConnectIntent, AuthConnectResponse, AuthFailureCode, CipherState, CompressionMode,
    ConnectResponse, ProxyCodec, ProxyRequest, ProxyResponse, TransportProtocol,
};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::codec::Framed;

struct TestConfig {
    username: String,
    private_key_pem: String,
}

impl fmt::Debug for TestConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("TestConfig").finish_non_exhaustive()
    }
}

impl ClientConnectionConfig for TestConfig {
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
    fn compression_mode(&self) -> CompressionMode {
        CompressionMode::None
    }
}

#[tokio::test]
async fn auth_connect_returns_a_session_secret_to_the_authenticated_user() {
    let identity = RsaKeyPair::generate(2048).unwrap();
    let config = TestConfig {
        username: "alice".to_string(),
        private_key_pem: identity.private_key_to_pem().unwrap(),
    };
    let expected = Address::Domain {
        host: "example.com".to_string(),
        port: 443,
    };
    let server_expected = expected.clone();
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = async move {
        let state = Arc::new(CipherState::new());
        let framed = Framed::new(server_io, ProxyCodec::new(state.clone()));
        let (mut writer, mut reader) = framed.split();
        let ProxyRequest::AuthConnect(request) = reader.next().await.unwrap().unwrap() else {
            panic!("expected AuthConnect")
        };
        let transcript = tcp_auth_connect_request_transcript(
            request.version, &request.username, request.timestamp, &request.client_nonce,
        ).unwrap();
        let public =
            RsaKeyPair::from_public_key_pem(&identity.public_key_to_pem().unwrap()).unwrap();
        verify_pss_sha256(&public, &transcript, &request.signature).unwrap();
        let secret = [9; TCP_MASTER_SECRET_LEN];
        let server_nonce = [5; 32];
        let session_id = [6; 16];
        writer
            .send(ProxyResponse::AuthConnect(AuthConnectResponse::success(
                protocol::crypto::encrypt_oaep_sha256_labelled(
                    &public, TCP_AUTH_CONNECT_RESPONSE_OAEP_LABEL, &secret,
                ).unwrap(),
                server_nonce,
                session_id,
            )))
            .await
            .unwrap();
        let cipher = TcpSessionCipher::new(
            TcpSessionRole::Proxy,
            secret,
            tcp_auth_connect_transcript_hash(&transcript),
            request.client_nonce,
            server_nonce,
            session_id,
        )
        .unwrap();
        state.set_session_cipher(Arc::new(cipher)).unwrap();
        let ProxyRequest::AuthConnectIntent(AuthConnectIntent::Connect(intent)) =
            reader.next().await.unwrap().unwrap() else { panic!("expected protected intent") };
        assert_eq!(intent.address, server_expected);
        writer
            .send(ProxyResponse::Connect(ConnectResponse {
                request_id: intent.request_id,
                success: true,
                message: "connected".to_string(),
            }))
            .await
            .unwrap();
    };
    let client = AuthenticatedConnection::establish_target(
        client_io,
        &config,
        expected,
        TransportProtocol::Tcp,
    );
    let (_, result) = tokio::join!(server, client);
    assert!(result.is_ok());
}

#[tokio::test]
async fn terminal_auth_connect_failure_is_reported_to_callers() {
    let identity = RsaKeyPair::generate(2048).unwrap();
    let config = TestConfig {
        username: "alice".to_string(),
        private_key_pem: identity.private_key_to_pem().unwrap(),
    };
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = async move {
        let state = Arc::new(CipherState::new());
        let mut framed = Framed::new(server_io, ProxyCodec::new(state));
        let _ = framed.next().await.unwrap().unwrap();
        framed
            .send(ProxyResponse::AuthConnect(
                AuthConnectResponse::terminal_failure(
                    AuthFailureCode::UserDisabled,
                    "User disabled",
                ),
            ))
            .await
            .unwrap();
    };
    let client = AuthenticatedConnection::establish_target(
        client_io,
        &config,
        Address::Domain {
            host: "example.com".to_string(),
            port: 443,
        },
        TransportProtocol::Tcp,
    );
    let (_, result) = tokio::join!(server, client);
    let error = match result {
        Ok(_) => panic!("terminal failure unexpectedly connected"),
        Err(error) => error,
    };
    assert_eq!(
        auth_failure_code(&error),
        Some(AuthFailureCode::UserDisabled)
    );
}
