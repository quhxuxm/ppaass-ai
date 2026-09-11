//! AuthConnect handshake and initial-operation dispatch.
//!
//! The Agent proves its identity with RSA-PSS, sends a per-request secret
//! wrapped to the Proxy RSA key, and carries the target intent only as AEAD
//! ciphertext. No post-auth ConnectRequest is accepted by protocol v6.

use super::*;
use protocol::crypto::{parse_public_key_pem_cached, verify_pss_sha256};
use protocol::tcp_transport::{
    TCP_AUTH_CONNECT_OAEP_LABEL, TCP_HANDSHAKE_VERSION, TCP_MASTER_SECRET_LEN,
    TCP_SERVER_NONCE_LEN, TCP_SESSION_ID_LEN, TcpSessionCipher, TcpSessionRole,
    open_auth_connect_intent, tcp_auth_connect_intent_aad, tcp_auth_connect_request_transcript,
    tcp_auth_connect_transcript_hash,
};
use protocol::{AuthConnectResponse, ProxyRequest, ProxyResponse};
use rand::Rng;

pub const GENERIC_AUTH_FAILURE_MESSAGE: &str = "Authentication failed";

pub fn terminal_auth_failure_response(
    code: AuthFailureCode,
    message: &str,
) -> Result<AuthConnectResponse> {
    if !matches!(
        code,
        AuthFailureCode::UserDisabled | AuthFailureCode::UserExpired
    ) {
        return Err(ProxyError::Authentication(
            "Refusing to expose a non-terminal authentication failure".to_string(),
        ));
    }
    let response = AuthConnectResponse::terminal_failure(code, message);
    response.validate_shape()?;
    Ok(response)
}

impl ServerConnection {
    pub(super) async fn read_request(&mut self) -> Result<Option<ProxyRequest>> {
        match self.reader.next().await {
            Some(Ok(request)) => Ok(Some(request)),
            Some(Err(error)) => Err(ProxyError::Protocol(protocol::ProtocolError::Io(error))),
            None => Ok(None),
        }
    }

    /// Read the cleartext bootstrap frame only far enough to find its user.
    #[instrument(skip(self))]
    pub async fn peek_auth_username(&mut self) -> Result<String> {
        let request = self
            .read_request()
            .await?
            .ok_or_else(|| ProxyError::Connection("Connection closed".to_string()))?;
        let ProxyRequest::AuthConnect(request) = request else {
            return Err(ProxyError::Authentication(
                "Expected AuthConnect request".to_string(),
            ));
        };
        request
            .validate_shape()
            .map_err(|_| ProxyError::Authentication("Invalid AuthConnect request".to_string()))?;
        let username = request.username.clone();
        self.pending_auth_connect = Some(request);
        Ok(username)
    }

    pub async fn send_auth_error(&mut self) -> Result<()> {
        self.send_response(ProxyResponse::AuthConnect(AuthConnectResponse::failure(
            GENERIC_AUTH_FAILURE_MESSAGE,
        )))
        .await
    }

    async fn reject_authentication(&mut self, detail: &str) -> Result<()> {
        self.send_auth_error().await?;
        Err(ProxyError::Authentication(detail.to_string()))
    }

    async fn send_terminal_auth_error(
        &mut self,
        code: AuthFailureCode,
        message: &str,
    ) -> Result<()> {
        self.send_response(ProxyResponse::AuthConnect(terminal_auth_failure_response(
            code, message,
        )?))
        .await
    }

    #[instrument(skip(self, proxy_config, user_config))]
    pub async fn authenticate(
        &mut self,
        proxy_config: &ProxyConfig,
        user_config: UserConfig,
    ) -> Result<()> {
        let request = self.pending_auth_connect.take().ok_or_else(|| {
            ProxyError::Authentication("No pending AuthConnect request".to_string())
        })?;
        request
            .validate_shape()
            .map_err(|_| ProxyError::Authentication("Invalid AuthConnect request".to_string()))?;
        let intent_aad = tcp_auth_connect_intent_aad(
            request.version,
            &request.username,
            request.timestamp,
            &request.client_nonce,
            &request.encrypted_request_secret,
            &request.intent_nonce,
        )
        .map_err(|_| ProxyError::Authentication("Invalid AuthConnect request".to_string()))?;
        let transcript =
            tcp_auth_connect_request_transcript(&intent_aad, &request.encrypted_intent).map_err(
                |_| ProxyError::Authentication("Invalid AuthConnect request".to_string()),
            )?;
        let transcript_hash = tcp_auth_connect_transcript_hash(&transcript);

        if request.username != user_config.username {
            self.send_auth_error().await?;
            return Err(ProxyError::Authentication("Username mismatch".to_string()));
        }
        let current_time = common::current_timestamp();
        let replay_tolerance = proxy_config.replay_attack_tolerance.max(0) as u64;
        if current_time.abs_diff(request.timestamp) > replay_tolerance {
            self.send_auth_error().await?;
            return Err(ProxyError::Authentication("Timestamp expired".to_string()));
        }
        let user_public_key = match parse_public_key_pem_cached(&user_config.public_key_pem) {
            Ok(key) => key,
            Err(error) => {
                self.send_auth_error().await?;
                return Err(ProxyError::Authentication(format!(
                    "Invalid public key: {error}"
                )));
            }
        };
        if verify_pss_sha256(&user_public_key, &transcript, &request.signature).is_err() {
            self.send_auth_error().await?;
            return Err(ProxyError::Authentication(
                "Invalid authentication proof".to_string(),
            ));
        }
        let valid_until = request
            .timestamp
            .saturating_add(proxy_config.replay_attack_tolerance.max(0));
        if !self.user_manager.claim_tcp_auth_nonce(
            &request.username,
            request.client_nonce,
            current_time,
            valid_until,
        ) {
            self.send_auth_error().await?;
            return Err(ProxyError::Authentication(
                "Authentication request replayed".to_string(),
            ));
        }
        if !user_config.enabled {
            self.send_terminal_auth_error(AuthFailureCode::UserDisabled, "User disabled")
                .await?;
            return Err(ProxyError::Authentication("User disabled".to_string()));
        }
        if user_config.is_expired_at(current_time)? {
            self.send_terminal_auth_error(AuthFailureCode::UserExpired, "User expired")
                .await?;
            return Err(ProxyError::Authentication("User expired".to_string()));
        }

        let request_secret = match self.auth_connect_key.decrypt_oaep_sha256_labelled(
            TCP_AUTH_CONNECT_OAEP_LABEL,
            &request.encrypted_request_secret,
        ) {
            Ok(secret) => secret,
            Err(_) => {
                return self
                    .reject_authentication("Invalid AuthConnect secret")
                    .await;
            }
        };
        let request_secret: [u8; TCP_MASTER_SECRET_LEN] = match request_secret.try_into() {
            Ok(secret) => secret,
            Err(_) => {
                return self
                    .reject_authentication("Invalid AuthConnect secret length")
                    .await;
            }
        };
        let encoded_intent = match open_auth_connect_intent(
            &request_secret,
            &request.intent_nonce,
            &intent_aad,
            &request.encrypted_intent,
        ) {
            Ok(intent) => intent,
            Err(_) => {
                return self
                    .reject_authentication("Invalid encrypted target intent")
                    .await;
            }
        };
        let initial_intent: AuthConnectIntent = match bitcode::deserialize(&encoded_intent) {
            Ok(intent) => intent,
            Err(_) => {
                return self
                    .reject_authentication("Invalid encrypted target intent")
                    .await;
            }
        };

        let mut server_nonce = [0_u8; TCP_SERVER_NONCE_LEN];
        let mut session_id = [0_u8; TCP_SESSION_ID_LEN];
        rand::rng().fill_bytes(&mut server_nonce);
        rand::rng().fill_bytes(&mut session_id);
        let session_cipher = TcpSessionCipher::new(
            TcpSessionRole::Proxy,
            request_secret,
            transcript_hash,
            request.client_nonce,
            server_nonce,
            session_id,
        )
        .map_err(|_| {
            ProxyError::Authentication("Failed to initialize session protection".to_string())
        })?;
        let authorization = ConnectionAuthorization::new(self.user_manager.clone(), &user_config)?;

        self.send_response(ProxyResponse::AuthConnect(AuthConnectResponse::success(
            server_nonce,
            session_id,
        )))
        .await?;
        self.cipher_state
            .set_session_cipher(Arc::new(session_cipher))?;
        self.user_config = Some(user_config);
        self.authorization = Some(authorization);
        self.pending_initial_intent = Some(initial_intent);
        debug!(version = TCP_HANDSHAKE_VERSION, "AuthConnect 认证成功");
        Ok(())
    }

    pub(super) async fn send_response(&mut self, response: ProxyResponse) -> Result<()> {
        self.writer
            .send(response)
            .await
            .map_err(|error| ProxyError::Connection(format!("Failed to send response: {error}")))
    }

    pub async fn handle_initial_intent(&mut self) -> Result<()> {
        let intent = self.pending_initial_intent.take().ok_or_else(|| {
            ProxyError::Authentication(
                "Authenticated stream is missing its initial intent".to_string(),
            )
        })?;
        match intent {
            AuthConnectIntent::Connect(request) => self.handle_connect(request).await,
            AuthConnectIntent::SpeedTest(request) => self.handle_speed_test(request).await,
        }
    }
}
