use crate::tcp_transport::{
    AuthFailureCode, TCP_AUTH_CONNECT_INTENT_NONCE_LEN, TCP_AUTH_NONCE_LEN, TCP_HANDSHAKE_VERSION,
    TCP_MAX_RSA_FIELD_LEN, TCP_SERVER_NONCE_LEN, TCP_SESSION_ID_LEN,
    validate_tcp_auth_response_message, validate_tcp_username,
};
use serde::{Deserialize, Serialize};

use super::{ConnectRequest, SpeedTestRequest};

/// The first and only client-to-proxy control request for a TCP/Yamux stream.
///
/// `encrypted_request_secret` is RSA-OAEP encrypted to the Proxy's pinned
/// encryption key. `encrypted_intent` holds the target operation under a key
/// derived from that per-request secret; the signature binds every field.
#[derive(Clone, Serialize, Deserialize)]
pub struct AuthConnectRequest {
    pub version: u8,
    pub username: String,
    pub timestamp: i64,
    pub client_nonce: [u8; TCP_AUTH_NONCE_LEN],
    pub encrypted_request_secret: Vec<u8>,
    pub intent_nonce: [u8; TCP_AUTH_CONNECT_INTENT_NONCE_LEN],
    pub encrypted_intent: Vec<u8>,
    pub signature: Vec<u8>,
}

impl AuthConnectRequest {
    pub fn validate_shape(&self) -> crate::Result<()> {
        if self.version != TCP_HANDSHAKE_VERSION {
            return Err(crate::ProtocolError::VersionMismatch);
        }
        validate_tcp_username(&self.username)?;
        if self.encrypted_request_secret.is_empty()
            || self.encrypted_request_secret.len() > TCP_MAX_RSA_FIELD_LEN
            || self.encrypted_intent.len() < 16
            || self.signature.is_empty()
            || self.signature.len() > TCP_MAX_RSA_FIELD_LEN
        {
            return Err(crate::ProtocolError::InvalidMessage(
                "invalid auth-connect request field length".to_string(),
            ));
        }
        Ok(())
    }
}

impl std::fmt::Debug for AuthConnectRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthConnectRequest")
            .field("version", &self.version)
            .field("username", &self.username)
            .field("timestamp", &self.timestamp)
            .field("client_nonce", &self.client_nonce)
            .field("encrypted_request_secret", &"[REDACTED]")
            .field("intent_nonce", &self.intent_nonce)
            .field("encrypted_intent", &"[REDACTED]")
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthConnectIntent {
    Connect(ConnectRequest),
    SpeedTest(SpeedTestRequest),
}

/// Cleartext bootstrap response. The following ConnectResponse/Data records
/// are protected with the keys derived from `request_secret` and these values.
#[derive(Clone, Serialize, Deserialize)]
pub struct AuthConnectResponse {
    pub version: u8,
    pub success: bool,
    pub message: String,
    #[serde(default)]
    pub failure_code: Option<AuthFailureCode>,
    pub server_nonce: [u8; TCP_SERVER_NONCE_LEN],
    pub session_id: [u8; TCP_SESSION_ID_LEN],
}

impl AuthConnectResponse {
    pub fn success(
        server_nonce: [u8; TCP_SERVER_NONCE_LEN],
        session_id: [u8; TCP_SESSION_ID_LEN],
    ) -> Self {
        Self {
            version: TCP_HANDSHAKE_VERSION,
            success: true,
            message: "Authentication successful".to_string(),
            failure_code: None,
            server_nonce,
            session_id,
        }
    }

    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            version: TCP_HANDSHAKE_VERSION,
            success: false,
            message: message.into(),
            failure_code: None,
            server_nonce: [0; TCP_SERVER_NONCE_LEN],
            session_id: [0; TCP_SESSION_ID_LEN],
        }
    }

    pub fn terminal_failure(code: AuthFailureCode, message: impl Into<String>) -> Self {
        Self {
            failure_code: Some(code),
            ..Self::failure(message)
        }
    }

    pub fn validate_shape(&self) -> crate::Result<()> {
        if self.version != TCP_HANDSHAKE_VERSION {
            return Err(crate::ProtocolError::VersionMismatch);
        }
        validate_tcp_auth_response_message(&self.message)?;
        if self.success {
            if self.failure_code.is_some()
                || self.server_nonce == [0; TCP_SERVER_NONCE_LEN]
                || self.session_id == [0; TCP_SESSION_ID_LEN]
            {
                return Err(crate::ProtocolError::InvalidMessage(
                    "invalid successful auth-connect response fields".to_string(),
                ));
            }
        } else if self.server_nonce != [0; TCP_SERVER_NONCE_LEN]
            || self.session_id != [0; TCP_SESSION_ID_LEN]
        {
            return Err(crate::ProtocolError::InvalidMessage(
                "failed auth-connect response contains session material".to_string(),
            ));
        }
        Ok(())
    }
}

impl std::fmt::Debug for AuthConnectResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthConnectResponse")
            .field("version", &self.version)
            .field("success", &self.success)
            .field("message", &self.message)
            .field("failure_code", &self.failure_code)
            .field("server_nonce", &self.server_nonce)
            .field("session_id", &self.session_id)
            .finish()
    }
}
