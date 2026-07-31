use crate::tcp_transport::{
    AuthFailureCode, TCP_HANDSHAKE_VERSION, TCP_MAX_RSA_FIELD_LEN,
    validate_tcp_auth_response_message,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub version: u8,
    pub success: bool,
    pub message: String,
    /// Stable failure reason returned after the Agent proof has been checked.
    #[serde(default)]
    pub failure_code: Option<AuthFailureCode>,
    /// OAEP-SHA256 encrypted [`crate::tcp_transport::TcpSessionSecret`].
    /// Empty for an authentication failure.
    pub encrypted_session: Vec<u8>,
}

impl AuthResponse {
    pub fn success(encrypted_session: Vec<u8>) -> Self {
        Self {
            version: TCP_HANDSHAKE_VERSION,
            success: true,
            message: "Authentication successful".to_string(),
            failure_code: None,
            encrypted_session,
        }
    }

    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            version: TCP_HANDSHAKE_VERSION,
            success: false,
            message: message.into(),
            failure_code: None,
            encrypted_session: Vec::new(),
        }
    }

    pub fn terminal_failure(code: AuthFailureCode, message: impl Into<String>) -> Self {
        Self {
            version: TCP_HANDSHAKE_VERSION,
            success: false,
            message: message.into(),
            failure_code: Some(code),
            encrypted_session: Vec::new(),
        }
    }

    pub fn validate_shape(&self) -> crate::Result<()> {
        if self.version != TCP_HANDSHAKE_VERSION {
            return Err(crate::ProtocolError::VersionMismatch);
        }
        validate_tcp_auth_response_message(&self.message)?;
        if self.success {
            if self.encrypted_session.is_empty()
                || self.encrypted_session.len() > TCP_MAX_RSA_FIELD_LEN
                || self.failure_code.is_some()
            {
                return Err(crate::ProtocolError::InvalidMessage(
                    "invalid successful authentication response fields".to_string(),
                ));
            }
        } else if !self.encrypted_session.is_empty() {
            return Err(crate::ProtocolError::InvalidMessage(
                "failed authentication response contains an encrypted session".to_string(),
            ));
        }
        Ok(())
    }
}

impl std::fmt::Debug for AuthResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthResponse")
            .field("version", &self.version)
            .field("success", &self.success)
            .field("message", &self.message)
            .field("failure_code", &self.failure_code)
            .field("encrypted_session", &"[REDACTED]")
            .finish()
    }
}
