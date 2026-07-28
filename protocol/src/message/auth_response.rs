use crate::tcp_transport::{TCP_HANDSHAKE_VERSION, TCP_MAX_AUTH_ERROR_LEN, TCP_MAX_RSA_FIELD_LEN};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub version: u8,
    pub success: bool,
    pub message: String,
    /// OAEP-SHA256 encrypted [`crate::tcp_transport::TcpSessionSecret`].
    /// Empty for an authentication failure.
    pub encrypted_session: Vec<u8>,
    /// RSA-PSS-SHA256 signature by the pinned Proxy transport identity over
    /// the canonical success response transcript. Empty for failures.
    pub proxy_signature: Vec<u8>,
}

impl AuthResponse {
    pub fn success(encrypted_session: Vec<u8>, proxy_signature: Vec<u8>) -> Self {
        Self {
            version: TCP_HANDSHAKE_VERSION,
            success: true,
            message: "Authentication successful".to_string(),
            encrypted_session,
            proxy_signature,
        }
    }

    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            version: TCP_HANDSHAKE_VERSION,
            success: false,
            message: message.into(),
            encrypted_session: Vec::new(),
            proxy_signature: Vec::new(),
        }
    }

    pub fn validate_shape(&self) -> crate::Result<()> {
        if self.version != TCP_HANDSHAKE_VERSION {
            return Err(crate::ProtocolError::VersionMismatch);
        }
        if self.message.len() > TCP_MAX_AUTH_ERROR_LEN {
            return Err(crate::ProtocolError::InvalidMessage(
                "authentication response message is too long".to_string(),
            ));
        }
        if self.message.chars().any(char::is_control) {
            return Err(crate::ProtocolError::InvalidMessage(
                "authentication response message contains control characters".to_string(),
            ));
        }
        if self.success {
            if self.encrypted_session.is_empty()
                || self.encrypted_session.len() > TCP_MAX_RSA_FIELD_LEN
                || self.proxy_signature.is_empty()
                || self.proxy_signature.len() > TCP_MAX_RSA_FIELD_LEN
            {
                return Err(crate::ProtocolError::InvalidMessage(
                    "invalid successful authentication response fields".to_string(),
                ));
            }
        } else if !self.encrypted_session.is_empty() || !self.proxy_signature.is_empty() {
            return Err(crate::ProtocolError::InvalidMessage(
                "failed authentication response contains protected fields".to_string(),
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
            .field("encrypted_session", &"[REDACTED]")
            .field("proxy_signature", &"[REDACTED]")
            .finish()
    }
}
