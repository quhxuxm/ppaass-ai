use crate::tcp_transport::{
    TCP_AUTH_NONCE_LEN, TCP_HANDSHAKE_VERSION, TCP_MAX_RSA_FIELD_LEN, validate_tcp_username,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub version: u8,
    pub username: String,
    pub timestamp: i64,
    pub client_nonce: [u8; TCP_AUTH_NONCE_LEN],
    pub signature: Vec<u8>,
}

impl AuthRequest {
    pub fn validate_shape(&self) -> crate::Result<()> {
        if self.version != TCP_HANDSHAKE_VERSION {
            return Err(crate::ProtocolError::VersionMismatch);
        }
        validate_tcp_username(&self.username)?;
        if self.signature.is_empty() || self.signature.len() > TCP_MAX_RSA_FIELD_LEN {
            return Err(crate::ProtocolError::InvalidMessage(
                "invalid authentication signature length".to_string(),
            ));
        }
        Ok(())
    }
}

impl std::fmt::Debug for AuthRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthRequest")
            .field("version", &self.version)
            .field("username", &self.username)
            .field("timestamp", &self.timestamp)
            .field("client_nonce", &self.client_nonce)
            .field("signature", &"[REDACTED]")
            .finish()
    }
}
