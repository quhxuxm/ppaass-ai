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
    /// Stable failure reason. It is trusted only after the Proxy identity
    /// signature has been verified against the current request transcript.
    #[serde(default)]
    pub failure_code: Option<AuthFailureCode>,
    /// OAEP-SHA256 encrypted [`crate::tcp_transport::TcpSessionSecret`].
    /// Empty for an authentication failure.
    pub encrypted_session: Vec<u8>,
    /// RSA-PSS-SHA256 signature by the pinned Proxy transport identity over
    /// the canonical success or failure response transcript. Legacy/hostile
    /// unsigned failures are parseable but never trusted by the client.
    pub proxy_signature: Vec<u8>,
}

impl AuthResponse {
    pub fn success(encrypted_session: Vec<u8>, proxy_signature: Vec<u8>) -> Self {
        Self {
            version: TCP_HANDSHAKE_VERSION,
            success: true,
            message: "Authentication successful".to_string(),
            failure_code: None,
            encrypted_session,
            proxy_signature,
        }
    }

    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            version: TCP_HANDSHAKE_VERSION,
            success: false,
            message: message.into(),
            failure_code: None,
            encrypted_session: Vec::new(),
            proxy_signature: Vec::new(),
        }
    }

    pub fn signed_failure(
        code: AuthFailureCode,
        message: impl Into<String>,
        proxy_signature: Vec<u8>,
    ) -> Self {
        Self {
            version: TCP_HANDSHAKE_VERSION,
            success: false,
            message: message.into(),
            failure_code: Some(code),
            encrypted_session: Vec::new(),
            proxy_signature,
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
                || self.proxy_signature.is_empty()
                || self.proxy_signature.len() > TCP_MAX_RSA_FIELD_LEN
                || self.failure_code.is_some()
            {
                return Err(crate::ProtocolError::InvalidMessage(
                    "invalid successful authentication response fields".to_string(),
                ));
            }
        } else {
            if !self.encrypted_session.is_empty() {
                return Err(crate::ProtocolError::InvalidMessage(
                    "failed authentication response contains an encrypted session".to_string(),
                ));
            }
            if self.proxy_signature.len() > TCP_MAX_RSA_FIELD_LEN {
                return Err(crate::ProtocolError::InvalidMessage(
                    "failed authentication response signature is too long".to_string(),
                ));
            }
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
            .field("proxy_signature", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize)]
    struct LegacyAuthResponseV2 {
        version: u8,
        success: bool,
        message: String,
        encrypted_session: Vec<u8>,
        proxy_signature: Vec<u8>,
    }

    #[test]
    fn signed_and_unsigned_failures_have_safe_shapes() {
        let signed = AuthResponse::signed_failure(
            AuthFailureCode::UserExpired,
            "User expired",
            vec![7_u8; 256],
        );
        signed.validate_shape().unwrap();

        let unsigned = AuthResponse::failure("Authentication failed");
        unsigned.validate_shape().unwrap();
        assert_eq!(unsigned.failure_code, None);
        assert!(unsigned.proxy_signature.is_empty());
    }

    #[test]
    fn successful_response_cannot_carry_a_failure_code() {
        let mut response = AuthResponse::success(vec![1_u8; 256], vec![2_u8; 256]);
        response.failure_code = Some(AuthFailureCode::UserExpired);
        assert!(response.validate_shape().is_err());
    }

    #[test]
    fn serde_default_keeps_code_less_failures_untrusted() {
        let response: AuthResponse = serde_json::from_value(serde_json::json!({
            "version": TCP_HANDSHAKE_VERSION,
            "success": false,
            "message": "legacy failure",
            "encrypted_session": [],
            "proxy_signature": []
        }))
        .unwrap();
        assert_eq!(response.failure_code, None);
        response.validate_shape().unwrap();
    }

    #[test]
    fn bitcode_v2_and_v3_auth_response_schemas_are_not_interchangeable() {
        let legacy = LegacyAuthResponseV2 {
            version: 2,
            success: false,
            message: "User expired".to_string(),
            encrypted_session: Vec::new(),
            proxy_signature: Vec::new(),
        };
        let legacy_encoded = bitcode::serialize(&legacy).unwrap();
        assert!(bitcode::deserialize::<AuthResponse>(&legacy_encoded).is_err());

        let current = AuthResponse::signed_failure(
            AuthFailureCode::UserExpired,
            "User expired",
            vec![3_u8; 256],
        );
        let current_encoded = bitcode::serialize(&current).unwrap();
        assert!(bitcode::deserialize::<LegacyAuthResponseV2>(&current_encoded).is_err());
    }
}
