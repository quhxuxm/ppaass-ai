use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::message::PROTOCOL_VERSION;
use crate::{ProtocolError, Result};

pub const TCP_HANDSHAKE_VERSION: u8 = PROTOCOL_VERSION;
pub const TCP_AUTH_NONCE_LEN: usize = 32;
pub const TCP_SERVER_NONCE_LEN: usize = 32;
pub const TCP_MASTER_SECRET_LEN: usize = 32;
pub const TCP_SESSION_ID_LEN: usize = 16;
pub const TCP_MAX_USERNAME_LEN: usize = 256;
pub const TCP_MAX_RSA_FIELD_LEN: usize = 1_024;
pub const TCP_MAX_AUTH_ERROR_LEN: usize = 512;
pub const TCP_SESSION_SECRET_MAX_SIZE: usize = 512;
pub const TCP_OAEP_LABEL: &str = "ppaass/tcp-yamux/auth-response/v4";

const AUTH_REQUEST_DOMAIN: &[u8] = b"ppaass/tcp-yamux/auth-request/v4\0";
const AUTH_REPLAY_KEY_DOMAIN: &[u8] = b"ppaass/tcp-yamux/auth-replay-key/v4\0";
const AUTH_REPLAY_USER_DOMAIN: &[u8] = b"ppaass/tcp-yamux/auth-replay-user/v4\0";

/// Stable, machine-readable reason carried by a failed TCP authentication response.
///
/// The Proxy only returns terminal account state after validating the Agent's
/// fresh, non-replayed authentication proof.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum AuthFailureCode {
    UserExpired = 1,
    UserDisabled = 2,
    #[default]
    Other = 255,
}

/// Secret response encrypted to the authenticated user's public key.
///
/// `auth_transcript_hash` binds version, username, timestamp and client nonce.
/// The client must recompute and compare it, as well as the explicit client
/// nonce, before accepting any key material.
#[derive(Clone, Serialize, Deserialize)]
pub struct TcpSessionSecret {
    pub version: u8,
    pub auth_transcript_hash: [u8; 32],
    pub client_nonce: [u8; TCP_AUTH_NONCE_LEN],
    pub server_nonce: [u8; TCP_SERVER_NONCE_LEN],
    pub session_id: [u8; TCP_SESSION_ID_LEN],
    pub master_secret: [u8; TCP_MASTER_SECRET_LEN],
}

impl std::fmt::Debug for TcpSessionSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TcpSessionSecret")
            .field("version", &self.version)
            .field("auth_transcript_hash", &self.auth_transcript_hash)
            .field("client_nonce", &self.client_nonce)
            .field("server_nonce", &self.server_nonce)
            .field("session_id", &self.session_id)
            .field("master_secret", &"[REDACTED]")
            .finish()
    }
}

impl TcpSessionSecret {
    pub fn validate_handshake_context(
        &self,
        expected_transcript_hash: &[u8; 32],
        expected_client_nonce: &[u8; TCP_AUTH_NONCE_LEN],
    ) -> Result<()> {
        if self.version != TCP_HANDSHAKE_VERSION
            || self.auth_transcript_hash != *expected_transcript_hash
            || self.client_nonce != *expected_client_nonce
        {
            return Err(ProtocolError::AuthenticationFailed(
                "authentication response context mismatch".to_string(),
            ));
        }
        Ok(())
    }
}

pub fn validate_tcp_username(username: &str) -> Result<()> {
    if username.is_empty() || username.len() > TCP_MAX_USERNAME_LEN {
        return Err(ProtocolError::InvalidMessage(
            "invalid authentication username length".to_string(),
        ));
    }
    if username.chars().any(char::is_control) {
        return Err(ProtocolError::InvalidMessage(
            "authentication username contains control characters".to_string(),
        ));
    }
    Ok(())
}

/// Canonical, length-delimited, domain-separated transcript signed by the
/// agent. There is no legacy transcript parser.
pub fn tcp_auth_request_transcript(
    version: u8,
    username: &str,
    timestamp: i64,
    client_nonce: &[u8; TCP_AUTH_NONCE_LEN],
) -> Result<Vec<u8>> {
    if version != TCP_HANDSHAKE_VERSION {
        return Err(ProtocolError::VersionMismatch);
    }
    validate_tcp_username(username)?;
    let username_len = u16::try_from(username.len()).map_err(|_| {
        ProtocolError::InvalidMessage("authentication username is too long".to_string())
    })?;
    let mut transcript =
        Vec::with_capacity(AUTH_REQUEST_DOMAIN.len() + 1 + 2 + username.len() + 8 + 32);
    transcript.extend_from_slice(AUTH_REQUEST_DOMAIN);
    transcript.push(version);
    transcript.extend_from_slice(&username_len.to_be_bytes());
    transcript.extend_from_slice(username.as_bytes());
    transcript.extend_from_slice(&timestamp.to_be_bytes());
    transcript.extend_from_slice(client_nonce);
    Ok(transcript)
}

pub fn tcp_auth_transcript_hash(transcript: &[u8]) -> [u8; 32] {
    Sha256::digest(transcript).into()
}

pub fn tcp_auth_replay_key(
    username: &str,
    client_nonce: &[u8; TCP_AUTH_NONCE_LEN],
) -> Result<[u8; 32]> {
    validate_tcp_username(username)?;
    let mut hasher = Sha256::new();
    hasher.update(AUTH_REPLAY_KEY_DOMAIN);
    hasher.update((username.len() as u16).to_be_bytes());
    hasher.update(username.as_bytes());
    hasher.update(client_nonce);
    Ok(hasher.finalize().into())
}

pub fn tcp_auth_replay_user_key(username: &str) -> Result<[u8; 32]> {
    validate_tcp_username(username)?;
    let mut hasher = Sha256::new();
    hasher.update(AUTH_REPLAY_USER_DOMAIN);
    hasher.update((username.len() as u16).to_be_bytes());
    hasher.update(username.as_bytes());
    Ok(hasher.finalize().into())
}

pub(crate) fn validate_tcp_auth_response_message(message: &str) -> Result<()> {
    if message.len() > TCP_MAX_AUTH_ERROR_LEN {
        return Err(ProtocolError::InvalidMessage(
            "authentication response message is too long".to_string(),
        ));
    }
    if message.chars().any(char::is_control) {
        return Err(ProtocolError::InvalidMessage(
            "authentication response message contains control characters".to_string(),
        ));
    }
    Ok(())
}

pub fn encode_tcp_session_secret(secret: &TcpSessionSecret) -> Result<Vec<u8>> {
    if secret.version != TCP_HANDSHAKE_VERSION {
        return Err(ProtocolError::VersionMismatch);
    }
    let encoded = bitcode::serialize(secret)?;
    if encoded.len() > TCP_SESSION_SECRET_MAX_SIZE {
        return Err(ProtocolError::MessageTooLarge(encoded.len()));
    }
    Ok(encoded)
}

pub fn decode_tcp_session_secret(bytes: &[u8]) -> Result<TcpSessionSecret> {
    if bytes.len() > TCP_SESSION_SECRET_MAX_SIZE {
        return Err(ProtocolError::MessageTooLarge(bytes.len()));
    }
    let secret: TcpSessionSecret = bitcode::deserialize(bytes)?;
    if secret.version != TCP_HANDSHAKE_VERSION {
        return Err(ProtocolError::VersionMismatch);
    }
    Ok(secret)
}
