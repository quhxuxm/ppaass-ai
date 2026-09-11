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
pub const TCP_AUTH_CONNECT_RESPONSE_OAEP_LABEL: &str =
    "ppaass/tcp-yamux/auth-connect/session-secret/v7";

const AUTH_CONNECT_REQUEST_DOMAIN: &[u8] = b"ppaass/tcp-yamux/auth-connect/request/v7\0";
const AUTH_REPLAY_KEY_DOMAIN: &[u8] = b"ppaass/tcp-yamux/auth-replay-key/v7\0";
const AUTH_REPLAY_USER_DOMAIN: &[u8] = b"ppaass/tcp-yamux/auth-replay-user/v7\0";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum AuthFailureCode {
    UserExpired = 1,
    UserDisabled = 2,
    #[default]
    Other = 255,
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

/// Canonical signature input. The username is deliberately cleartext so the
/// Entry can select the user's registered public key before verification.
pub fn tcp_auth_connect_request_transcript(
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
    let mut transcript = Vec::with_capacity(
        AUTH_CONNECT_REQUEST_DOMAIN.len() + 1 + 2 + username.len() + 8 + TCP_AUTH_NONCE_LEN,
    );
    transcript.extend_from_slice(AUTH_CONNECT_REQUEST_DOMAIN);
    transcript.push(version);
    transcript.extend_from_slice(&username_len.to_be_bytes());
    transcript.extend_from_slice(username.as_bytes());
    transcript.extend_from_slice(&timestamp.to_be_bytes());
    transcript.extend_from_slice(client_nonce);
    Ok(transcript)
}

pub fn tcp_auth_connect_transcript_hash(transcript: &[u8]) -> [u8; 32] {
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
    if message.len() > TCP_MAX_AUTH_ERROR_LEN || message.chars().any(char::is_control) {
        return Err(ProtocolError::InvalidMessage(
            "invalid authentication response message".to_string(),
        ));
    }
    Ok(())
}
