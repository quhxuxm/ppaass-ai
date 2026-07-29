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
pub const TCP_OAEP_LABEL: &str = "ppaass/tcp-yamux/auth-response/v3";

const AUTH_REQUEST_DOMAIN: &[u8] = b"ppaass/tcp-yamux/auth-request/v3\0";
const AUTH_RESPONSE_DOMAIN: &[u8] = b"ppaass/tcp-yamux/auth-response-signature/v3\0";
const AUTH_REPLAY_KEY_DOMAIN: &[u8] = b"ppaass/tcp-yamux/auth-replay-key/v3\0";
const AUTH_REPLAY_USER_DOMAIN: &[u8] = b"ppaass/tcp-yamux/auth-replay-user/v3\0";

/// Stable, machine-readable reason carried by a failed TCP authentication response.
///
/// A client must only act on this value after verifying the accompanying Proxy
/// transport-identity signature. An unsigned or invalidly signed value is
/// untrusted input and must not be treated as an account state transition.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum AuthFailureCode {
    UserExpired = 1,
    UserDisabled = 2,
    #[default]
    Other = 255,
}

impl AuthFailureCode {
    fn transcript_value(self) -> u8 {
        self as u8
    }
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

/// Canonical transcript signed by the Proxy transport identity.
///
/// The signature is checked with a pinned public key before the client performs
/// OAEP decryption. The ciphertext itself carries and cryptographically binds
/// the client nonce, server nonce, session id and master secret.
pub fn tcp_auth_response_signature_transcript(
    version: u8,
    auth_transcript_hash: &[u8; 32],
    encrypted_session: &[u8],
) -> Result<Vec<u8>> {
    if version != TCP_HANDSHAKE_VERSION {
        return Err(ProtocolError::VersionMismatch);
    }
    if encrypted_session.is_empty() || encrypted_session.len() > TCP_MAX_RSA_FIELD_LEN {
        return Err(ProtocolError::InvalidMessage(
            "invalid encrypted authentication response length".to_string(),
        ));
    }
    let ciphertext_len = u32::try_from(encrypted_session.len()).map_err(|_| {
        ProtocolError::InvalidMessage("encrypted authentication response is too long".to_string())
    })?;
    let mut transcript =
        Vec::with_capacity(AUTH_RESPONSE_DOMAIN.len() + 1 + 1 + 32 + 4 + encrypted_session.len());
    transcript.extend_from_slice(AUTH_RESPONSE_DOMAIN);
    transcript.push(version);
    // Only successful responses are signed. This byte prevents a future
    // extension from reinterpreting the same signature as a failure response.
    transcript.push(1);
    transcript.extend_from_slice(auth_transcript_hash);
    transcript.extend_from_slice(&ciphertext_len.to_be_bytes());
    transcript.extend_from_slice(encrypted_session);
    Ok(transcript)
}

/// Canonical transcript signed by the Proxy transport identity for a failed
/// authentication response.
///
/// The request transcript hash prevents replaying a genuine terminal account
/// status into another Agent login attempt. The stable failure code and the
/// human-readable message are both covered by the signature.
pub fn tcp_auth_failure_signature_transcript(
    version: u8,
    auth_transcript_hash: &[u8; 32],
    code: AuthFailureCode,
    message: &str,
) -> Result<Vec<u8>> {
    if version != TCP_HANDSHAKE_VERSION {
        return Err(ProtocolError::VersionMismatch);
    }
    validate_tcp_auth_response_message(message)?;
    let message_len = u16::try_from(message.len()).map_err(|_| {
        ProtocolError::InvalidMessage("authentication response message is too long".to_string())
    })?;
    let mut transcript =
        Vec::with_capacity(AUTH_RESPONSE_DOMAIN.len() + 1 + 1 + 32 + 1 + 2 + message.len());
    transcript.extend_from_slice(AUTH_RESPONSE_DOMAIN);
    transcript.push(version);
    // Success signatures use 1. Keeping the discriminator in the shared
    // domain makes the two transcript forms impossible to reinterpret.
    transcript.push(0);
    transcript.extend_from_slice(auth_transcript_hash);
    transcript.push(code.transcript_value());
    transcript.extend_from_slice(&message_len.to_be_bytes());
    transcript.extend_from_slice(message.as_bytes());
    Ok(transcript)
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

#[cfg(test)]
mod tests;
