use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::message::PROTOCOL_VERSION;
use crate::{ProtocolError, Result};

pub const TCP_HANDSHAKE_VERSION: u8 = PROTOCOL_VERSION;
pub const TCP_AUTH_NONCE_LEN: usize = 32;
pub const TCP_AUTH_CONNECT_INTENT_NONCE_LEN: usize = 12;
pub const TCP_SERVER_NONCE_LEN: usize = 32;
pub const TCP_MASTER_SECRET_LEN: usize = 32;
pub const TCP_SESSION_ID_LEN: usize = 16;
pub const TCP_MAX_USERNAME_LEN: usize = 256;
pub const TCP_MAX_RSA_FIELD_LEN: usize = 1_024;
pub const TCP_MAX_AUTH_ERROR_LEN: usize = 512;
pub const TCP_AUTH_CONNECT_OAEP_LABEL: &str = "ppaass/tcp-yamux/auth-connect/request-secret/v6";

const AUTH_CONNECT_REQUEST_DOMAIN: &[u8] = b"ppaass/tcp-yamux/auth-connect/request/v6\0";
const AUTH_CONNECT_INTENT_AAD_DOMAIN: &[u8] = b"ppaass/tcp-yamux/auth-connect/intent/v6\0";
const AUTH_REPLAY_KEY_DOMAIN: &[u8] = b"ppaass/tcp-yamux/auth-replay-key/v6\0";
const AUTH_REPLAY_USER_DOMAIN: &[u8] = b"ppaass/tcp-yamux/auth-replay-user/v6\0";

/// Stable, machine-readable reason returned after a valid fresh Agent proof.
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

/// AEAD additional authenticated data for the encrypted target intent.
/// The signature later covers this AAD plus the ciphertext itself.
pub fn tcp_auth_connect_intent_aad(
    version: u8,
    username: &str,
    timestamp: i64,
    client_nonce: &[u8; TCP_AUTH_NONCE_LEN],
    encrypted_request_secret: &[u8],
    intent_nonce: &[u8; TCP_AUTH_CONNECT_INTENT_NONCE_LEN],
) -> Result<Vec<u8>> {
    if version != TCP_HANDSHAKE_VERSION {
        return Err(ProtocolError::VersionMismatch);
    }
    validate_tcp_username(username)?;
    let username_len = u16::try_from(username.len()).map_err(|_| {
        ProtocolError::InvalidMessage("authentication username is too long".to_string())
    })?;
    let secret_len = u16::try_from(encrypted_request_secret.len()).map_err(|_| {
        ProtocolError::InvalidMessage("encrypted request secret is too long".to_string())
    })?;
    let mut aad = Vec::with_capacity(
        AUTH_CONNECT_INTENT_AAD_DOMAIN.len()
            + 1
            + 2
            + username.len()
            + 8
            + TCP_AUTH_NONCE_LEN
            + 2
            + encrypted_request_secret.len()
            + TCP_AUTH_CONNECT_INTENT_NONCE_LEN,
    );
    aad.extend_from_slice(AUTH_CONNECT_INTENT_AAD_DOMAIN);
    aad.push(version);
    aad.extend_from_slice(&username_len.to_be_bytes());
    aad.extend_from_slice(username.as_bytes());
    aad.extend_from_slice(&timestamp.to_be_bytes());
    aad.extend_from_slice(client_nonce);
    aad.extend_from_slice(&secret_len.to_be_bytes());
    aad.extend_from_slice(encrypted_request_secret);
    aad.extend_from_slice(intent_nonce);
    Ok(aad)
}

/// Canonical signature input. It commits to every authentication and encrypted
/// target-intent field without parsing attacker controlled bitcode first.
pub fn tcp_auth_connect_request_transcript(
    intent_aad: &[u8],
    encrypted_intent: &[u8],
) -> Result<Vec<u8>> {
    let intent_len = u32::try_from(encrypted_intent.len()).map_err(|_| {
        ProtocolError::InvalidMessage("encrypted target intent is too long".to_string())
    })?;
    let mut transcript = Vec::with_capacity(
        AUTH_CONNECT_REQUEST_DOMAIN.len() + intent_aad.len() + 4 + encrypted_intent.len(),
    );
    transcript.extend_from_slice(AUTH_CONNECT_REQUEST_DOMAIN);
    transcript.extend_from_slice(intent_aad);
    transcript.extend_from_slice(&intent_len.to_be_bytes());
    transcript.extend_from_slice(encrypted_intent);
    Ok(transcript)
}

pub fn tcp_auth_connect_transcript_hash(transcript: &[u8]) -> [u8; 32] {
    Sha256::digest(transcript).into()
}

pub fn seal_auth_connect_intent(
    request_secret: &[u8; TCP_MASTER_SECRET_LEN],
    intent_nonce: &[u8; TCP_AUTH_CONNECT_INTENT_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let key = UnboundKey::new(&aead::AES_256_GCM, request_secret)
        .map_err(|_| ProtocolError::InvalidKey("invalid auth-connect key".to_string()))?;
    let mut ciphertext = plaintext.to_vec();
    LessSafeKey::new(key)
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(*intent_nonce),
            Aad::from(aad),
            &mut ciphertext,
        )
        .map_err(|_| {
            ProtocolError::Encryption("auth-connect intent encryption failed".to_string())
        })?;
    Ok(ciphertext)
}

pub fn open_auth_connect_intent(
    request_secret: &[u8; TCP_MASTER_SECRET_LEN],
    intent_nonce: &[u8; TCP_AUTH_CONNECT_INTENT_NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let key = UnboundKey::new(&aead::AES_256_GCM, request_secret)
        .map_err(|_| ProtocolError::InvalidKey("invalid auth-connect key".to_string()))?;
    let mut plaintext = ciphertext.to_vec();
    let plaintext_len = LessSafeKey::new(key)
        .open_in_place(
            Nonce::assume_unique_for_key(*intent_nonce),
            Aad::from(aad),
            &mut plaintext,
        )
        .map_err(|_| {
            ProtocolError::AuthenticationFailed(
                "auth-connect intent authentication failed".to_string(),
            )
        })?
        .len();
    plaintext.truncate(plaintext_len);
    Ok(plaintext)
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
