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
mod tests {
    use super::*;
    use crate::MessageType;
    use crate::crypto::{RsaKeyPair, encrypt_oaep_sha256_labelled, verify_pss_sha256};
    use crate::tcp_transport::{TcpSessionCipher, TcpSessionRole};

    #[test]
    fn transcript_signature_binds_every_client_context_field() {
        let key_pair = RsaKeyPair::generate(2048).unwrap();
        let public_key =
            RsaKeyPair::from_public_key_pem(&key_pair.public_key_to_pem().unwrap()).unwrap();
        let nonce = [7_u8; TCP_AUTH_NONCE_LEN];
        let transcript =
            tcp_auth_request_transcript(TCP_HANDSHAKE_VERSION, "alice", 1234, &nonce).unwrap();
        let signature = key_pair.sign_pss_sha256(&transcript).unwrap();
        verify_pss_sha256(&public_key, &transcript, &signature).unwrap();

        let mut changed_nonce = nonce;
        changed_nonce[0] ^= 1;
        for changed in [
            tcp_auth_request_transcript(TCP_HANDSHAKE_VERSION, "mallory", 1234, &nonce).unwrap(),
            tcp_auth_request_transcript(TCP_HANDSHAKE_VERSION, "alice", 1235, &nonce).unwrap(),
            tcp_auth_request_transcript(TCP_HANDSHAKE_VERSION, "alice", 1234, &changed_nonce)
                .unwrap(),
        ] {
            assert!(verify_pss_sha256(&public_key, &changed, &signature).is_err());
        }
        assert!(
            tcp_auth_request_transcript(TCP_HANDSHAKE_VERSION - 1, "alice", 1234, &nonce).is_err()
        );
    }

    #[test]
    fn encrypted_secret_context_rejects_replayed_response() {
        let first_nonce = [1_u8; TCP_AUTH_NONCE_LEN];
        let second_nonce = [2_u8; TCP_AUTH_NONCE_LEN];
        let first_transcript =
            tcp_auth_request_transcript(TCP_HANDSHAKE_VERSION, "alice", 1, &first_nonce).unwrap();
        let second_transcript =
            tcp_auth_request_transcript(TCP_HANDSHAKE_VERSION, "alice", 2, &second_nonce).unwrap();
        let secret = TcpSessionSecret {
            version: TCP_HANDSHAKE_VERSION,
            auth_transcript_hash: tcp_auth_transcript_hash(&first_transcript),
            client_nonce: first_nonce,
            server_nonce: [3; TCP_SERVER_NONCE_LEN],
            session_id: [4; TCP_SESSION_ID_LEN],
            master_secret: [5; TCP_MASTER_SECRET_LEN],
        };

        secret
            .validate_handshake_context(&tcp_auth_transcript_hash(&first_transcript), &first_nonce)
            .unwrap();
        assert!(
            secret
                .validate_handshake_context(
                    &tcp_auth_transcript_hash(&second_transcript),
                    &second_nonce,
                )
                .is_err()
        );
    }

    #[test]
    fn proxy_signature_binds_version_request_and_complete_ciphertext() {
        let proxy_identity = RsaKeyPair::generate(2048).unwrap();
        let proxy_public =
            RsaKeyPair::from_public_key_pem(&proxy_identity.public_key_to_pem().unwrap()).unwrap();
        let request_hash = [7_u8; 32];
        let ciphertext = vec![9_u8; 256];
        let transcript = tcp_auth_response_signature_transcript(
            TCP_HANDSHAKE_VERSION,
            &request_hash,
            &ciphertext,
        )
        .unwrap();
        let signature = proxy_identity.sign_pss_sha256(&transcript).unwrap();
        verify_pss_sha256(&proxy_public, &transcript, &signature).unwrap();

        let mut changed_hash = request_hash;
        changed_hash[0] ^= 1;
        let changed_request = tcp_auth_response_signature_transcript(
            TCP_HANDSHAKE_VERSION,
            &changed_hash,
            &ciphertext,
        )
        .unwrap();
        assert!(verify_pss_sha256(&proxy_public, &changed_request, &signature).is_err());

        let mut changed_ciphertext = ciphertext;
        changed_ciphertext[31] ^= 1;
        let changed_response = tcp_auth_response_signature_transcript(
            TCP_HANDSHAKE_VERSION,
            &request_hash,
            &changed_ciphertext,
        )
        .unwrap();
        assert!(verify_pss_sha256(&proxy_public, &changed_response, &signature).is_err());
    }

    #[test]
    fn failure_signature_binds_request_code_and_message() {
        let proxy_identity = RsaKeyPair::generate(2048).unwrap();
        let proxy_public =
            RsaKeyPair::from_public_key_pem(&proxy_identity.public_key_to_pem().unwrap()).unwrap();
        let request_hash = [21_u8; 32];
        let transcript = tcp_auth_failure_signature_transcript(
            TCP_HANDSHAKE_VERSION,
            &request_hash,
            AuthFailureCode::UserExpired,
            "User expired",
        )
        .unwrap();
        let signature = proxy_identity.sign_pss_sha256(&transcript).unwrap();
        verify_pss_sha256(&proxy_public, &transcript, &signature).unwrap();

        let mut changed_hash = request_hash;
        changed_hash[0] ^= 1;
        for changed in [
            tcp_auth_failure_signature_transcript(
                TCP_HANDSHAKE_VERSION,
                &changed_hash,
                AuthFailureCode::UserExpired,
                "User expired",
            )
            .unwrap(),
            tcp_auth_failure_signature_transcript(
                TCP_HANDSHAKE_VERSION,
                &request_hash,
                AuthFailureCode::UserDisabled,
                "User expired",
            )
            .unwrap(),
            tcp_auth_failure_signature_transcript(
                TCP_HANDSHAKE_VERSION,
                &request_hash,
                AuthFailureCode::UserExpired,
                "User expired today",
            )
            .unwrap(),
        ] {
            assert!(verify_pss_sha256(&proxy_public, &changed, &signature).is_err());
        }
    }

    #[test]
    fn session_secret_encoding_is_bounded_and_versioned() {
        let secret = TcpSessionSecret {
            version: TCP_HANDSHAKE_VERSION,
            auth_transcript_hash: [1; 32],
            client_nonce: [2; TCP_AUTH_NONCE_LEN],
            server_nonce: [3; TCP_SERVER_NONCE_LEN],
            session_id: [4; TCP_SESSION_ID_LEN],
            master_secret: [5; TCP_MASTER_SECRET_LEN],
        };
        let encoded = encode_tcp_session_secret(&secret).unwrap();
        let decoded = decode_tcp_session_secret(&encoded).unwrap();
        decoded
            .validate_handshake_context(&secret.auth_transcript_hash, &secret.client_nonce)
            .unwrap();

        let mut wrong_version = secret;
        wrong_version.version -= 1;
        assert!(encode_tcp_session_secret(&wrong_version).is_err());
        assert!(decode_tcp_session_secret(&vec![0; TCP_SESSION_SECRET_MAX_SIZE + 1]).is_err());
    }

    #[test]
    fn complete_signed_handshake_and_directional_records_interoperate() {
        let user = RsaKeyPair::generate(2048).unwrap();
        let user_public =
            RsaKeyPair::from_public_key_pem(&user.public_key_to_pem().unwrap()).unwrap();
        let proxy_identity = RsaKeyPair::generate(2048).unwrap();
        let pinned_proxy_public =
            RsaKeyPair::from_public_key_pem(&proxy_identity.public_key_to_pem().unwrap()).unwrap();
        let client_nonce = [11; TCP_AUTH_NONCE_LEN];
        let request = tcp_auth_request_transcript(
            TCP_HANDSHAKE_VERSION,
            "alice",
            1_700_000_000,
            &client_nonce,
        )
        .unwrap();
        let request_hash = tcp_auth_transcript_hash(&request);
        let client_proof = user.sign_pss_sha256(&request).unwrap();
        verify_pss_sha256(&user_public, &request, &client_proof).unwrap();

        let secret = TcpSessionSecret {
            version: TCP_HANDSHAKE_VERSION,
            auth_transcript_hash: request_hash,
            client_nonce,
            server_nonce: [12; TCP_SERVER_NONCE_LEN],
            session_id: [13; TCP_SESSION_ID_LEN],
            master_secret: [14; TCP_MASTER_SECRET_LEN],
        };
        let encoded_secret = encode_tcp_session_secret(&secret).unwrap();
        let encrypted_session =
            encrypt_oaep_sha256_labelled(&user_public, TCP_OAEP_LABEL, &encoded_secret).unwrap();
        let response_transcript = tcp_auth_response_signature_transcript(
            TCP_HANDSHAKE_VERSION,
            &request_hash,
            &encrypted_session,
        )
        .unwrap();
        let proxy_signature = proxy_identity
            .sign_pss_sha256(&response_transcript)
            .unwrap();

        // Client verifies the pinned server identity before OAEP decryption.
        verify_pss_sha256(&pinned_proxy_public, &response_transcript, &proxy_signature).unwrap();
        let decrypted = user
            .decrypt_oaep_sha256_labelled(TCP_OAEP_LABEL, &encrypted_session)
            .unwrap();
        let accepted = decode_tcp_session_secret(&decrypted).unwrap();
        accepted
            .validate_handshake_context(&request_hash, &client_nonce)
            .unwrap();

        let agent = TcpSessionCipher::new(
            TcpSessionRole::Agent,
            accepted.master_secret,
            request_hash,
            client_nonce,
            accepted.server_nonce,
            accepted.session_id,
        )
        .unwrap();
        let proxy = TcpSessionCipher::new(
            TcpSessionRole::Proxy,
            secret.master_secret,
            request_hash,
            client_nonce,
            secret.server_nonce,
            secret.session_id,
        )
        .unwrap();
        let request_frame = agent.seal(MessageType::Data, 0, b"hello proxy").unwrap();
        assert_eq!(
            proxy
                .open(MessageType::Data, 0, request_frame.0, &request_frame.1,)
                .unwrap(),
            b"hello proxy"
        );
        let response_frame = proxy.seal(MessageType::Data, 0, b"hello agent").unwrap();
        assert_eq!(
            agent
                .open(MessageType::Data, 0, response_frame.0, &response_frame.1,)
                .unwrap(),
            b"hello agent"
        );
    }

    #[test]
    fn wrong_proxy_pin_and_legacy_raw_style_proof_are_rejected() {
        let user = RsaKeyPair::generate(2048).unwrap();
        let user_public =
            RsaKeyPair::from_public_key_pem(&user.public_key_to_pem().unwrap()).unwrap();
        let proxy_identity = RsaKeyPair::generate(2048).unwrap();
        let wrong_proxy_identity = RsaKeyPair::generate(2048).unwrap();
        let wrong_pin =
            RsaKeyPair::from_public_key_pem(&wrong_proxy_identity.public_key_to_pem().unwrap())
                .unwrap();
        let request_hash = [1; 32];
        let ciphertext = vec![2; user.modulus_size()];
        let response_transcript = tcp_auth_response_signature_transcript(
            TCP_HANDSHAKE_VERSION,
            &request_hash,
            &ciphertext,
        )
        .unwrap();
        let proxy_signature = proxy_identity
            .sign_pss_sha256(&response_transcript)
            .unwrap();
        assert!(verify_pss_sha256(&wrong_pin, &response_transcript, &proxy_signature).is_err());

        let request = tcp_auth_request_transcript(
            TCP_HANDSHAKE_VERSION,
            "alice",
            10,
            &[3; TCP_AUTH_NONCE_LEN],
        )
        .unwrap();
        // The retired wire path sent a modulus-sized raw private-RSA result,
        // not a PSS signature. A modulus-sized opaque blob must not pass.
        let legacy_raw_style_proof = vec![0x42; user.modulus_size()];
        assert!(verify_pss_sha256(&user_public, &request, &legacy_raw_style_proof).is_err());
    }
}
