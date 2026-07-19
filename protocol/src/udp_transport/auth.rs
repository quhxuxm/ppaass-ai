use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

use super::{
    UDP_MAX_DATAGRAM_SIZE, UDP_TRANSPORT_HEADER_LEN, UdpPacketHeader, UdpPacketKind, UdpSessionId,
    UdpTransportError, UdpTransportResult,
};

pub const UDP_AUTH_NONCE_LEN: usize = 32;
pub const UDP_MASTER_KEY_LEN: usize = 32;

/// Cleartext first flight. It carries only identity/challenge context and a
/// signature made with the user's private key; it never carries session key material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpAuthInit {
    pub username: String,
    pub timestamp: i64,
    pub client_nonce: [u8; UDP_AUTH_NONCE_LEN],
    pub proof: Vec<u8>,
}

/// Cleartext envelope for the response. `encrypted_session_secret` must be the
/// bitcode encoding of [`UdpSessionSecret`] encrypted by the upper layer with
/// RSAES-OAEP-SHA256 and the authenticated user's RSA public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpAuthOk {
    pub encrypted_session_secret: Vec<u8>,
}

/// Secret response contents. This value itself must never be sent in cleartext.
#[derive(Clone, Serialize, Deserialize)]
pub struct UdpSessionSecret {
    /// Binds this encrypted response to the exact AuthInit header.
    pub session_id: UdpSessionId,
    /// Binds this encrypted response to the exact client challenge.
    pub client_nonce: [u8; UDP_AUTH_NONCE_LEN],
    pub master_key: [u8; UDP_MASTER_KEY_LEN],
    pub server_nonce: [u8; UDP_AUTH_NONCE_LEN],
}

impl std::fmt::Debug for UdpSessionSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UdpSessionSecret")
            .field("session_id", &self.session_id)
            .field("client_nonce", &self.client_nonce)
            .field("master_key", &"[REDACTED]")
            .field("server_nonce", &self.server_nonce)
            .finish()
    }
}

impl UdpSessionSecret {
    /// Reject a decrypted AuthOk that belongs to any other AuthInit. This is
    /// checked before the secret is accepted for traffic key derivation.
    pub fn validate_handshake_context(
        &self,
        session_id: &UdpSessionId,
        client_nonce: &[u8; UDP_AUTH_NONCE_LEN],
    ) -> UdpTransportResult<()> {
        if self.session_id == *session_id && self.client_nonce == *client_nonce {
            Ok(())
        } else {
            Err(UdpTransportError::AuthenticationFailed)
        }
    }
}

/// Domain-separated SHA-256 digest signed by the agent's private key.
/// Length-prefixing the username makes the transcript unambiguous.
pub fn udp_auth_proof_digest(
    session_id: &UdpSessionId,
    username: &str,
    timestamp: i64,
    client_nonce: &[u8; UDP_AUTH_NONCE_LEN],
) -> [u8; 32] {
    let username_bytes = username.as_bytes();
    let username_len = u32::try_from(username_bytes.len()).unwrap_or(u32::MAX);
    let mut hasher = Sha256::new();
    hasher.update(b"ppaass/native-udp/auth-proof/v1\0");
    hasher.update(session_id);
    hasher.update(username_len.to_be_bytes());
    hasher.update(username_bytes);
    hasher.update(timestamp.to_be_bytes());
    hasher.update(client_nonce);
    hasher.finalize().into()
}

/// Encode an AuthInit as a complete cleartext UDP datagram with the shared
/// magic/version/kind/session header.
pub fn encode_auth_init(
    session_id: UdpSessionId,
    auth: &UdpAuthInit,
) -> UdpTransportResult<Vec<u8>> {
    encode_auth_packet(UdpPacketKind::AuthInit, session_id, auth)
}

pub fn decode_auth_init(datagram: &[u8]) -> UdpTransportResult<(UdpPacketHeader, UdpAuthInit)> {
    decode_auth_packet(UdpPacketKind::AuthInit, datagram)
}

/// Encode an AuthOk as a complete cleartext UDP datagram. Only its RSA-encrypted
/// secret blob is exposed on the wire.
pub fn encode_auth_ok(session_id: UdpSessionId, auth: &UdpAuthOk) -> UdpTransportResult<Vec<u8>> {
    encode_auth_packet(UdpPacketKind::AuthOk, session_id, auth)
}

pub fn decode_auth_ok(datagram: &[u8]) -> UdpTransportResult<(UdpPacketHeader, UdpAuthOk)> {
    decode_auth_packet(UdpPacketKind::AuthOk, datagram)
}

/// Serialize the secret before the upper layer RSA-encrypts it.
pub fn encode_session_secret(secret: &UdpSessionSecret) -> UdpTransportResult<Vec<u8>> {
    bitcode::serialize(secret).map_err(|error| UdpTransportError::Serialization(error.to_string()))
}

/// Deserialize the plaintext obtained only after upper-layer RSA decryption.
pub fn decode_session_secret(bytes: &[u8]) -> UdpTransportResult<UdpSessionSecret> {
    bitcode::deserialize(bytes).map_err(|error| UdpTransportError::Serialization(error.to_string()))
}

fn encode_auth_packet<T: Serialize>(
    kind: UdpPacketKind,
    session_id: UdpSessionId,
    value: &T,
) -> UdpTransportResult<Vec<u8>> {
    let payload = bitcode::serialize(value)
        .map_err(|error| UdpTransportError::Serialization(error.to_string()))?;
    let datagram_len = UDP_TRANSPORT_HEADER_LEN + payload.len();
    if datagram_len > UDP_MAX_DATAGRAM_SIZE {
        return Err(UdpTransportError::DatagramTooLarge(datagram_len));
    }

    let header = UdpPacketHeader::new(kind, session_id, 0, 0, 0, 1, payload.len() as u32);
    let mut datagram = Vec::with_capacity(datagram_len);
    datagram.extend_from_slice(&header.encode()?);
    datagram.extend_from_slice(&payload);
    Ok(datagram)
}

fn decode_auth_packet<T: DeserializeOwned>(
    expected_kind: UdpPacketKind,
    datagram: &[u8],
) -> UdpTransportResult<(UdpPacketHeader, T)> {
    if datagram.len() > UDP_MAX_DATAGRAM_SIZE {
        return Err(UdpTransportError::DatagramTooLarge(datagram.len()));
    }
    if datagram.len() < UDP_TRANSPORT_HEADER_LEN {
        return Err(UdpTransportError::DatagramTooShort(datagram.len()));
    }

    let header = UdpPacketHeader::decode(datagram)?;
    if header.kind != expected_kind {
        return Err(UdpTransportError::UnexpectedPacketKind {
            expected: expected_kind as u8,
            actual: header.kind as u8,
        });
    }
    let payload = &datagram[UDP_TRANSPORT_HEADER_LEN..];
    if header.total_len as usize != payload.len() {
        return Err(UdpTransportError::InvalidHeader(
            "authentication payload length does not match total_len",
        ));
    }
    let value = bitcode::deserialize(payload)
        .map_err(|error| UdpTransportError::Serialization(error.to_string()))?;
    Ok((header, value))
}
