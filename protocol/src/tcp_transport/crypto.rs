use std::sync::Mutex;

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::message::{MessageType, PROTOCOL_VERSION};
use crate::{ProtocolError, Result};

use super::{TCP_AUTH_NONCE_LEN, TCP_MASTER_SECRET_LEN, TCP_SERVER_NONCE_LEN, TCP_SESSION_ID_LEN};

const KEY_LEN: usize = 32;
const NONCE_PREFIX_LEN: usize = 4;
const FRAME_AAD_DOMAIN: &[u8] = b"ppaass/tcp-yamux/frame/v3\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TcpFrameDirection {
    ClientToServer = 1,
    ServerToClient = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpSessionRole {
    Agent,
    Proxy,
}

#[derive(Clone)]
pub struct TcpDirectionalKeyMaterial {
    pub client_to_server_key: [u8; KEY_LEN],
    pub server_to_client_key: [u8; KEY_LEN],
    pub client_to_server_nonce_prefix: [u8; NONCE_PREFIX_LEN],
    pub server_to_client_nonce_prefix: [u8; NONCE_PREFIX_LEN],
}

impl std::fmt::Debug for TcpDirectionalKeyMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TcpDirectionalKeyMaterial")
            .field("client_to_server_key", &"[REDACTED]")
            .field("server_to_client_key", &"[REDACTED]")
            .field(
                "client_to_server_nonce_prefix",
                &self.client_to_server_nonce_prefix,
            )
            .field(
                "server_to_client_nonce_prefix",
                &self.server_to_client_nonce_prefix,
            )
            .finish()
    }
}

impl TcpDirectionalKeyMaterial {
    pub fn derive(
        master_secret: &[u8; TCP_MASTER_SECRET_LEN],
        auth_transcript_hash: &[u8; 32],
        client_nonce: &[u8; TCP_AUTH_NONCE_LEN],
        server_nonce: &[u8; TCP_SERVER_NONCE_LEN],
        session_id: &[u8; TCP_SESSION_ID_LEN],
    ) -> Result<Self> {
        let mut salt_hasher = Sha256::new();
        salt_hasher.update(b"ppaass/tcp-yamux/hkdf-salt/v3\0");
        salt_hasher.update([PROTOCOL_VERSION]);
        salt_hasher.update(auth_transcript_hash);
        salt_hasher.update(client_nonce);
        salt_hasher.update(server_nonce);
        salt_hasher.update(session_id);
        let salt = salt_hasher.finalize();
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), master_secret);

        let mut material = Self {
            client_to_server_key: [0; KEY_LEN],
            server_to_client_key: [0; KEY_LEN],
            client_to_server_nonce_prefix: [0; NONCE_PREFIX_LEN],
            server_to_client_nonce_prefix: [0; NONCE_PREFIX_LEN],
        };
        expand(
            &hkdf,
            b"ppaass/tcp-yamux/v3/client-to-server/key",
            &mut material.client_to_server_key,
        )?;
        expand(
            &hkdf,
            b"ppaass/tcp-yamux/v3/server-to-client/key",
            &mut material.server_to_client_key,
        )?;
        expand(
            &hkdf,
            b"ppaass/tcp-yamux/v3/client-to-server/nonce-prefix",
            &mut material.client_to_server_nonce_prefix,
        )?;
        expand(
            &hkdf,
            b"ppaass/tcp-yamux/v3/server-to-client/nonce-prefix",
            &mut material.server_to_client_nonce_prefix,
        )?;

        if material.client_to_server_key == material.server_to_client_key
            || material.client_to_server_nonce_prefix == material.server_to_client_nonce_prefix
        {
            return Err(ProtocolError::InvalidKey(
                "directional TCP key derivation collision".to_string(),
            ));
        }
        Ok(material)
    }
}

fn expand(hkdf: &Hkdf<Sha256>, label: &[u8], output: &mut [u8]) -> Result<()> {
    hkdf.expand(label, output)
        .map_err(|_| ProtocolError::InvalidKey("TCP key derivation failed".to_string()))
}

struct DirectionState {
    direction: TcpFrameDirection,
    cipher: Aes256Gcm,
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
}

#[derive(Debug)]
struct SequenceState {
    next: u64,
    exhausted: bool,
}

/// Directional AEAD state shared by the framed encoder and decoder.
pub struct TcpSessionCipher {
    role: TcpSessionRole,
    send: DirectionState,
    receive: DirectionState,
    send_sequence: Mutex<SequenceState>,
    receive_sequence: Mutex<SequenceState>,
}

impl std::fmt::Debug for TcpSessionCipher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TcpSessionCipher")
            .field("role", &self.role)
            .field("send_direction", &self.send.direction)
            .field("receive_direction", &self.receive.direction)
            .finish_non_exhaustive()
    }
}

impl TcpSessionCipher {
    pub fn new(
        role: TcpSessionRole,
        master_secret: [u8; TCP_MASTER_SECRET_LEN],
        auth_transcript_hash: [u8; 32],
        client_nonce: [u8; TCP_AUTH_NONCE_LEN],
        server_nonce: [u8; TCP_SERVER_NONCE_LEN],
        session_id: [u8; TCP_SESSION_ID_LEN],
    ) -> Result<Self> {
        let material = TcpDirectionalKeyMaterial::derive(
            &master_secret,
            &auth_transcript_hash,
            &client_nonce,
            &server_nonce,
            &session_id,
        )?;
        Ok(Self::from_key_material(role, material))
    }

    pub fn from_key_material(role: TcpSessionRole, material: TcpDirectionalKeyMaterial) -> Self {
        let client_to_server = DirectionState {
            direction: TcpFrameDirection::ClientToServer,
            cipher: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&material.client_to_server_key)),
            nonce_prefix: material.client_to_server_nonce_prefix,
        };
        let server_to_client = DirectionState {
            direction: TcpFrameDirection::ServerToClient,
            cipher: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&material.server_to_client_key)),
            nonce_prefix: material.server_to_client_nonce_prefix,
        };
        let (send, receive) = match role {
            TcpSessionRole::Agent => (client_to_server, server_to_client),
            TcpSessionRole::Proxy => (server_to_client, client_to_server),
        };
        Self {
            role,
            send,
            receive,
            send_sequence: Mutex::new(SequenceState {
                next: 0,
                exhausted: false,
            }),
            receive_sequence: Mutex::new(SequenceState {
                next: 0,
                exhausted: false,
            }),
        }
    }

    pub fn seal(
        &self,
        message_type: MessageType,
        compression: u8,
        plaintext: &[u8],
    ) -> Result<(u64, Vec<u8>)> {
        let mut sequence = self.send_sequence.lock().map_err(|_| {
            ProtocolError::Encryption("TCP send sequence state is unavailable".to_string())
        })?;
        if sequence.exhausted {
            return Err(ProtocolError::Encryption(
                "TCP send sequence exhausted".to_string(),
            ));
        }
        let current = sequence.next;
        let nonce = make_nonce(self.send.nonce_prefix, current);
        let aad = frame_aad(self.send.direction, message_type, compression, current);
        let ciphertext = self
            .send
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| ProtocolError::Encryption("TCP frame encryption failed".to_string()))?;
        advance_sequence(&mut sequence);
        Ok((current, ciphertext))
    }

    pub fn open(
        &self,
        message_type: MessageType,
        compression: u8,
        wire_sequence: u64,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let mut sequence = self.receive_sequence.lock().map_err(|_| {
            ProtocolError::Decryption("TCP receive sequence state is unavailable".to_string())
        })?;
        if sequence.exhausted {
            return Err(ProtocolError::Decryption(
                "TCP receive sequence exhausted".to_string(),
            ));
        }
        if wire_sequence != sequence.next {
            return Err(ProtocolError::InvalidMessage(format!(
                "unexpected TCP frame sequence: expected {}, got {wire_sequence}",
                sequence.next
            )));
        }
        let nonce = make_nonce(self.receive.nonce_prefix, wire_sequence);
        let aad = frame_aad(
            self.receive.direction,
            message_type,
            compression,
            wire_sequence,
        );
        let plaintext = self
            .receive
            .cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                ProtocolError::AuthenticationFailed("TCP frame authentication failed".to_string())
            })?;
        advance_sequence(&mut sequence);
        Ok(plaintext)
    }
}

fn advance_sequence(sequence: &mut SequenceState) {
    if sequence.next == u64::MAX {
        sequence.exhausted = true;
    } else {
        sequence.next += 1;
    }
}

fn make_nonce(prefix: [u8; NONCE_PREFIX_LEN], sequence: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[..NONCE_PREFIX_LEN].copy_from_slice(&prefix);
    nonce[NONCE_PREFIX_LEN..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

fn frame_aad(
    direction: TcpFrameDirection,
    message_type: MessageType,
    compression: u8,
    sequence: u64,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(FRAME_AAD_DOMAIN.len() + 12);
    aad.extend_from_slice(FRAME_AAD_DOMAIN);
    aad.push(direction as u8);
    aad.push(PROTOCOL_VERSION);
    aad.push(message_type as u8);
    aad.push(compression);
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cipher_pair() -> (TcpSessionCipher, TcpSessionCipher) {
        let inputs = (
            [1; TCP_MASTER_SECRET_LEN],
            [2; 32],
            [3; TCP_AUTH_NONCE_LEN],
            [4; TCP_SERVER_NONCE_LEN],
            [5; TCP_SESSION_ID_LEN],
        );
        (
            TcpSessionCipher::new(
                TcpSessionRole::Agent,
                inputs.0,
                inputs.1,
                inputs.2,
                inputs.3,
                inputs.4,
            )
            .unwrap(),
            TcpSessionCipher::new(
                TcpSessionRole::Proxy,
                inputs.0,
                inputs.1,
                inputs.2,
                inputs.3,
                inputs.4,
            )
            .unwrap(),
        )
    }

    #[test]
    fn both_directions_interoperate_but_reflection_fails() {
        let (agent, proxy) = cipher_pair();
        let (sequence, ciphertext) = agent.seal(MessageType::Data, 0, b"request").unwrap();
        assert_eq!(
            proxy
                .open(MessageType::Data, 0, sequence, &ciphertext)
                .unwrap(),
            b"request"
        );
        assert!(
            agent
                .open(MessageType::Data, 0, sequence, &ciphertext)
                .is_err()
        );

        let (sequence, ciphertext) = proxy.seal(MessageType::Data, 0, b"response").unwrap();
        assert_eq!(
            agent
                .open(MessageType::Data, 0, sequence, &ciphertext)
                .unwrap(),
            b"response"
        );
    }

    #[test]
    fn duplicate_skipped_and_reordered_sequences_are_rejected() {
        let (agent, proxy) = cipher_pair();
        let first = agent.seal(MessageType::Data, 0, b"first").unwrap();
        let second = agent.seal(MessageType::Data, 0, b"second").unwrap();

        assert!(
            proxy
                .open(MessageType::Data, 0, second.0, &second.1)
                .is_err()
        );
        proxy.open(MessageType::Data, 0, first.0, &first.1).unwrap();
        assert!(proxy.open(MessageType::Data, 0, first.0, &first.1).is_err());
        proxy
            .open(MessageType::Data, 0, second.0, &second.1)
            .unwrap();
    }

    #[test]
    fn aad_binds_type_compression_and_direction() {
        let (agent, proxy) = cipher_pair();
        let frame = agent.seal(MessageType::Data, 2, b"payload").unwrap();
        assert!(
            proxy
                .open(MessageType::ConnectRequest, 2, frame.0, &frame.1)
                .is_err()
        );

        let (agent, proxy) = cipher_pair();
        let frame = agent.seal(MessageType::Data, 2, b"payload").unwrap();
        assert!(proxy.open(MessageType::Data, 3, frame.0, &frame.1).is_err());
    }

    #[test]
    fn sequence_exhaustion_fails_closed() {
        let (agent, proxy) = cipher_pair();
        agent.send_sequence.lock().unwrap().next = u64::MAX;
        proxy.receive_sequence.lock().unwrap().next = u64::MAX;
        let final_frame = agent.seal(MessageType::Data, 0, b"last").unwrap();
        proxy
            .open(MessageType::Data, 0, final_frame.0, &final_frame.1)
            .unwrap();
        assert!(agent.seal(MessageType::Data, 0, b"too late").is_err());
        assert!(
            proxy
                .open(MessageType::Data, 0, u64::MAX, &final_frame.1)
                .is_err()
        );
    }
}
