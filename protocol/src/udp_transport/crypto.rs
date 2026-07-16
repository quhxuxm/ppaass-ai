use std::time::Instant;

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadInPlace, KeyInit, Payload},
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use super::{
    FragmentReassembler, ReassemblyConfig, ReplayWindow, UDP_AEAD_TAG_LEN, UDP_MAX_DATAGRAM_SIZE,
    UDP_MAX_FRAGMENT_PLAINTEXT, UDP_MAX_FRAGMENTS, UDP_MAX_MESSAGE_SIZE, UDP_TRANSPORT_HEADER_LEN,
    UdpPacketHeader, UdpPacketKind, UdpSessionId, UdpSessionMessage, UdpTransportError,
    UdpTransportResult,
};

const KEY_LEN: usize = 32;
const NONCE_PREFIX_LEN: usize = 4;
const NONCE_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpSessionRole {
    Agent,
    Proxy,
}

/// Both wire directions derived from a session secret. Direction labels are
/// fixed protocol inputs, not selected by callers.
#[derive(Clone)]
pub struct UdpDirectionalKeyMaterial {
    pub client_to_server_key: [u8; KEY_LEN],
    pub server_to_client_key: [u8; KEY_LEN],
    pub client_to_server_nonce_prefix: [u8; NONCE_PREFIX_LEN],
    pub server_to_client_nonce_prefix: [u8; NONCE_PREFIX_LEN],
}

impl std::fmt::Debug for UdpDirectionalKeyMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UdpDirectionalKeyMaterial")
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

impl UdpDirectionalKeyMaterial {
    pub fn derive(
        master_key: &[u8; KEY_LEN],
        session_id: &UdpSessionId,
        client_nonce: &[u8; 32],
        server_nonce: &[u8; 32],
    ) -> UdpTransportResult<Self> {
        let mut salt_hasher = Sha256::new();
        salt_hasher.update(b"ppaass/native-udp/hkdf-salt/v1\0");
        salt_hasher.update(session_id);
        salt_hasher.update(client_nonce);
        salt_hasher.update(server_nonce);
        let salt = salt_hasher.finalize();
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), master_key);

        let mut material = Self {
            client_to_server_key: [0; KEY_LEN],
            server_to_client_key: [0; KEY_LEN],
            client_to_server_nonce_prefix: [0; NONCE_PREFIX_LEN],
            server_to_client_nonce_prefix: [0; NONCE_PREFIX_LEN],
        };
        expand_label(
            &hkdf,
            b"ppaass/native-udp/v1/client-to-server/key",
            &mut material.client_to_server_key,
        )?;
        expand_label(
            &hkdf,
            b"ppaass/native-udp/v1/server-to-client/key",
            &mut material.server_to_client_key,
        )?;
        expand_label(
            &hkdf,
            b"ppaass/native-udp/v1/client-to-server/nonce-prefix",
            &mut material.client_to_server_nonce_prefix,
        )?;
        expand_label(
            &hkdf,
            b"ppaass/native-udp/v1/server-to-client/nonce-prefix",
            &mut material.server_to_client_nonce_prefix,
        )?;

        if material.client_to_server_key == material.server_to_client_key
            || material.client_to_server_nonce_prefix == material.server_to_client_nonce_prefix
        {
            return Err(UdpTransportError::KeyDerivation);
        }
        Ok(material)
    }
}

fn expand_label(hkdf: &Hkdf<Sha256>, label: &[u8], output: &mut [u8]) -> UdpTransportResult<()> {
    hkdf.expand(label, output)
        .map_err(|_| UdpTransportError::KeyDerivation)
}

struct DirectionState {
    cipher: Aes256Gcm,
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
}

#[derive(Debug, Clone)]
pub struct DecryptedUdpFragment {
    pub header: UdpPacketHeader,
    pub payload: Vec<u8>,
}

/// Directional AEAD and replay state for one authenticated session.
pub struct UdpSessionCrypto {
    role: UdpSessionRole,
    session_id: UdpSessionId,
    send: DirectionState,
    receive: DirectionState,
    next_send_sequence: u64,
    send_sequence_exhausted: bool,
    replay: ReplayWindow,
}

impl std::fmt::Debug for UdpSessionCrypto {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UdpSessionCrypto")
            .field("role", &self.role)
            .field("session_id", &self.session_id)
            .field("next_send_sequence", &self.next_send_sequence)
            .field("send_sequence_exhausted", &self.send_sequence_exhausted)
            .field("replay", &self.replay)
            .finish_non_exhaustive()
    }
}

impl UdpSessionCrypto {
    pub fn new(
        role: UdpSessionRole,
        session_id: UdpSessionId,
        master_key: [u8; KEY_LEN],
        client_nonce: [u8; 32],
        server_nonce: [u8; 32],
    ) -> UdpTransportResult<Self> {
        let keys = UdpDirectionalKeyMaterial::derive(
            &master_key,
            &session_id,
            &client_nonce,
            &server_nonce,
        )?;
        Ok(Self::from_key_material(role, session_id, keys))
    }

    pub fn from_key_material(
        role: UdpSessionRole,
        session_id: UdpSessionId,
        keys: UdpDirectionalKeyMaterial,
    ) -> Self {
        let client_to_server = DirectionState {
            cipher: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&keys.client_to_server_key)),
            nonce_prefix: keys.client_to_server_nonce_prefix,
        };
        let server_to_client = DirectionState {
            cipher: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&keys.server_to_client_key)),
            nonce_prefix: keys.server_to_client_nonce_prefix,
        };
        let (send, receive) = match role {
            UdpSessionRole::Agent => (client_to_server, server_to_client),
            UdpSessionRole::Proxy => (server_to_client, client_to_server),
        };
        Self {
            role,
            session_id,
            send,
            receive,
            next_send_sequence: 0,
            send_sequence_exhausted: false,
            replay: ReplayWindow::new(),
        }
    }

    pub fn role(&self) -> UdpSessionRole {
        self.role
    }

    pub fn session_id(&self) -> UdpSessionId {
        self.session_id
    }

    pub fn replay_window(&self) -> &ReplayWindow {
        &self.replay
    }

    /// Encrypt and independently authenticate every fragment of one message.
    pub fn seal_message(
        &mut self,
        message_id: u64,
        plaintext: &[u8],
    ) -> UdpTransportResult<Vec<Vec<u8>>> {
        if plaintext.len() > UDP_MAX_MESSAGE_SIZE {
            return Err(UdpTransportError::MessageTooLarge(plaintext.len()));
        }
        let fragment_count = plaintext.len().div_ceil(UDP_MAX_FRAGMENT_PLAINTEXT).max(1);
        if fragment_count > UDP_MAX_FRAGMENTS {
            return Err(UdpTransportError::TooManyFragments(fragment_count));
        }
        if self.send_sequence_exhausted {
            return Err(UdpTransportError::SequenceExhausted);
        }
        let last_sequence = self
            .next_send_sequence
            .checked_add(fragment_count as u64 - 1)
            .ok_or(UdpTransportError::SequenceExhausted)?;

        let mut datagrams = Vec::with_capacity(fragment_count);
        for fragment_index in 0..fragment_count {
            let start = fragment_index * UDP_MAX_FRAGMENT_PLAINTEXT;
            let end = (start + UDP_MAX_FRAGMENT_PLAINTEXT).min(plaintext.len());
            let fragment = &plaintext[start..end];
            let seq = self.next_send_sequence + fragment_index as u64;
            let header = UdpPacketHeader::new(
                UdpPacketKind::Encrypted,
                self.session_id,
                seq,
                message_id,
                fragment_index as u16,
                fragment_count as u16,
                plaintext.len() as u32,
            );
            let aad = header.encode()?;
            let nonce = make_nonce(self.send.nonce_prefix, seq);
            // Build the wire datagram once and encrypt the payload in place.  The
            // previous path allocated a ciphertext Vec in aes-gcm and then copied
            // it into a second datagram Vec for every fragment.
            let datagram_len = aad.len() + fragment.len() + UDP_AEAD_TAG_LEN;
            if datagram_len > UDP_MAX_DATAGRAM_SIZE {
                return Err(UdpTransportError::DatagramTooLarge(datagram_len));
            }
            let mut datagram = Vec::with_capacity(datagram_len);
            datagram.extend_from_slice(&aad);
            datagram.extend_from_slice(fragment);
            let payload_start = aad.len();
            let tag = self
                .send
                .cipher
                .encrypt_in_place_detached(
                    Nonce::from_slice(&nonce),
                    &aad,
                    &mut datagram[payload_start..],
                )
                .map_err(|_| UdpTransportError::EncryptionFailed)?;
            datagram.extend_from_slice(&tag);
            datagrams.push(datagram);
        }

        if last_sequence == u64::MAX {
            self.send_sequence_exhausted = true;
        } else {
            self.next_send_sequence = last_sequence + 1;
        }
        Ok(datagrams)
    }

    /// Parse, replay-check, authenticate, then commit a single fragment.
    pub fn open_datagram(&mut self, datagram: &[u8]) -> UdpTransportResult<DecryptedUdpFragment> {
        if datagram.len() > UDP_MAX_DATAGRAM_SIZE {
            return Err(UdpTransportError::DatagramTooLarge(datagram.len()));
        }
        if datagram.len() < UDP_TRANSPORT_HEADER_LEN + UDP_AEAD_TAG_LEN {
            return Err(UdpTransportError::DatagramTooShort(datagram.len()));
        }

        let header = UdpPacketHeader::decode(datagram)?;
        if header.kind != UdpPacketKind::Encrypted {
            return Err(UdpTransportError::UnexpectedPacketKind {
                expected: UdpPacketKind::Encrypted as u8,
                actual: header.kind as u8,
            });
        }
        if header.session_id != self.session_id {
            return Err(UdpTransportError::WrongSession);
        }
        if !self.replay.may_accept(header.seq) {
            return Err(UdpTransportError::ReplayRejected);
        }

        let aad = &datagram[..UDP_TRANSPORT_HEADER_LEN];
        let ciphertext = &datagram[UDP_TRANSPORT_HEADER_LEN..];
        let nonce = make_nonce(self.receive.nonce_prefix, header.seq);
        let plaintext = self
            .receive
            .cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| UdpTransportError::AuthenticationFailed)?;
        if plaintext.len() > UDP_MAX_FRAGMENT_PLAINTEXT {
            return Err(UdpTransportError::InvalidHeader(
                "decrypted fragment exceeds maximum plaintext size",
            ));
        }
        if header.total_len != 0 && plaintext.is_empty() {
            return Err(UdpTransportError::InvalidHeader(
                "non-empty messages cannot contain empty fragments",
            ));
        }
        if !self.replay.commit(header.seq) {
            return Err(UdpTransportError::ReplayRejected);
        }
        Ok(DecryptedUdpFragment {
            header,
            payload: plaintext,
        })
    }
}

fn make_nonce(prefix: [u8; NONCE_PREFIX_LEN], seq: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0_u8; NONCE_LEN];
    nonce[..NONCE_PREFIX_LEN].copy_from_slice(&prefix);
    nonce[NONCE_PREFIX_LEN..].copy_from_slice(&seq.to_be_bytes());
    nonce
}

/// High-level bitcode + fragmentation + AEAD + replay + reassembly codec.
#[derive(Debug)]
pub struct UdpSessionCodec {
    crypto: UdpSessionCrypto,
    reassembler: FragmentReassembler,
    next_message_id: u64,
    message_id_exhausted: bool,
}

impl UdpSessionCodec {
    pub fn new(
        role: UdpSessionRole,
        session_id: UdpSessionId,
        master_key: [u8; KEY_LEN],
        client_nonce: [u8; 32],
        server_nonce: [u8; 32],
    ) -> UdpTransportResult<Self> {
        Self::with_reassembly_config(
            role,
            session_id,
            master_key,
            client_nonce,
            server_nonce,
            ReassemblyConfig::default(),
        )
    }

    pub fn with_reassembly_config(
        role: UdpSessionRole,
        session_id: UdpSessionId,
        master_key: [u8; KEY_LEN],
        client_nonce: [u8; 32],
        server_nonce: [u8; 32],
        reassembly_config: ReassemblyConfig,
    ) -> UdpTransportResult<Self> {
        Ok(Self {
            crypto: UdpSessionCrypto::new(
                role,
                session_id,
                master_key,
                client_nonce,
                server_nonce,
            )?,
            reassembler: FragmentReassembler::new(reassembly_config)?,
            next_message_id: 0,
            message_id_exhausted: false,
        })
    }

    pub fn session_id(&self) -> UdpSessionId {
        self.crypto.session_id()
    }

    pub fn encode_message(
        &mut self,
        message: &UdpSessionMessage,
    ) -> UdpTransportResult<Vec<Vec<u8>>> {
        if self.message_id_exhausted {
            return Err(UdpTransportError::MessageIdExhausted);
        }
        let plaintext = message.encode()?;
        let message_id = self.next_message_id;
        let datagrams = self.crypto.seal_message(message_id, &plaintext)?;
        if message_id == u64::MAX {
            self.message_id_exhausted = true;
        } else {
            self.next_message_id += 1;
        }
        Ok(datagrams)
    }

    pub fn decode_datagram(
        &mut self,
        datagram: &[u8],
    ) -> UdpTransportResult<Option<UdpSessionMessage>> {
        self.decode_datagram_at(datagram, Instant::now())
    }

    pub fn decode_datagram_at(
        &mut self,
        datagram: &[u8],
        now: Instant,
    ) -> UdpTransportResult<Option<UdpSessionMessage>> {
        let fragment = self.crypto.open_datagram(datagram)?;
        self.reassembler
            .push(fragment, now)?
            .map(|message| UdpSessionMessage::decode(&message))
            .transpose()
    }

    pub fn cleanup_expired(&mut self, now: Instant) -> usize {
        self.reassembler.cleanup_expired(now)
    }
}
