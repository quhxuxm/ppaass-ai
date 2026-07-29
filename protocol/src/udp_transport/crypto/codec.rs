use std::time::Instant;

use super::{KEY_LEN, UdpSessionCrypto, UdpSessionRole};
use crate::udp_transport::{
    FragmentReassembler, ReassemblyConfig, UdpSessionId, UdpSessionMessage, UdpTransportError,
    UdpTransportResult,
};

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
