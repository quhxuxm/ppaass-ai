use protocol::crypto::{RsaKeyPair, encrypt_oaep_sha256_labelled};
use protocol::udp_transport::*;
use protocol::{Address, UdpRelayPacket};
use std::time::{Duration, Instant};

const SESSION_ID: UdpSessionId = [0x11; 16];
const MASTER_KEY: [u8; 32] = [0x22; 32];
const CLIENT_NONCE: [u8; 32] = [0x33; 32];
const SERVER_NONCE: [u8; 32] = [0x44; 32];

fn codecs() -> (UdpSessionCodec, UdpSessionCodec) {
    (
        UdpSessionCodec::new(
            UdpSessionRole::Agent,
            SESSION_ID,
            MASTER_KEY,
            CLIENT_NONCE,
            SERVER_NONCE,
        )
        .unwrap(),
        UdpSessionCodec::new(
            UdpSessionRole::Proxy,
            SESSION_ID,
            MASTER_KEY,
            CLIENT_NONCE,
            SERVER_NONCE,
        )
        .unwrap(),
    )
}

fn noisy_bytes(len: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_u32;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

fn fragment(
    message_id: u64,
    index: u16,
    count: u16,
    total_len: u32,
    payload: &[u8],
) -> DecryptedUdpFragment {
    DecryptedUdpFragment {
        header: UdpPacketHeader::new(
            UdpPacketKind::Encrypted,
            SESSION_ID,
            u64::from(index),
            message_id,
            index,
            count,
            total_len,
        ),
        payload: payload.to_vec(),
    }
}

mod auth;
mod crypto;
mod payload_limits;
mod reassembly;
mod replay;
mod serialization;
