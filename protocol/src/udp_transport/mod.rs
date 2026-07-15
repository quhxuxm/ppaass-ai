//! Native encrypted UDP transport primitives.
//!
//! This module deliberately contains no socket I/O. Callers own authentication,
//! RSA-OAEP encryption of [`UdpSessionSecret`], and UDP socket lifecycle; this layer
//! owns packet framing, directional AEAD, replay protection, and reassembly.

mod auth;
mod crypto;
mod error;
mod header;
mod message;
mod reassembly;
mod replay;

#[cfg(test)]
mod tests;

pub use auth::{
    UdpAuthInit, UdpAuthOk, UdpSessionSecret, decode_auth_init, decode_auth_ok,
    decode_session_secret, encode_auth_init, encode_auth_ok, encode_session_secret,
    udp_auth_proof_digest,
};
pub use crypto::{
    DecryptedUdpFragment, UdpDirectionalKeyMaterial, UdpSessionCodec, UdpSessionCrypto,
    UdpSessionRole,
};
pub use error::{UdpTransportError, UdpTransportResult};
pub use header::{UdpPacketHeader, UdpPacketKind};
pub use message::UdpSessionMessage;
pub use reassembly::{FragmentReassembler, ReassemblyConfig};
pub use replay::ReplayWindow;

/// Four-byte discriminator at the start of every encrypted UDP datagram.
pub const UDP_TRANSPORT_MAGIC: [u8; 4] = *b"PUDP";
/// Wire format version for the native UDP transport.
pub const UDP_TRANSPORT_VERSION: u8 = 1;
/// Maximum complete UDP datagram size, including header and authentication tag.
///
/// 1350 bytes stays below the common 1500-byte path MTU even with IPv6/UDP
/// headers, while allowing a normal 1200-byte QUIC Initial carried by the UDP
/// relay envelope to remain a single independently authenticated datagram.
pub const UDP_MAX_DATAGRAM_SIZE: usize = 1_350;
/// Fixed encoded header length.
pub const UDP_TRANSPORT_HEADER_LEN: usize = 46;
/// AES-GCM authentication tag length.
pub const UDP_AEAD_TAG_LEN: usize = 16;
/// Maximum plaintext carried by one encrypted fragment.
pub const UDP_MAX_FRAGMENT_PLAINTEXT: usize =
    UDP_MAX_DATAGRAM_SIZE - UDP_TRANSPORT_HEADER_LEN - UDP_AEAD_TAG_LEN;
/// Maximum reassembled bitcode message size.
pub const UDP_MAX_MESSAGE_SIZE: usize = 70 * 1024;
/// Maximum fragments in one message.
pub const UDP_MAX_FRAGMENTS: usize = 64;
/// Number of sequence numbers remembered by replay protection.
pub const UDP_REPLAY_WINDOW_SIZE: usize = 4096;

const _: () = assert!(UDP_MAX_MESSAGE_SIZE <= UDP_MAX_FRAGMENTS * UDP_MAX_FRAGMENT_PLAINTEXT);

pub type UdpSessionId = [u8; 16];
