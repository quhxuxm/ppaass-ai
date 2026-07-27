#![deny(clippy::expect_used)]

pub mod codec;
pub mod compression;
pub mod crypto;
pub mod error;
pub mod message;
pub mod udp_transport;

pub use codec::{AgentCodec, CipherState, MessageCodec, ProxyCodec, ProxyDecoder, ProxyEncoder};
pub use compression::{CompressionMode, compress, decompress};
pub use crypto::{AesGcmCipher, CryptoManager, RsaKeyPair};
pub use error::{ProtocolError, Result};
pub use message::{
    Address, AuthRequest, AuthResponse, ConnectRequest, ConnectResponse, DataPacket, Message,
    MessageType, ProxyRequest, ProxyResponse, TransportProtocol, UdpRelayPacket,
};
pub use udp_transport::{
    FragmentReassembler, ReassemblyConfig, ReplayWindow, UdpAuthInit, UdpAuthOk,
    UdpDirectionalKeyMaterial, UdpPacketHeader, UdpPacketKind, UdpSessionCodec, UdpSessionCrypto,
    UdpSessionMessage, UdpSessionRole, UdpSessionSecret, UdpTransportError, UdpTransportResult,
    udp_auth_proof_digest,
};
