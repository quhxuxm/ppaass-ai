#![deny(clippy::expect_used)]

pub mod codec;
pub mod compression;
pub mod crypto;
pub mod error;
pub mod message;
pub mod tcp_transport;
pub mod udp_transport;

pub use codec::{AgentCodec, CipherState, MessageCodec, ProxyCodec, ProxyDecoder, ProxyEncoder};
pub use compression::{CompressionMode, compress, decompress};
pub use crypto::RsaKeyPair;
pub use error::{ProtocolError, Result};
pub use message::{
    Address, AuthRequest, AuthResponse, ConnectRequest, ConnectResponse, DataPacket, Message,
    MessageType, ProxyRequest, ProxyResponse, TransportProtocol, UdpRelayPacket,
};
pub use tcp_transport::{
    AuthFailureCode, TcpDirectionalKeyMaterial, TcpFrameDirection, TcpSessionCipher,
    TcpSessionRole, TcpSessionSecret, decode_tcp_session_secret, encode_tcp_session_secret,
    tcp_auth_failure_signature_transcript, tcp_auth_request_transcript,
    tcp_auth_response_signature_transcript, tcp_auth_transcript_hash,
};
pub use udp_transport::{
    FragmentReassembler, ReassemblyConfig, ReplayWindow, UdpAuthInit, UdpAuthOk,
    UdpDirectionalKeyMaterial, UdpPacketHeader, UdpPacketKind, UdpSessionCodec, UdpSessionCrypto,
    UdpSessionMessage, UdpSessionRole, UdpSessionSecret, UdpTransportError, UdpTransportResult,
    udp_auth_ok_signature_transcript, udp_auth_proof_digest,
};
