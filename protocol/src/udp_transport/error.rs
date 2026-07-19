use thiserror::Error;

pub type UdpTransportResult<T> = Result<T, UdpTransportError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum UdpTransportError {
    #[error("UDP datagram is too large: {0} bytes")]
    DatagramTooLarge(usize),

    #[error("UDP datagram is too short: {0} bytes")]
    DatagramTooShort(usize),

    #[error("invalid UDP transport magic")]
    InvalidMagic,

    #[error("unsupported UDP transport version: {0}")]
    UnsupportedVersion(u8),

    #[error("invalid UDP packet kind: {0}")]
    InvalidPacketKind(u8),

    #[error("unexpected UDP packet kind: expected {expected}, got {actual}")]
    UnexpectedPacketKind { expected: u8, actual: u8 },

    #[error("invalid UDP transport header: {0}")]
    InvalidHeader(&'static str),

    #[error("UDP message is too large: {0} bytes")]
    MessageTooLarge(usize),

    #[error("UDP message has too many fragments: {0}")]
    TooManyFragments(usize),

    #[error("UDP session does not match this codec")]
    WrongSession,

    #[error("UDP packet authentication failed")]
    AuthenticationFailed,

    #[error("UDP packet encryption failed")]
    EncryptionFailed,

    #[error("UDP packet was rejected by replay protection")]
    ReplayRejected,

    #[error("UDP send sequence is exhausted")]
    SequenceExhausted,

    #[error("UDP message id is exhausted")]
    MessageIdExhausted,

    #[error("UDP fragment conflicts with an existing fragment")]
    ConflictingFragment,

    #[error("UDP reassembly limit exceeded: {0}")]
    ReassemblyLimit(&'static str),

    #[error("UDP message serialization failed: {0}")]
    Serialization(String),

    #[error("UDP key derivation failed")]
    KeyDerivation,
}
