/// Framed TCP/Yamux wire protocol version.
///
/// Version 2 deliberately has no version-1 fallback: version 1 transported a
/// client-selected symmetric key through a raw RSA private-key operation and
/// reused one bidirectional AEAD key with random nonces.
pub const PROTOCOL_VERSION: u8 = 2;
pub const MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024; // 4MB
pub const MAX_YAMUX_CONTROL_FRAME_SIZE: usize = 64 * 1024; // 64KB
