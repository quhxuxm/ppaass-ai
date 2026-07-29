/// Framed TCP/Yamux wire protocol version.
///
/// Version 3 adds Proxy-signed structured authentication failure codes and
/// deliberately has no version-2 fallback because `AuthResponse` has a new
/// bitcode wire shape. Version 2 had already retired the unsafe version-1 RSA
/// handshake and bidirectional record key.
pub const PROTOCOL_VERSION: u8 = 3;
pub const MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024; // 4MB
pub const MAX_YAMUX_CONTROL_FRAME_SIZE: usize = 64 * 1024; // 64KB
