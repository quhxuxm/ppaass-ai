/// Framed TCP/Yamux wire protocol version.
///
/// Version 6 combines authentication and target intent into one client
/// request. The target intent is AEAD encrypted before it reaches the Proxy.
pub const PROTOCOL_VERSION: u8 = 6;
pub const MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024; // 4MB
pub const MAX_YAMUX_CONTROL_FRAME_SIZE: usize = 64 * 1024; // 64KB
