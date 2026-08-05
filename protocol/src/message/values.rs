/// Framed TCP/Yamux wire protocol version.
///
/// Version 4 removes the Proxy transport-identity signature from
/// `AuthResponse`. It deliberately has no version-3 fallback because the
/// bitcode wire shape changed. Agent authentication still uses RSA-PSS and the
/// session secret remains encrypted to the authenticated user's public key.
pub const PROTOCOL_VERSION: u8 = 4;
pub const MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024; // 4MB
pub const MAX_YAMUX_CONTROL_FRAME_SIZE: usize = 64 * 1024; // 64KB
