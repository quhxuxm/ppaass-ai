//! Version-4 TCP/Yamux handshake and record protection.
//!
//! The handshake authenticates the agent with RSA-PSS-SHA256. The proxy then
//! creates the session secret and returns it only inside an RSA-OAEP-SHA256
//! ciphertext. HKDF expands that secret into independent keys and nonce
//! prefixes for each wire direction. TCP ordering lets the record layer reject
//! every duplicate, skipped, or reordered sequence number.

mod auth;
mod crypto;

pub(crate) use auth::validate_tcp_auth_response_message;
pub use auth::{
    AuthFailureCode, TCP_AUTH_NONCE_LEN, TCP_HANDSHAKE_VERSION, TCP_MASTER_SECRET_LEN,
    TCP_MAX_AUTH_ERROR_LEN, TCP_MAX_RSA_FIELD_LEN, TCP_OAEP_LABEL, TCP_SERVER_NONCE_LEN,
    TCP_SESSION_ID_LEN, TCP_SESSION_SECRET_MAX_SIZE, TcpSessionSecret, decode_tcp_session_secret,
    encode_tcp_session_secret, tcp_auth_replay_key, tcp_auth_replay_user_key,
    tcp_auth_request_transcript, tcp_auth_transcript_hash, validate_tcp_username,
};
pub use crypto::{TcpDirectionalKeyMaterial, TcpFrameDirection, TcpSessionCipher, TcpSessionRole};
