//! Version-7 TCP/Yamux handshake and record protection.
//!
//! The Agent signs its identity proof. The Proxy generates a per-session secret,
//! encrypts it to that user's RSA public key, and HKDF expands it into independent
//! keys and nonce prefixes for each wire direction.

mod auth;
mod crypto;

pub(crate) use auth::validate_tcp_auth_response_message;
pub use auth::{
    AuthFailureCode, TCP_AUTH_CONNECT_RESPONSE_OAEP_LABEL,
    TCP_AUTH_NONCE_LEN, TCP_HANDSHAKE_VERSION, TCP_MASTER_SECRET_LEN, TCP_MAX_AUTH_ERROR_LEN,
    TCP_MAX_RSA_FIELD_LEN, TCP_SERVER_NONCE_LEN, TCP_SESSION_ID_LEN,
    tcp_auth_connect_request_transcript,
    tcp_auth_connect_transcript_hash, tcp_auth_replay_key, tcp_auth_replay_user_key,
    validate_tcp_username,
};
pub use crypto::{TcpDirectionalKeyMaterial, TcpFrameDirection, TcpSessionCipher, TcpSessionRole};
