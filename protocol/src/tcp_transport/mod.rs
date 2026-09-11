//! Version-6 TCP/Yamux handshake and record protection.
//!
//! The Agent signs an RSA-OAEP protected per-request secret and an AEAD
//! encrypted target intent. HKDF expands that secret into independent keys and
//! nonce prefixes for each wire direction after the Proxy accepts the request.

mod auth;
mod crypto;

pub(crate) use auth::validate_tcp_auth_response_message;
pub use auth::{
    AuthFailureCode, TCP_AUTH_CONNECT_INTENT_NONCE_LEN, TCP_AUTH_CONNECT_OAEP_LABEL,
    TCP_AUTH_NONCE_LEN, TCP_HANDSHAKE_VERSION, TCP_MASTER_SECRET_LEN, TCP_MAX_AUTH_ERROR_LEN,
    TCP_MAX_RSA_FIELD_LEN, TCP_SERVER_NONCE_LEN, TCP_SESSION_ID_LEN, open_auth_connect_intent,
    seal_auth_connect_intent, tcp_auth_connect_intent_aad, tcp_auth_connect_request_transcript,
    tcp_auth_connect_transcript_hash, tcp_auth_replay_key, tcp_auth_replay_user_key,
    validate_tcp_username,
};
pub use crypto::{TcpDirectionalKeyMaterial, TcpFrameDirection, TcpSessionCipher, TcpSessionRole};
