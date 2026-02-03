use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Invalid message format: {0}")]
    InvalidMessage(String),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Protocol version mismatch")]
    VersionMismatch,

    #[error("Message too large: {0} bytes")]
    MessageTooLarge(usize),
}
