use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("Authentication error: {0}")]
    Authentication(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Bandwidth limit exceeded")]
    BandwidthLimitExceeded,

    #[error("User not found: {0}")]
    UserNotFound(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    #[error("RSA error: {0}")]
    Rsa(String),

    #[error("AES error: {0}")]
    Aes(String),
}

pub type Result<T> = std::result::Result<T, Error>;
