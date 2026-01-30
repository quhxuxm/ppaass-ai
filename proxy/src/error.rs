use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum ProxyError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Protocol error: {0}")]
    Protocol(#[from] protocol::ProtocolError),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Authentication error: {0}")]
    Authentication(String),

    #[error("User not found: {0}")]
    UserNotFound(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Bandwidth limit exceeded")]
    BandwidthLimitExceeded,

    #[error("Connection limit exceeded")]
    ConnectionLimitExceeded,
}

pub type Result<T> = std::result::Result<T, ProxyError>;
