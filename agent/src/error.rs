use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum AgentError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Protocol error: {0}")]
    Protocol(#[from] protocol::ProtocolError),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Authentication error: {0}")]
    Authentication(String),

    #[error("Pool error: {0}")]
    Pool(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("SOCKS5 error: {0}")]
    Socks5(String),

    #[error("HTTP error: {0}")]
    Http(String),
}

pub type Result<T> = std::result::Result<T, AgentError>;
