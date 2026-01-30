use thiserror::Error;

#[derive(Error, Debug)]
pub enum AgentError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Protocol error: {0}")]
    Protocol(#[from] protocol::ProtocolError),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Authentication error: {0}")]
    Authentication(String),

    #[error("SOCKS5 error: {0}")]
    Socks5(String),
}

pub type Result<T> = std::result::Result<T, AgentError>;
