use thiserror::Error;

pub type Result<T> = std::result::Result<T, AndroidAgentError>;

#[derive(Debug, Error)]
pub enum AndroidAgentError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("connection error: {0}")]
    Connection(String),

    #[error("unsupported platform: {0}")]
    UnsupportedPlatform(String),
}
