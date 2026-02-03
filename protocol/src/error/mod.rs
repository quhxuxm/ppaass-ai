mod protocol_error;

pub use protocol_error::ProtocolError;
pub type Result<T> = std::result::Result<T, ProtocolError>;
