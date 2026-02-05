use super::message_type::MessageType;
use super::values::PROTOCOL_VERSION;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub version: u8,
    pub message_type: MessageType,
    /// Compression mode flag: 0=None, 1=Zstd, 2=Lz4, 3=Gzip
    #[serde(default)]
    pub compression: u8,
    pub payload: Vec<u8>,
}

impl Message {
    pub fn new(message_type: MessageType, payload: Vec<u8>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message_type,
            compression: 0,
            payload,
        }
    }

    pub fn with_compression(message_type: MessageType, payload: Vec<u8>, compression: u8) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message_type,
            compression,
            payload,
        }
    }
}
