use super::message_type::MessageType;
use super::values::PROTOCOL_VERSION;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub version: u8,
    pub message_type: MessageType,
    pub payload: Vec<u8>,
}

impl Message {
    pub fn new(message_type: MessageType, payload: Vec<u8>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message_type,
            payload,
        }
    }
}
