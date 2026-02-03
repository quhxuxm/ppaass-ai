use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPacket {
    pub stream_id: String,
    pub data: Vec<u8>,
    pub is_end: bool,
}
