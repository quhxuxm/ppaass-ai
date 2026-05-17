use serde::{Deserialize, Serialize};

/// agent 与 proxy 之间传输数据的数据包
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPacket {
    pub stream_id: String,
    pub data: Vec<u8>,
    pub is_end: bool,
}
