use super::Address;
use crate::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpRelayPacket {
    pub flow_id: u64,
    pub address: Address,
    pub data: Vec<u8>,
}

impl UdpRelayPacket {
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(bitcode::serialize(self)?)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        Ok(bitcode::deserialize(data)?)
    }
}
