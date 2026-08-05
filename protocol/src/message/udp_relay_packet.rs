use super::Address;
use crate::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpRelayPacket {
    pub flow_id: u64,
    pub address: Address,
    pub data: Vec<u8>,
}

#[derive(Serialize)]
struct UdpRelayPacketRef<'a> {
    flow_id: u64,
    address: &'a Address,
    data: &'a [u8],
}

impl UdpRelayPacket {
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(bitcode::serialize(self)?)
    }

    /// Encode without cloning the address or payload owned by the relay queue.
    pub fn encode_parts(flow_id: u64, address: &Address, data: &[u8]) -> Result<Vec<u8>> {
        Ok(bitcode::serialize(&UdpRelayPacketRef {
            flow_id,
            address,
            data,
        })?)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        Ok(bitcode::deserialize(data)?)
    }
}
