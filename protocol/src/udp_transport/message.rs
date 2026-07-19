use crate::Address;
use serde::{Deserialize, Serialize};

use super::{UdpTransportError, UdpTransportResult};

/// Messages multiplexed inside an authenticated native UDP session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UdpSessionMessage {
    /// Opens a logical UDP flow and carries its first datagram atomically.
    OpenData {
        flow_id: u64,
        address: Address,
        data: Vec<u8>,
    },
    ConnectResponse {
        flow_id: u64,
        success: bool,
        error: Option<String>,
    },
    Data {
        flow_id: u64,
        data: Vec<u8>,
    },
    Close {
        flow_id: u64,
        reason: Option<String>,
    },
    Ping {
        token: u64,
    },
    Pong {
        token: u64,
    },
}

impl UdpSessionMessage {
    pub fn encode(&self) -> UdpTransportResult<Vec<u8>> {
        bitcode::serialize(self)
            .map_err(|error| UdpTransportError::Serialization(error.to_string()))
    }

    pub fn decode(bytes: &[u8]) -> UdpTransportResult<Self> {
        bitcode::deserialize(bytes)
            .map_err(|error| UdpTransportError::Serialization(error.to_string()))
    }
}
