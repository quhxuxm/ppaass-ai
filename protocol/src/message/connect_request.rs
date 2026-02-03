use super::address::Address;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectRequest {
    pub request_id: String,
    pub address: Address,
}
