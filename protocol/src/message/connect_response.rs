use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectResponse {
    pub request_id: String,
    pub success: bool,
    pub message: String,
}
