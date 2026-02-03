use super::{AuthResponse, ConnectResponse, DataPacket};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProxyResponse {
    Auth(AuthResponse),
    Connect(ConnectResponse),
    Data(DataPacket),
    Error { message: String },
}
