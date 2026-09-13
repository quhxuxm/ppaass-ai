use super::{AuthConnectResponse, ConnectResponse, DataPacket};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProxyResponse {
    AuthConnect(AuthConnectResponse),
    Connect(ConnectResponse),
    Data(DataPacket),
    Error { message: String },
}
