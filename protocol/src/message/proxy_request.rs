use super::{AuthRequest, ConnectRequest, DataPacket};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProxyRequest {
    Auth(AuthRequest),
    Connect(ConnectRequest),
    Data(DataPacket),
}
