use super::{AuthConnectIntent, AuthConnectRequest, DataPacket};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProxyRequest {
    AuthConnect(AuthConnectRequest),
    AuthConnectIntent(AuthConnectIntent),
    Data(DataPacket),
}
