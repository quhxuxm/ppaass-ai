use super::{AuthRequest, ConnectRequest, DataPacket, SpeedTestRequest};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProxyRequest {
    Auth(AuthRequest),
    Connect(ConnectRequest),
    SpeedTest(SpeedTestRequest),
    Data(DataPacket),
}
