use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    AuthConnectRequest = 1,
    AuthConnectResponse = 2,
    AuthConnectIntent = 3,
    ConnectResponse = 4,
    Data = 5,
    Error = 6,
    SpeedTestRequest = 7,
}
