use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    AuthRequest = 1,
    AuthResponse = 2,
    ConnectRequest = 3,
    ConnectResponse = 4,
    Data = 5,
}
