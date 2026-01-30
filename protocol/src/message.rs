use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; // 64MB

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    AuthRequest = 1,
    AuthResponse = 2,
    ConnectRequest = 3,
    ConnectResponse = 4,
    Data = 5,
    Heartbeat = 6,
    Disconnect = 7,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub version: u8,
    pub message_type: MessageType,
    pub payload: Vec<u8>,
}

impl Message {
    pub fn new(message_type: MessageType, payload: Vec<u8>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message_type,
            payload,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub timestamp: i64,
    pub encrypted_aes_key: Vec<u8>, // AES key encrypted with RSA public key
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub success: bool,
    pub message: String,
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Address {
    Domain { host: String, port: u16 },
    Ipv4 { addr: [u8; 4], port: u16 },
    Ipv6 { addr: [u8; 16], port: u16 },
}

impl Address {
    pub fn port(&self) -> u16 {
        match self {
            Address::Domain { port, .. } => *port,
            Address::Ipv4 { port, .. } => *port,
            Address::Ipv6 { port, .. } => *port,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectRequest {
    pub request_id: String,
    pub address: Address,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectResponse {
    pub request_id: String,
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPacket {
    pub stream_id: String,
    pub data: Vec<u8>,
    pub is_end: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProxyRequest {
    Auth(AuthRequest),
    Connect(ConnectRequest),
    Data(DataPacket),
    Heartbeat,
    Disconnect(String), // stream_id
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProxyResponse {
    Auth(AuthResponse),
    Connect(ConnectResponse),
    Data(DataPacket),
    Heartbeat,
    Error { message: String },
}
